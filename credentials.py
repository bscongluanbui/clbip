"""Dashboard credential persistence; only the privileged worker writes secrets."""
from contextlib import contextmanager
import os
from pathlib import Path
import secrets
import stat
import tempfile
import threading


PASSWORD_FIELDS = {'current_password', 'new_password', 'confirm_password'}
MAX_PASSWORD_BYTES = 65536
_locks, _locks_guard = {}, threading.Lock()


class CredentialError(RuntimeError):
    def __init__(self, message, status=503):
        super().__init__(message)
        self.status = status


def validate_password_change(value):
    """Validate exact values without trimming, normalizing or exposing them."""
    if not isinstance(value, dict) or set(value) != PASSWORD_FIELDS:
        raise CredentialError('Cần mật khẩu hiện tại, mật khẩu mới và xác nhận mật khẩu.', 400)
    for field in PASSWORD_FIELDS:
        password = value[field]
        if not isinstance(password, str):
            raise CredentialError('Các trường mật khẩu phải là chuỗi.', 400)
        try:
            encoded = password.encode('utf-8')
        except UnicodeError:
            raise CredentialError('Mật khẩu phải là chuỗi UTF-8 hợp lệ.', 400) from None
        if len(encoded) > MAX_PASSWORD_BYTES:
            raise CredentialError('Dữ liệu mật khẩu vượt giới hạn request 64 KiB.', 413)
    if not secrets.compare_digest(value['new_password'].encode('utf-8'), value['confirm_password'].encode('utf-8')):
        raise CredentialError('Xác nhận mật khẩu mới chưa khớp.', 400)
    return dict(value)


class DashboardCredentialStore:
    """An installed, fixed credential path, never a client-selected RPC path."""
    def __init__(self, path, *, require_root=False):
        self.path = Path(path)
        if not self.path.is_absolute():
            raise CredentialError('Đường dẫn mật khẩu dashboard chưa được cấu hình.')
        self.require_root = require_root
        key = os.path.normcase(os.path.abspath(self.path))
        with _locks_guard:
            self._thread_lock = _locks.setdefault(key, threading.Lock())

    def initialize(self, password, *, group_id=10001):
        """Bootstrap a mutable volume once; never replace an existing credential.

        Docker secrets are read-only mountpoints. Only this separate directory
        receives atomic replacements; the dashboard mounts the directory RO.
        """
        if not isinstance(password, str) or len(password.encode('utf-8')) > MAX_PASSWORD_BYTES:
            raise CredentialError('Mật khẩu khởi tạo dashboard chưa được cấu hình.')
        temporary = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
            parent = self.path.parent.lstat()
            if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
                raise OSError('credential directory type')
            if self.require_root and os.name != 'nt':
                if parent.st_uid != 0 or stat.S_IMODE(parent.st_mode) & 0o022:
                    raise OSError('credential directory ownership')
                os.chown(self.path.parent, 0, group_id)
                self.path.parent.chmod(0o750)
            with self._thread_lock, self._file_lock():
                if self.path.exists() or self.path.is_symlink():
                    self._read()
                    return False
                fd, temporary = tempfile.mkstemp(prefix='.admin-password-', dir=self.path.parent)
                with os.fdopen(fd, 'wb') as stream:
                    if os.name != 'nt':
                        os.fchown(stream.fileno(), 0 if self.require_root else os.getuid(), group_id)
                        os.fchmod(stream.fileno(), 0o640)
                    stream.write(password.encode('utf-8'))
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, self.path)
                temporary = None
                if os.name != 'nt':
                    directory = os.open(self.path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
                return True
        except (OSError, ValueError, UnicodeError):
            raise CredentialError('Chưa khởi tạo được mật khẩu dashboard trên volume lưu trữ.') from None
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass

    def _open_regular(self, path, flags, mode=0o600):
        # The installed secrets directory is root-owned and not group-writable.
        # O_NOFOLLOW plus inode comparison also protects portable platforms.
        try:
            named = path.lstat()
        except FileNotFoundError:
            named = None
        if named is not None and (not stat.S_ISREG(named.st_mode) or stat.S_ISLNK(named.st_mode)
                or getattr(named, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0)):
            raise OSError('credential type')
        # Opening a FIFO before inspecting it would block indefinitely. The
        # no-block flag also closes the race where a regular path is exchanged.
        fd = os.open(path, flags | getattr(os, 'O_NOFOLLOW', 0)
                     | getattr(os, 'O_NONBLOCK', 0), mode)
        try:
            metadata, named = os.fstat(fd), path.lstat()
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)
                    or stat.S_ISLNK(named.st_mode)
                    or (self.require_root and os.name != 'nt' and
                        (metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o137))):
                raise OSError('credential metadata')
            return fd, metadata
        except BaseException:
            os.close(fd)
            raise

    def _read(self):
        fd, metadata = self._open_regular(self.path, os.O_RDONLY)
        with os.fdopen(fd, 'rb') as stream:
            raw = stream.read(MAX_PASSWORD_BYTES + 1)
        if len(raw) > MAX_PASSWORD_BYTES:
            raise ValueError('credential size')
        value = raw.decode('utf-8')
        return value, metadata

    def read(self):
        return self.read_snapshot()[0]

    def read_snapshot(self):
        """Read password and revision from one open inode for session revocation."""
        try:
            value, metadata = self._read()
            revision = ':'.join(str(getattr(metadata, field)) for field in
                ('st_dev', 'st_ino', 'st_mtime_ns', 'st_ctime_ns', 'st_size'))
            return value, revision
        except (OSError, ValueError, UnicodeError):
            raise CredentialError('Mật khẩu dashboard chưa sẵn sàng.') from None

    @contextmanager
    def _file_lock(self):
        path = self.path.with_name('.' + self.path.name + '.lock')
        fd, unused = self._open_regular(path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            if os.name == 'nt':
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b'\0')
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                try:
                    yield
                finally:
                    os.lseek(fd, 0, os.SEEK_SET)
                    msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                os.fchmod(fd, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
                try:
                    yield
                finally:
                    fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def change(self, current, new, confirm):
        values = validate_password_change({'current_password': current,
            'new_password': new, 'confirm_password': confirm})
        temporary, committed = None, False
        try:
            with self._thread_lock, self._file_lock():
                stored, metadata = self._read()
                if not secrets.compare_digest(values['current_password'].encode('utf-8'), stored.encode('utf-8')):
                    raise CredentialError('Mật khẩu hiện tại chưa chính xác.', 403)
                if secrets.compare_digest(values['new_password'].encode('utf-8'), stored.encode('utf-8')):
                    return {'changed': False, 'requires_login': False, 'unchanged': True}
                fd, temporary = tempfile.mkstemp(prefix='.admin-password-', dir=self.path.parent)
                try:
                    if os.name != 'nt':
                        os.fchown(fd, metadata.st_uid, metadata.st_gid)
                        os.fchmod(fd, stat.S_IMODE(metadata.st_mode))
                    with os.fdopen(fd, 'wb') as stream:
                        fd = None
                        stream.write(values['new_password'].encode('utf-8'))
                        stream.flush()
                        os.fsync(stream.fileno())
                    # Detect unexpected replacement between verification and commit.
                    named = self.path.lstat()
                    if (named.st_dev, named.st_ino) != (metadata.st_dev, metadata.st_ino):
                        raise OSError('credential changed')
                    os.replace(temporary, self.path)
                    temporary = None
                    committed = True
                    if os.name != 'nt':
                        directory = os.open(self.path.parent, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
                        try:
                            os.fsync(directory)
                        finally:
                            os.close(directory)
                finally:
                    if fd is not None:
                        os.close(fd)
            return {'changed': True, 'requires_login': True}
        except CredentialError:
            raise
        except (OSError, ValueError, UnicodeError):
            if committed:
                raise CredentialError('Mật khẩu dashboard đã đổi; đăng nhập lại bằng mật khẩu mới. '
                    'Chưa xác nhận đồng bộ lưu trữ.') from None
            raise CredentialError('Chưa cập nhật được mật khẩu dashboard. Thử lại sau.') from None
        finally:
            if temporary is not None:
                try:
                    os.unlink(temporary)
                except OSError:
                    pass
