#!/usr/bin/env python3
"""Change GUI_PORT transactionally; recreate dashboard ONLY, never its worker."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import sys
import tempfile
import time
import uuid

try:
    from .doctor import ComposeProject, Redactor, dashboard_address, http_probe, run_command
except ImportError:
    from doctor import ComposeProject, Redactor, dashboard_address, http_probe, run_command


def valid_port(value):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError('Dashboard port must be an integer in 1024..65535')
    if isinstance(value, str) and (not value.isascii() or not value.isdecimal()):
        raise ValueError('Dashboard port must be an integer in 1024..65535')
    port = int(value)
    if not 1024 <= port <= 65535:
        raise ValueError('Dashboard port must be in 1024..65535')
    return port


def probe_port(host, port):
    """Never reuse a busy listener, and never silently replace GUI_BIND."""
    family = socket.AF_INET6 if ipaddress.ip_address(host).version == 6 else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        listener.bind((host, port))
        listener.listen(1)


def sync_directory(path):
    if os.name == 'posix':
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def atomic_write(path, content, *, metadata=None):
    descriptor, temporary = tempfile.mkstemp(prefix='.dashboard-port-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            os.chmod(temporary, stat.S_IMODE(metadata.st_mode) if metadata else 0o600)
            if metadata and os.name == 'posix':
                os.chown(temporary, metadata.st_uid, metadata.st_gid)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        temporary = None
        sync_directory(path.parent)
    finally:
        if temporary is not None:
            os.unlink(temporary)


@contextmanager
def update_lock(project_dir):
    """Persistent inode + OS advisory lock: lock deletion cannot admit a rival."""
    path = Path(project_dir) / '.dashboard-port.lock'
    if path.is_symlink():
        raise ValueError('Port-update lock must not be a symlink')
    flags = os.O_CREAT | os.O_RDWR | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError('Port-update lock must be a regular file')
        if os.name == 'posix':
            import fcntl
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                raise RuntimeError('Another dashboard port update is in progress') from exc
        else:
            import msvcrt
            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b'0')
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise RuntimeError('Another dashboard port update is in progress') from exc
        yield
    finally:
        os.close(descriptor)


def update_env(original, port):
    text = original.decode('utf-8')
    # Preserve unrelated variables/comments/newlines; avoid duplicate GUI_PORT
    # definitions, including shell-compatible "export GUI_PORT=..." forms.
    newline = '\r\n' if '\r\n' in text else '\n'
    lines, found = [], False
    for line in text.splitlines(keepends=True):
        if re.match(r'^\s*(?:export\s+)?GUI_PORT\s*=', line):
            if not found:
                lines.append(f'GUI_PORT={port}' + newline)
                found = True
        else:
            lines.append(line)
    if not found:
        if lines and not lines[-1].endswith(('\n', '\r')):
            lines.append(newline)
        lines.append(f'GUI_PORT={port}' + newline)
    return ''.join(lines).encode('utf-8')


def wait_live(url, *, probe=http_probe, timeout=15):
    deadline = time.monotonic() + timeout
    while True:
        try:
            result = probe(url + '/livez', timeout=2)
            if result.get('http') == 200 and result.get('body', {}).get('alive') is True:
                return
        except (OSError, ValueError):
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError('Dashboard /livez did not become healthy')
        time.sleep(.25)


def change_port(port, *, project_dir=None, compose_files=None, env_file=None,
                runner=run_command, probe=probe_port, live_check=wait_live, out=None):
    out = out or sys.stdout
    port = valid_port(port)
    project = ComposeProject(project_dir or Path(__file__).resolve().parents[1],
                             compose_files=compose_files, env_file=env_file, runner=runner)
    target = project.env_file
    if not target.parent.is_dir() or not target.resolve().is_relative_to(project.root):
        raise ValueError('Env file must stay inside the project directory')
    for file in project.files:
        if not file.resolve().is_relative_to(project.root):
            raise ValueError('Compose files must stay inside the project directory')
    # A shell GUI_PORT would override the .env edit. Use the helper's .env while
    # preserving every other process variable, especially GUI_BIND and identity.
    child_env = dict(os.environ)
    child_env.pop('GUI_PORT', None)
    redactor = Redactor()
    for name in ('admin_password', 'secret_key', 'service_token'):
        redactor.add_file(project.root / 'secrets' / name)
    redactor.learn_env_file(target)

    with update_lock(project.root):
        existed = target.exists()
        metadata = target.stat() if existed else None
        if existed and (target.is_symlink() or not target.is_file()):
            raise ValueError('Env file must be a regular non-symlink file')
        original = target.read_bytes() if existed else b''
        try:
            config = project.config(env=child_env)
        except RuntimeError as exc:
            raise RuntimeError(redactor(exc)) from exc
        redactor.learn(config)
        host, old, old_url = dashboard_address(config)
        if old == port:
            print(f'DASHBOARD_PORT: unchanged={port}; bind={host}; no files/services changed', file=out)
            return {'changed': False, 'port': port, 'bind': host}
        # This happens before backup/edit/recreate. Occupied port changes nothing.
        probe(host, port)
        directory = project.root / '.dashboard-port-backups'
        if directory.is_symlink():
            raise ValueError('Backup directory must not be a symlink')
        directory.mkdir(mode=0o700, exist_ok=True)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
        backup = directory / stamp
        backup.mkdir(mode=0o700)
        atomic_write(backup / 'env.before', original)
        for index, file in enumerate(project.files):
            atomic_write(backup / f'compose-{index}.before', file.read_bytes())
        atomic_write(backup / 'manifest.json', json.dumps({'env_file': str(target), 'env_existed': existed,
                     'compose_files': [str(file) for file in project.files], 'old_port': old,
                     'new_port': port, 'bind': host}, indent=2).encode('utf-8'))

        recreate_started = False
        try:
            updated = update_env(original, port)
            atomic_write(target, updated, metadata=metadata)
            resolved = project.config(env=child_env)
            actual_host, actual_port, url = dashboard_address(resolved)
            if actual_port != port or actual_host != host:
                raise RuntimeError('Compose override prevents GUI_PORT update or changes GUI_BIND')
            recreate_started = True
            result = project.command('up', '-d', '--no-deps', '--force-recreate', '--no-build',
                                     '--pull', 'never', 'dashboard', timeout=120, env=child_env)
            if result['exit'] != 0 or result.get('timeout'):
                raise RuntimeError('Dashboard recreate failed: ' + redactor(result['output']))
            live_check(url)
        except Exception as exc:
            if existed:
                atomic_write(target, original, metadata=metadata)
            else:
                target.unlink()
                sync_directory(target.parent)
            rollback = 'env restored; old dashboard was not recreated'
            if recreate_started:
                result = project.command('up', '-d', '--no-deps', '--force-recreate', '--no-build',
                                         '--pull', 'never', 'dashboard', timeout=120, env=child_env)
                if result['exit'] == 0 and not result.get('timeout'):
                    try:
                        live_check(old_url)
                        rollback = 'env restored; previous dashboard port verified live'
                    except Exception:
                        rollback = 'env restored; previous dashboard liveness not confirmed'
                else:
                    rollback = 'env restored; dashboard rollback recreate failed: ' + redactor(result['output'])
            raise RuntimeError(redactor(str(exc)) + '; ROLLBACK: ' + rollback + '; backup=' + str(backup)) from exc
        print(f'DASHBOARD_PORT: {old} -> {port}; bind={host}; backup={backup}; /livez=200', file=out)
        print('Worker was not started/restarted; proxy pool and credentials were not modified.', file=out)
        return {'changed': True, 'port': port, 'old_port': old, 'bind': host, 'backup': str(backup)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('port')
    parser.add_argument('--project-dir', default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument('--compose-file', action='append', dest='compose_files')
    parser.add_argument('--env-file')
    args = parser.parse_args(argv)
    try:
        change_port(**vars(args))
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        print('DASHBOARD_PORT ERROR: ' + Redactor()(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
