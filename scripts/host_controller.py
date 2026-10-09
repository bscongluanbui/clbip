#!/usr/bin/env python3
"""Host-only PID helper. Its fixed worker target and API never execute client commands."""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import stat
import struct
import subprocess
import threading

MIN_LIMIT, MAX_LIMIT, HEADROOM, MAX_MESSAGE = 256, 16384, 64, 8192


class ControllerError(RuntimeError):
    pass


class PidController:
    def __init__(self, *, container='ipv6-proxy-manager-worker-1', project='ipv6-proxy-manager',
                 compose='/home/ubuntu/ipv6/docker-compose.yml', env_file=None, runner=None, fs_root='/'):
        self.container, self.project = container, project
        self.compose = Path(compose).resolve()
        self.env_file = Path(env_file).resolve() if env_file else self.compose.parent / '.env'
        self.runner = runner or self._run
        self.fs_root = Path(fs_root)
        self.lock = threading.Lock()
        self.rollback_ticket = None

    @staticmethod
    def _run(command):
        done = subprocess.run(command, capture_output=True, text=True, timeout=15)
        if done.returncode:
            raise ControllerError('Docker PID operation failed: ' + done.stderr.strip()[:240])
        return done.stdout

    def identity(self):
        objects = json.loads(self.runner(['docker', 'inspect', self.container]))
        if len(objects) != 1:
            raise ControllerError('Worker identity chưa xác nhận')
        obj = objects[0]
        labels = obj['Config'].get('Labels', {})
        if labels.get('com.docker.compose.project') != self.project or labels.get('com.docker.compose.service') != 'worker':
            raise ControllerError('Container không khớp worker cố định')
        if not obj['State'].get('Running') or type(obj['State'].get('Pid')) is not int or obj['State']['Pid'] <= 0:
            raise ControllerError('Worker chưa chạy')
        source = next((m['Source'] for m in obj.get('Mounts', []) if m.get('Destination') == '/run/ipv6-manager'), None)
        if not source:
            raise ControllerError('Worker runtime mount chưa xác nhận')
        return obj, Path(source)

    def _cgroup(self, obj):
        proc = self.fs_root / ('proc/' + str(obj['State']['Pid']) + '/cgroup')
        rel = next((line.split(':', 2)[2] for line in proc.read_text().splitlines() if line.startswith('0::')), None)
        if rel is None:
            raise ControllerError('Live PID setting hiện cần cgroup v2')
        root = (self.fs_root / 'sys/fs/cgroup').resolve()
        path = (root / rel.lstrip('/')).resolve()
        if not path.is_relative_to(root) or path == root:
            raise ControllerError('Worker cgroup path không hợp lệ')
        return path

    def status(self):
        obj, _ = self.identity(); cg = self._cgroup(obj)
        root = (self.fs_root / 'sys/fs/cgroup').resolve()
        limits, local, parent = [], None, []
        node = cg
        while True:
            try:
                raw = (node / 'pids.max').read_text().strip()
            except FileNotFoundError:
                if node == cg:
                    raise ControllerError('Worker PID limit chưa quan sát được')
            else:
                if raw != 'max' and not re.fullmatch(r'[0-9]+', raw):
                    raise ControllerError('PID limit counter không hợp lệ')
                value = 'max' if raw == 'max' else int(raw)
                if node == cg:
                    local = value
                if value != 'max':
                    limits.append(value)
                    if node != cg:
                        parent.append(value)
            if node == root:
                break
            node = node.parent
        return {'effective_limit': min(limits) if limits else 'max',
                'local_limit': local, 'parent_limit': min(parent) if parent else None,
                'current': int((cg / 'pids.current').read_text()),
                'minimum_headroom': HEADROOM, 'min_limit': MIN_LIMIT, 'max_limit': MAX_LIMIT,
                'container_id': obj['Id']}

    def _require_compose_variable(self):
        """Require the worker's actual YAML field, not an unrelated env key."""
        services_indent = worker_indent = None
        for line in self.compose.read_text(encoding='utf-8').splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            indent = len(line) - len(line.lstrip(' '))
            if services_indent is None:
                if stripped == 'services:':
                    services_indent = indent
                continue
            if indent <= services_indent:
                break
            if worker_indent is None:
                if stripped == 'worker:':
                    worker_indent = indent
                continue
            if indent <= worker_indent:
                break
            if re.fullmatch(r'''pids_limit:\s*["']?\$\{WORKER_THREAD_LIMIT(?::-(?:[0-9]+|-1))?\}["']?\s*(?:#.*)?''', stripped):
                return
        raise ControllerError('Compose worker cần pids_limit: ${WORKER_THREAD_LIMIT:-4096} trước khi chỉnh live')

    def _env_snapshot(self):
        if not self.env_file.exists():
            return {'data': None, 'mode': None, 'uid': None, 'gid': None}
        metadata = self.env_file.stat()
        return {'data': self.env_file.read_bytes(), 'mode': stat.S_IMODE(metadata.st_mode),
                'uid': metadata.st_uid, 'gid': metadata.st_gid}

    @staticmethod
    def _set_metadata(path, mode, uid, gid):
        # Root-written replacements must remain readable by the Compose owner.
        # chmod follows chown because chown can clear file mode bits on Linux.
        if hasattr(os, 'chown'):
            os.chown(path, uid, gid)
        path.chmod(mode)

    def _sync_env_directory(self):
        if hasattr(os, 'O_DIRECTORY'):
            descriptor = os.open(self.env_file.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def _restore_env(self, snapshot):
        data = snapshot['data']
        if data is None:
            self.env_file.unlink(missing_ok=True)
            self._sync_env_directory()
            if self.env_file.exists():
                raise ControllerError('PID env rollback chưa xác nhận')
            return
        if self.env_file.exists():
            metadata = self.env_file.stat()
            if (self.env_file.read_bytes() == data and stat.S_IMODE(metadata.st_mode) == snapshot['mode'] and
                    (metadata.st_uid, metadata.st_gid) == (snapshot['uid'], snapshot['gid'])):
                return
        temporary = self.env_file.with_name(self.env_file.name + '.pid-limit-restore-tmp')
        with open(temporary, 'wb') as out:
            out.write(data); out.flush(); os.fsync(out.fileno())
        self._set_metadata(temporary, snapshot['mode'], snapshot['uid'], snapshot['gid'])
        os.replace(temporary, self.env_file); self._sync_env_directory()
        metadata = self.env_file.stat()
        if (self.env_file.read_bytes() != data or stat.S_IMODE(metadata.st_mode) != snapshot['mode'] or
                (metadata.st_uid, metadata.st_gid) != (snapshot['uid'], snapshot['gid'])):
            raise ControllerError('PID env rollback chưa xác nhận')

    def _restore_transaction(self, container_id, local_limit, env_snapshot):
        self.runner(['docker', 'update', '--pids-limit', '-1' if local_limit == 'max' else str(local_limit), container_id])
        restored = self.status()
        if restored['container_id'] != container_id or restored['local_limit'] != local_limit:
            raise ControllerError('PID live rollback chưa xác nhận')
        self._restore_env(env_snapshot)
        return restored

    def _persist(self, value):
        # A single managed variable; preserve every existing env line and permission.
        data = self.env_file.read_text(encoding='utf-8') if self.env_file.exists() else ''
        lines = data.splitlines(keepends=True)
        lines = [line for line in lines if not line.startswith('WORKER_THREAD_LIMIT=')]
        if lines and not lines[-1].endswith('\n'): lines[-1] += '\n'
        lines.append('WORKER_THREAD_LIMIT=' + str(value) + '\n')
        temporary = self.env_file.with_name(self.env_file.name + '.pid-limit-tmp')
        owner = self.env_file.stat() if self.env_file.exists() else self.compose.stat()
        mode = stat.S_IMODE(owner.st_mode) if self.env_file.exists() else 0o600
        with open(temporary, 'w', encoding='utf-8') as out:
            out.write(''.join(lines)); out.flush(); os.fsync(out.fileno())
        self._set_metadata(temporary, mode, owner.st_uid, owner.st_gid)
        os.replace(temporary, self.env_file); self._sync_env_directory()

    def dispatch(self, method, params):
        if not isinstance(params, dict): raise ControllerError('Params không hợp lệ')
        with self.lock:
            if method == 'status' and not params: return self.status()
            if method not in {'set_limit', 'restore_limit'} or set(params) != {'limit'}:
                raise ControllerError('Host PID method không hỗ trợ')
            wanted = params['limit']; before = self.status()
            rollback = method == 'restore_limit'
            if rollback:
                if (self.rollback_ticket is None or wanted != self.rollback_ticket['limit'] or
                        before['container_id'] != self.rollback_ticket['container_id']):
                    raise ControllerError('PID rollback ticket không khớp')
            elif type(wanted) is not int or not MIN_LIMIT <= wanted <= MAX_LIMIT:
                raise ControllerError('thread_limit phải trong 256..16384')
            if not rollback:
                self._require_compose_variable()
                if before['parent_limit'] is not None and wanted > before['parent_limit']:
                    raise ControllerError('Trần thread bị giới hạn bởi ancestor: ' + str(before['parent_limit']))
            if not rollback and wanted < before['current'] + HEADROOM:
                raise ControllerError('Trần thread cần ít nhất ' + str(before['current'] + HEADROOM) + ' theo tải hiện tại')
            obj, _ = self.identity()
            if obj['Id'] != before['container_id']:
                raise ControllerError('Worker đổi identity trước khi áp dụng PID limit')
            env_before = self._env_snapshot()
            # Target pinned to the verified full ID, never arbitrary user-supplied container names.
            try:
                self.runner(['docker', 'update', '--pids-limit', '-1' if wanted == 'max' else str(wanted), obj['Id']])
                after = self.status()
                if (after['container_id'] != obj['Id'] or after['local_limit'] != wanted or
                        not rollback and after['effective_limit'] != wanted):
                    raise ControllerError('Giới hạn Docker chưa có hiệu lực')
                if rollback:
                    self._restore_env(self.rollback_ticket['env'])
                else:
                    self._persist(wanted)
                    persisted = self.env_file.read_text(encoding='utf-8').splitlines()
                    if 'WORKER_THREAD_LIMIT=' + str(wanted) not in persisted:
                        raise ControllerError('PID Compose persistence chưa xác nhận')
            except (ControllerError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
                try:
                    self._restore_transaction(obj['Id'], before['local_limit'], env_before)
                except (ControllerError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as restore_exc:
                    raise ControllerError('PID operation thất bại; live/env rollback chưa xác nhận') from restore_exc
                raise ControllerError('PID operation thất bại; đã xác nhận phục hồi live limit và Compose env') from exc
            self.rollback_ticket = None if rollback else {'limit': before['local_limit'], 'container_id': obj['Id'], 'env': env_before}
            return {**after, 'previous_limit': before['local_limit'], 'persisted': True, 'restarted': False}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(5)
        try:
            _, uid, _ = struct.unpack('3i', self.request.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i')))
            if uid != 0: raise ControllerError('Chỉ network worker được gọi host PID controller')
            raw = self.rfile.readline(MAX_MESSAGE + 1)
            if len(raw) > MAX_MESSAGE or not raw.endswith(b'\n'): raise ControllerError('Request quá lớn')
            request = json.loads(raw)
            if not isinstance(request,dict) or set(request)!={'method','params'}: raise ControllerError('Request không hợp lệ')
            result = self.server.controller.dispatch(request['method'],request['params'])
            response={'ok':True,'result':result}
        except (ControllerError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
            response={'ok':False,'error':str(exc)[:512]}
        self.wfile.write(json.dumps(response).encode()+b'\n')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--compose',required=True)
    parser.add_argument('--container',default='ipv6-proxy-manager-worker-1')
    parser.add_argument('--project',default='ipv6-proxy-manager')
    args=parser.parse_args()
    controller=PidController(container=args.container,project=args.project,compose=args.compose)
    # Rebind when Compose recreates the runtime mount. No Docker socket is exposed to either container.
    while True:
        try:
            _, source=controller.identity(); path=source/'host-control.sock'
            if path.exists():
                if not stat.S_ISSOCK(path.lstat().st_mode): raise ControllerError('Host controller path collision')
                path.unlink()
            with socketserver.UnixStreamServer(str(path),Handler) as server:
                server.controller=controller;server.timeout=2
                os.chown(path,0,10001);path.chmod(0o660)
                while True:
                    server.handle_request()
                    try:
                        _, current_source=controller.identity()
                        if current_source!=source:break
                    except (ControllerError,OSError,ValueError,KeyError,subprocess.SubprocessError):break
        except (ControllerError,OSError,ValueError,KeyError,subprocess.SubprocessError):
            import time;time.sleep(2)


if __name__=='__main__':main()
