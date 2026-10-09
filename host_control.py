"""Small Unix client for the optional host PID controller; never a Docker socket."""
import copy
import json
import os
import socket
import threading
import time

MAX_MESSAGE = 8192


class HostControlError(RuntimeError):
    pass


class HostControlClient:
    def __init__(self, socket_path=None, timeout=90.0):
        self.socket_path = socket_path or os.environ.get('HOST_CONTROL_SOCKET', '/run/ipv6-manager/host-control.sock')
        self.timeout = timeout
        self._lock = threading.Lock()
        self._cached = None
        self._observed = 0.0

    def _call(self, method, params=None):
        raw = json.dumps({'method': method, 'params': params or {}}, separators=(',', ':')).encode() + b'\n'
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(0.3 if method == 'status' else self.timeout)
                sock.connect(self.socket_path)
                sock.sendall(raw)
                with sock.makefile('rb') as stream:
                    response = stream.readline(MAX_MESSAGE + 1)
            if len(response) > MAX_MESSAGE or not response.endswith(b'\n'):
                raise ValueError('response size')
            obj = json.loads(response)
            if not isinstance(obj, dict) or type(obj.get('ok')) is not bool:
                raise ValueError('response shape')
            if not obj['ok']:
                raise HostControlError(str(obj.get('error', 'Host controller error'))[:512])
            result = obj.get('result')
            if not isinstance(result, dict):
                raise ValueError('result shape')
            return result
        except HostControlError:
            raise
        except (AttributeError, OSError, ValueError, TypeError) as exc:
            raise HostControlError('Host PID controller chưa sẵn sàng; chạy scripts/install_host_controller.sh trên host.') from exc

    def status(self):
        if not self._lock.acquire(blocking=False):
            return copy.deepcopy(self._cached or {'available': False, 'effective_limit': None,
                                                  'error': 'Host PID status đang được quan sát'})
        try:
            now = time.monotonic()
            if self._cached is None or now - self._observed >= 5:
                try:
                    self._cached = {'available': True, **self._call('status')}
                except HostControlError as exc:
                    self._cached = {'available': False, 'effective_limit': None, 'error': str(exc)}
                self._observed = now
            return copy.deepcopy(self._cached)
        finally:
            self._lock.release()

    def apply_limit(self, new_limit):
        if type(new_limit) is not int or not 256 <= new_limit <= 16384:
            raise HostControlError('thread_limit phải trong 256..16384')
        result = self._call('set_limit', {'limit': new_limit})
        if result.get('effective_limit') != new_limit or result.get('previous_limit') not in ('max',) and type(result.get('previous_limit')) is not int:
            raise HostControlError('Host PID controller chưa xác nhận giới hạn hiệu lực')
        with self._lock:
            self._cached = None
        return result

    def restore_limit(self, previous_limit):
        result = self._call('restore_limit', {'limit': previous_limit})
        if result.get('local_limit', result.get('effective_limit')) != previous_limit:
            raise HostControlError('Host PID rollback chưa xác nhận')
        with self._lock:
            self._cached = None
        return result
