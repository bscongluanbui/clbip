"""Authenticated local IPC. Dashboard never imports or executes network control."""
import json
import math
import os
from pathlib import Path
import secrets
import socket

MAX_MESSAGE = 2 * 1024 * 1024


def read_secret(name, *, required=True):
    path = os.environ.get(name + '_FILE')
    value = Path(path).read_text(encoding='utf-8').strip() if path else os.environ.get(name, '')
    if required and not value:
        raise RuntimeError(f'{name} hoặc {name}_FILE phải được cấu hình')
    return value


class RpcError(RuntimeError):
    def __init__(self, message, status=503):
        super().__init__(message)
        self.status = status


class WorkerClient:
    def __init__(self, socket_path=None, token=None):
        self.socket_path = socket_path or os.environ.get('WORKER_SOCKET', '/run/ipv6-manager/worker.sock')
        self.token = token if token is not None else read_secret('SERVICE_TOKEN', required=False)

    def call(self, method, params=None, *, timeout=None):
        if not isinstance(method, str) or (params is not None and not isinstance(params, dict)):
            raise RpcError('Worker request không hợp lệ', 400)
        try:
            timeout_value = float(os.environ.get('WORKER_RPC_TIMEOUT', '600') if timeout is None else timeout)
            if isinstance(timeout, bool) or not math.isfinite(timeout_value) or timeout_value <= 0:
                raise ValueError
        except (ValueError, TypeError, OverflowError):
            raise RpcError('Worker timeout không hợp lệ', 400) from None
        if len(self.token) < 32:
            raise RpcError('Service token chưa được cấu hình')
        payload = json.dumps({'token': self.token, 'method': method, 'params': params or {}}).encode() + b'\n'
        if len(payload) > MAX_MESSAGE:
            raise RpcError('Request quá lớn', 413)
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout_value)
                sock.connect(self.socket_path)
                sock.sendall(payload)
                with sock.makefile('rb') as stream:
                    raw = stream.readline(MAX_MESSAGE + 1)
        except OSError as exc:
            raise RpcError('Network worker chưa sẵn sàng') from exc
        if len(raw) > MAX_MESSAGE or not raw.endswith(b'\n'):
            raise RpcError('Worker response không hợp lệ')
        try:
            response = json.loads(raw)
            if not isinstance(response, dict) or type(response.get('ok')) is not bool:
                raise ValueError('response shape')
            if not response['ok']:
                status = response.get('status', 500)
                if type(status) is not int or not 400 <= status <= 599 or not isinstance(response.get('error'), str):
                    raise ValueError('error shape')
                raise RpcError(response['error'], status)
            if not isinstance(response.get('result'), dict):
                raise ValueError('result shape')
        except (UnicodeDecodeError, ValueError, TypeError) as exc:
            raise RpcError('Worker response không hợp lệ') from exc
        return response['result']


def authenticate(token, expected):
    return (isinstance(token, str) and isinstance(expected, str) and token.isascii()
            and expected.isascii() and len(expected) >= 32 and secrets.compare_digest(token, expected))
