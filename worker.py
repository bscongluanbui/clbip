"""One network reconciler, bounded authenticated Unix socket RPC, owned shutdown."""
import json
import logging
import os
from pathlib import Path
import signal
import socketserver
import stat
import threading
import time
from credentials import CredentialError, DashboardCredentialStore, validate_password_change
from rpc import MAX_MESSAGE, authenticate, read_secret
from service import OperationError, ProxyService
from validation import ValidationError
from heartbeat import HeartbeatMonitor
from runtime_monitor import RuntimeMonitor


def report(service, method, *args):
    """Notification storage problems must not destroy an RPC response."""
    if service is None:
        return
    try:
        getattr(service, method)(*args)
    except Exception as exc:
        logging.error('Worker notification failed: %s', type(exc).__name__)


def credential_dispatch(server, params):
    """Credential updates use their own lock, never the network mutation lock."""
    values = validate_password_change(params)
    store = getattr(server, 'credentials', None)
    if store is None:
        raise CredentialError('Volume mật khẩu dashboard chưa được cấu hình.')
    with server.credential_lock:
        now = time.monotonic()
        server.credential_attempts = [stamp for stamp in server.credential_attempts if now - stamp < 300]
        if len(server.credential_attempts) >= 5:
            raise CredentialError('Thử đổi mật khẩu lại sau 5 phút.', 429)
        try:
            result = store.change(values['current_password'], values['new_password'], values['confirm_password'])
        except CredentialError as exc:
            if exc.status == 403:
                server.credential_attempts.append(now)
            raise
        server.credential_attempts.clear()
        return result


class WorkerHandler(socketserver.StreamRequestHandler):
    def handle(self):
        method, dispatched = None, False
        try:
            self.request.settimeout(30)
            raw = self.rfile.readline(MAX_MESSAGE + 1)
            if len(raw) > MAX_MESSAGE or not raw.endswith(b'\n'):
                raise ValidationError('Invalid request framing')
            message = json.loads(raw)
            if not isinstance(message, dict) or not authenticate(message.get('token'), self.server.token):
                response = {'ok': False, 'status': 401, 'error': 'Worker authentication failed'}
                report(self.server.service, '_report_failure', 'worker.rpc', 'Lỗi RPC worker', 'Authentication failed')
            else:
                method, params = message.get('method'), message.get('params', {})
                dispatched = method != 'change_dashboard_password'
                result = credential_dispatch(self.server, params) if method == 'change_dashboard_password' else self.server.service.dispatch(method, params)
                response = {'ok': True, 'result': result}
                if method == 'change_dashboard_password':
                    report(self.server.service, '_report_resolved', 'operation:change_dashboard_password', 'Đổi mật khẩu dashboard đã hoạt động lại')
        except CredentialError as exc:
            response = {'ok': False, 'status': exc.status, 'error': str(exc)}
            report(self.server.service, '_report_failure', 'operation:change_dashboard_password', 'Lỗi đổi mật khẩu dashboard', 'CredentialError')
        except (ValidationError, ValueError, KeyError, TypeError) as exc:
            # Validation messages describe fields but never include secret values.
            response = {'ok': False, 'status': 400, 'error': str(exc) if isinstance(exc, ValidationError) else 'Input/config validation failed'}
            if not dispatched:
                report(self.server.service, '_report_failure', 'worker.rpc', 'Lỗi RPC worker', 'Input/config validation failed')
        except OperationError as exc:
            response = {'ok': False, 'status': 503, 'error': str(exc)}
            if not dispatched:
                report(self.server.service, '_report_failure', 'worker.rpc', 'Lỗi RPC worker', 'Operation failed')
        except Exception as exc:
            logging.error('Worker method failed: %s', type(exc).__name__)
            response = {'ok': False, 'status': 500, 'error': 'Worker internal error'}
            if not dispatched:
                key = 'operation:change_dashboard_password' if method == 'change_dashboard_password' else 'worker.rpc'
                report(self.server.service, '_report_failure', key, 'Lỗi RPC worker', type(exc).__name__)
        try:
            encoded = json.dumps(response).encode() + b'\n'
            response_too_large = len(encoded) > MAX_MESSAGE
            if response_too_large:
                report(self.server.service, '_report_failure', 'worker.rpc', 'Lỗi RPC worker', 'Response too large')
                encoded = b'{"ok":false,"status":413,"error":"Worker response too large"}\n'
            self.wfile.write(encoded)
            if response.get('ok') is True and not response_too_large:
                report(self.server.service, '_report_resolved', 'worker.rpc', 'RPC worker đã đáp ứng lại')
        except Exception as exc:
            report(self.server.service, '_report_failure', 'worker.rpc', 'Lỗi truyền RPC worker', type(exc).__name__)


class WorkerServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, path, service, token, credentials=None):
        self.service, self.token = service, token
        self.credentials = credentials
        self.credential_lock, self.credential_attempts = threading.Lock(), []
        self.slots = threading.BoundedSemaphore(32)
        super().__init__(path, WorkerHandler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            report(getattr(self, 'service', None), '_report_failure', 'worker.rpc_capacity', 'RPC worker đạt giới hạn', '32 simultaneous RPC handlers')
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
            report(getattr(self, 'service', None), '_report_resolved', 'worker.rpc_capacity', 'RPC worker đã nhận kết nối lại')
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def main():
    if os.name != 'posix':
        raise SystemExit('Network worker cần Linux host-network namespace')
    import fcntl
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    os.umask(0o077)
    token = read_secret('SERVICE_TOKEN')
    if len(token) < 32:
        raise SystemExit('SERVICE_TOKEN phải có ít nhất 32 ký tự')
    path = Path(os.environ.get('WORKER_SOCKET', '/run/ipv6-manager/worker.sock'))
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o770)
    path.parent.chmod(0o770)
    lock = (path.parent / 'worker.lock').open('a')
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit('Một worker khác đang sở hữu runtime socket')
    if path.is_symlink() or (path.exists() and not stat.S_ISSOCK(path.stat().st_mode)):
        raise SystemExit('WORKER_SOCKET không phải socket riêng của manager')
    if path.exists():
        path.unlink()
    credentials = None
    password_path = os.environ.get('DASHBOARD_PASSWORD_PATH')
    if password_path:
        credentials = DashboardCredentialStore(password_path, require_root=True)
        credentials.initialize(read_secret('ADMIN_PASSWORD', required=False), group_id=os.getgid())
    service = ProxyService()
    server = WorkerServer(str(path), service, token, credentials=credentials)
    path.chmod(0o660)
    thread = threading.Thread(target=service.run_reconciler, name='network-reconciler', daemon=True)
    thread.start()
    background = []
    if service.alerts is not None:
        sender = threading.Thread(target=service.alerts.run,
            args=(lambda: service.store.read()['settings'], service.stop_event),
            name='telegram-outbox', daemon=True)
        sender.start()
        background.append(sender)
    runtime = RuntimeMonitor(service)
    dashboard_monitor = threading.Thread(target=runtime.run, args=(service.stop_event,),
        name='dashboard-monitor', daemon=True)
    dashboard_monitor.start()
    background.append(dashboard_monitor)
    heartbeat = HeartbeatMonitor()
    def heartbeat_health():
        snapshot = service.heartbeat_snapshot()
        snapshot['healthy'] = snapshot['healthy'] and runtime.healthy and thread.is_alive() and all(t.is_alive() for t in background)
        return snapshot
    heartbeat_thread = threading.Thread(target=heartbeat.run,
        args=(service.stop_event, heartbeat_health), name='external-heartbeat', daemon=True)
    heartbeat_thread.start()

    def shutdown(signum, frame):
        service.stop_event.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    try:
        server.serve_forever(poll_interval=.5)
    finally:
        service.stop_event.set()
        thread.join(timeout=30)
        # DNS in an HTTP library can outlive its socket timeout. Daemons never
        # hold the mutation lock; bounded joins preserve owned shutdown.
        deadline = time.monotonic() + 2
        for daemon in background + [heartbeat_thread]:
            daemon.join(timeout=max(0, deadline - time.monotonic()))
        with service.lock:
            service.engine.stop_3proxy()
        server.server_close()
        path.unlink(missing_ok=True)
        lock.close()


if __name__ == '__main__':
    main()
