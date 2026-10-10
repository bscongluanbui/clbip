"""Unprivileged Flask dashboard; privileged operations use authenticated Unix IPC."""
import logging
import hashlib
import hmac
import ipaddress
import os
from pathlib import Path
import secrets
import threading
import time
from flask import Flask, g, jsonify, redirect, render_template, request, session, url_for
from credentials import CredentialError, DashboardCredentialStore, validate_password_change
from rpc import RpcError, WorkerClient, authenticate, read_secret


def create_app(config=None, client=None):
    app = Flask(__name__)
    app.config.update(SECRET_KEY=read_secret('SECRET_KEY', required=False) or None,
                      ADMIN_PASSWORD=read_secret('ADMIN_PASSWORD', required=False),
                      DASHBOARD_PASSWORD_PATH=os.environ.get('DASHBOARD_PASSWORD_PATH', ''),
                      DASHBOARD_PASSWORD_REQUIRE_ROOT=True,
                      GUI_PORT=os.environ.get('GUI_PORT', '7070'),
                      GUI_BIND=os.environ.get('GUI_BIND', '127.0.0.1'),
                      SERVICE_TOKEN=read_secret('SERVICE_TOKEN', required=False),
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Strict',
                      SESSION_COOKIE_SECURE=os.environ.get('SESSION_COOKIE_SECURE', 'true').lower() in ('1', 'true', 'yes'),
                      MAX_CONTENT_LENGTH=65536, PERMANENT_SESSION_LIFETIME=3600)
    hosts = os.environ.get('TRUSTED_HOSTS', '')
    if hosts:
        app.config['TRUSTED_HOSTS'] = [x.strip() for x in hosts.split(',') if x.strip()]
    if config:
        app.config.update(config)
        if config.get('PREVIEW'):
            app.config['DASHBOARD_PASSWORD_PATH'] = ''
    worker = client or WorkerClient()
    attempts, login_lock = {}, threading.Lock()
    password_attempts, password_lock = {}, threading.Lock()

    def current_password():
        path = app.config.get('DASHBOARD_PASSWORD_PATH')
        if path:
            # A missing file can precede worker bootstrap; malformed/unreadable
            # persisted credentials must not reactivate the bootstrap password.
            try:
                Path(path).lstat()
            except FileNotFoundError:
                pass
            except OSError:
                raise CredentialError('Mật khẩu dashboard chưa sẵn sàng.') from None
            else:
                return DashboardCredentialStore(path, require_root=app.config['DASHBOARD_PASSWORD_REQUIRE_ROOT']).read_snapshot()
        return app.config.get('ADMIN_PASSWORD', ''), 'bootstrap'

    def password_version(password, revision):
        return hmac.new(app.secret_key.encode('utf-8'),
                        b'dashboard-password-v1\0' + revision.encode('utf-8') + b'\0'
                        + password.encode('utf-8'), hashlib.sha256).hexdigest()

    def configured():
        try:
            password, revision = current_password()
            return isinstance(password, str) and bool(app.secret_key) and len(app.secret_key) >= 32 and len(app.config.get('SERVICE_TOKEN', '')) >= 32
        except (CredentialError, OSError, ValueError, UnicodeError, TypeError):
            return False

    def csrf_token():
        if not app.secret_key:
            return ''
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_urlsafe(32)
        return session['csrf_token']

    def csrf_valid():
        provided = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token', '')
        expected = session.get('csrf_token', '')
        return bool(expected) and bool(provided) and provided.isascii() and secrets.compare_digest(expected, provided)

    def is_service():
        header = request.headers.get('Authorization', '')
        return header.startswith('Bearer ') and authenticate(header[7:], app.config.get('SERVICE_TOKEN', ''))

    @app.before_request
    def check_auth():
        if request.endpoint in ('static', 'live', 'ready', 'heartbeat_liveness'):
            return None
        if not configured():
            return jsonify(success=False, error='Dashboard secrets chưa được cấu hình'), 503
        try:
            password, revision = current_password()
            g.dashboard_password = password
            g.password_version = password_version(password, revision)
        except (CredentialError, OSError, ValueError, UnicodeError, TypeError):
            return jsonify(success=False, error='Dashboard secrets chưa được cấu hình'), 503
        version = session.get('password_version')
        if session.get('logged_in') and (not isinstance(version, str) or not version.isascii()
                or not secrets.compare_digest(version, g.password_version)):
            session.clear()
        if not password:
            # An empty persisted password explicitly selects password-free
            # dashboard access. Still establish a versioned CSRF session.
            session.update(logged_in=True, password_version=g.password_version)
            session.permanent = True
            csrf_token()
        if request.endpoint == 'csrf':
            return None
        if request.endpoint == 'login':
            if request.method == 'POST' and not csrf_valid():
                return jsonify(success=False, error='CSRF token không hợp lệ'), 403
            return None
        service = is_service()
        if request.endpoint == 'telegram_config' and not service:
            return jsonify(success=False, error='Service authentication required'), 403
        if not service and not session.get('logged_in'):
            return (jsonify(success=False, error='Vui lòng đăng nhập'), 401) if request.path.startswith('/api/') else redirect(url_for('login'))
        if not service and request.method not in ('GET', 'HEAD', 'OPTIONS') and not csrf_valid():
            return jsonify(success=False, error='CSRF token không hợp lệ'), 403
        if app.config.get('PREVIEW') and request.path.startswith('/api/') and request.method not in ('GET', 'HEAD', 'OPTIONS'):
            return jsonify(success=False, error='Chế độ xem trước chỉ cho phép đọc'), 403

    @app.after_request
    def headers(response):
        response.headers.update({'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
                                 'Referrer-Policy': 'no-referrer',
                                 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"})
        if request.path.startswith('/api/') or request.path in ('/login', '/', '/heartbeatz'):
            response.headers['Cache-Control'] = 'no-store'
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        return response

    @app.errorhandler(RpcError)
    def rpc_error(exc):
        return jsonify(success=False, error=str(exc)), exc.status

    @app.errorhandler(400)
    def bad_request(exc):
        return jsonify(success=False, error='Request hoặc JSON body không hợp lệ'), 400

    @app.errorhandler(413)
    def too_large(exc):
        return jsonify(success=False, error='Request quá lớn'), 413

    @app.errorhandler(500)
    def internal_error(exc):
        logging.error('Dashboard request failed: %s', type(exc).__name__)
        return jsonify(success=False, error='Internal error; kiểm tra log đã redacted'), 500

    def body():
        value = request.get_json()
        if not isinstance(value, dict):
            raise RpcError('JSON body phải là object', 400)
        return value

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            key, now = request.remote_addr or 'unknown', time.monotonic()
            with login_lock:
                bucket = [x for x in attempts.get(key, []) if now-x < 300]
                if len(bucket) >= 5:
                    return render_template('login.html', csrf_token=csrf_token(), error='Thử lại sau 5 phút'), 429
                password = request.form.get('password', '')
                if not secrets.compare_digest(password.encode('utf-8'), g.dashboard_password.encode('utf-8')):
                    attempts[key] = bucket + [now]
                    if len(attempts) > 10000:
                        attempts.clear()
                        attempts[key] = bucket + [now]
                    return render_template('login.html', csrf_token=csrf_token(), error='Mật khẩu không chính xác'), 401
                attempts.pop(key, None)
            session.clear()
            session.update(logged_in=True, password_version=g.password_version)
            session.permanent = True
            csrf_token()
            return redirect(url_for('index'))
        return render_template('login.html', csrf_token=csrf_token(), error=None)

    @app.post('/logout')
    def logout():
        session.clear()
        return redirect(url_for('login'))

    @app.get('/')
    def index():
        return render_template('index.html')

    @app.get('/api/csrf')
    def csrf():
        return jsonify(csrf_token=csrf_token())

    @app.get('/livez')
    def live():
        return jsonify(alive=True)

    @app.get('/heartbeatz')
    def heartbeat_liveness():
        # Public booleans only. No pool addresses, credentials, error text, or
        # deep NIC/egress readiness checks enter this cheap observation.
        flags = {'alive': True, 'worker_alive': False, 'progress_fresh': False}
        if not configured():
            return jsonify(flags), 503
        try:
            snapshot = worker.call('controlplane_liveness', timeout=2)
        except RpcError:
            return jsonify(flags), 503
        if not isinstance(snapshot, dict):
            return jsonify(flags), 503
        flags['worker_alive'] = snapshot.get('reconciler_alive') is True
        flags['progress_fresh'] = snapshot.get('progress_fresh') is True
        healthy = snapshot.get('healthy') is True and all(flags.values())
        return jsonify(flags), 200 if healthy else 503

    @app.get('/readyz')
    def ready():
        if not configured():
            return jsonify(ready=False), 503
        try:
            health = worker.call('health')
        except RpcError:
            return jsonify(ready=False), 503
        return jsonify(ready=bool(health.get('ready'))), 200 if health.get('ready') else 503

    @app.get('/api/internal/telegram-config')
    def telegram_config():
        return jsonify(worker.call('telegram_config'))

    @app.post('/api/password')
    def change_password():
        # A service bearer token does not substitute for dashboard login and
        # current-password reauthentication, even if its other APIs can mutate.
        if not session.get('logged_in') or not csrf_valid():
            raise RpcError('Đăng nhập dashboard và gửi CSRF token để đổi mật khẩu', 403)
        try:
            values = validate_password_change(body())
        except CredentialError as exc:
            raise RpcError(str(exc), exc.status) from None
        key, now = request.remote_addr or 'unknown', time.monotonic()
        with password_lock:
            bucket = [stamp for stamp in password_attempts.get(key, []) if now - stamp < 300]
            if len(bucket) >= 5:
                response = jsonify(success=False, error='Thử đổi mật khẩu lại sau 5 phút')
                response.status_code = 429
                response.headers['Retry-After'] = '300'
                return response
            try:
                result = worker.call('change_dashboard_password', values)
            except RpcError as exc:
                if exc.status == 403:
                    if len(password_attempts) > 10000:
                        password_attempts.clear()
                    password_attempts[key] = bucket + [now]
                try:
                    password, revision = current_password()
                    if password_version(password, revision) != g.password_version:
                        session.clear()
                except (CredentialError, OSError, UnicodeError, TypeError, ValueError):
                    pass
                raise
            changed = isinstance(result, dict) and result.get('changed') is True and result.get('requires_login') is True
            unchanged = isinstance(result, dict) and result.get('changed') is False and result.get('requires_login') is False and result.get('unchanged') is True
            if not (changed or unchanged):
                raise RpcError('Worker chưa xác nhận cập nhật mật khẩu dashboard', 503)
            password_attempts.pop(key, None)
        if changed:
            session.clear()
        return jsonify(success=True, **result)

    # Explicit route table, never expose arbitrary worker attributes/method names.
    routes = [
        ('/api/settings', 'GET', 'settings', 'none'), ('/api/settings', 'POST', 'save_settings', 'body'),
        ('/api/users', 'GET', 'users', 'none'), ('/api/users', 'POST', 'add_user', 'body'),
        ('/api/users/<username>', 'DELETE', 'delete_user', 'path'),
        ('/api/interfaces', 'GET', 'interfaces', 'none'), ('/api/interface-subnets', 'GET', 'subnets', 'query'),
        ('/api/ipv6-addresses', 'GET', 'addresses', 'query'), ('/api/proxies', 'GET', 'proxies', 'none'),
        ('/api/proxies/generate', 'POST', 'generate', 'body'), ('/api/proxies/reset', 'POST', 'generate', 'reset'),
        ('/api/proxies/<int:proxy_id>', 'DELETE', 'delete', 'path'),
        ('/api/proxies/<int:proxy_id>/rotate', 'POST', 'rotate', 'path'),
        ('/api/proxies/rotate', 'POST', 'rotate', 'none'), ('/api/proxies/delete-all', 'POST', 'delete_all', 'none'),
        ('/api/cleanup-ipv6', 'POST', 'cleanup', 'none'), ('/api/proxy/start', 'POST', 'start', 'none'),
        ('/api/proxy/stop', 'POST', 'stop', 'none'), ('/api/proxy/restart', 'POST', 'restart', 'none'),
        ('/api/status', 'GET', 'status', 'none'), ('/api/proxy/health', 'GET', 'health', 'none'),
        ('/api/proxies/export', 'GET', 'export', 'query'), ('/api/logs', 'GET', 'logs', 'query'),
        ('/api/proxy/speedtest', 'POST', 'speedtest', 'body'),
        ('/api/proxy/speedtest-batch', 'POST', 'speedtest_batch', 'body'),
        ('/api/proxy/diagnostics', 'POST', 'diagnostics', 'body'),
        ('/api/proxy/auto-optimize', 'POST', 'auto_optimize', 'body'),
         ('/api/telegram/test', 'POST', 'telegram_test', 'none'), ('/api/events', 'GET', 'events', 'none'),
        ('/api/ownership/resolve', 'POST', 'resolve_uncertain', 'body'),
    ]

    def view(method, mode, mutation):
        def handle(**path_params):
            params = body() if mode in ('body', 'reset') else dict(request.args) if mode == 'query' else dict(path_params)
            if mode == 'reset':
                params['recreate'] = True
            if method == 'logs' and 'lines' in params:
                try:
                    params['lines'] = int(params['lines'])
                except ValueError:
                    raise RpcError('lines phải là số nguyên', 400)
            if mutation and request.headers.get('Idempotency-Key'):
                params['_idempotency_key'] = request.headers['Idempotency-Key']
            result = worker.call(method, params)
            if method == 'status':
                # The dashboard bind port is known here, not in the worker.
                # A reverse-proxy origin port must not overwrite LAN URLs.
                try:
                    port = int(app.config.get('GUI_PORT', 7070))
                    if not 1 <= port <= 65535:
                        raise ValueError('port range')
                except (TypeError, ValueError):
                    port = 7070
                try:
                    bind = ipaddress.IPv4Address(app.config.get('GUI_BIND', '127.0.0.1'))
                    if bind.is_multicast or bind.is_reserved:
                        raise ValueError('bind address')
                except (ValueError, TypeError):
                    bind = ipaddress.IPv4Address('127.0.0.1')
                observed = []
                for candidate in result.get('dashboard_hosts', []):
                    try:
                        address = ipaddress.IPv4Address(candidate) if isinstance(candidate, str) else None
                    except ValueError:
                        continue
                    if address is not None and not (address.is_unspecified or address.is_multicast or address.is_reserved):
                        if str(address) not in observed:
                            observed.append(str(address))
                hosts = observed if bind.is_unspecified else [str(bind)] if bind.is_loopback or str(bind) in observed else []
                result = {**result, 'dashboard_port': port, 'dashboard_bind': str(bind), 'dashboard_hosts': hosts,
                          'dashboard_password_required': bool(g.dashboard_password)}
            return jsonify(result)
        return handle

    for number, (url, http_method, method, mode) in enumerate(routes):
        app.add_url_rule(url, f'rpc_{number}_{method}', view(method, mode, http_method != 'GET' and method != 'diagnostics'), methods=[http_method])
    return app


app = create_app()
if __name__ == '__main__':
    raise SystemExit('Dùng gunicorn app:app qua start.sh; worker chạy worker.py')
