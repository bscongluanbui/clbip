"""Offline credential persistence, dashboard and worker routing regressions."""
import copy
from concurrent.futures import ThreadPoolExecutor
import io
import json
import os
from pathlib import Path
import socketserver
import stat
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import app as dashboard
from credentials import CredentialError, DashboardCredentialStore, validate_password_change
from rpc import RpcError


OLD = 'Initial-fixture-pass-42!'
NEW = 'Updated-fixture-pass-43!'
CONFIG = {'TESTING': True, 'SECRET_KEY': 'session-fixture-' + 'k' * 40,
          'ADMIN_PASSWORD': OLD, 'SERVICE_TOKEN': 'service-fixture-' + 't' * 40,
          'SESSION_COOKIE_SECURE': False, 'TRUSTED_HOSTS': ['localhost']}


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1] / 'tests')
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'admin_password'
        self.store = DashboardCredentialStore(self.path)
        self.store.initialize(OLD, group_id=os.getgid() if hasattr(os, 'getgid') else 10001)

    def values(self, **updates):
        return {'current_password': OLD, 'new_password': NEW, 'confirm_password': NEW, **updates}

    def test_bootstrap_does_not_overwrite_changed_password(self):
        self.assertFalse(self.store.initialize('different-bootstrap-pass'))
        self.store.change(OLD, NEW, NEW)
        self.assertFalse(self.store.initialize(OLD))
        self.assertEqual(self.store.read(), NEW)

    def test_atomic_password_change_persists_and_revises_snapshot(self):
        before = self.store.read_snapshot()
        result = self.store.change(OLD, NEW, NEW)
        self.assertEqual(result, {'changed': True, 'requires_login': True})
        reopened = DashboardCredentialStore(self.path)
        self.assertEqual(reopened.read(), NEW)
        self.assertNotEqual(before[1], reopened.read_snapshot()[1])
        self.assertFalse(list(self.path.parent.glob('.admin-password-*')))
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o640)

    def test_current_password_is_checked_without_exposing_values(self):
        with self.assertRaises(CredentialError) as caught:
            self.store.change('wrong-fixture-password', NEW, NEW)
        self.assertEqual(caught.exception.status, 403)
        self.assertNotIn(OLD, str(caught.exception))
        self.assertNotIn(NEW, str(caught.exception))
        self.assertEqual(self.store.read(), OLD)

    def test_failed_replace_preserves_original_and_removes_temporary(self):
        with patch('credentials.os.replace', side_effect=OSError('fixture failure')):
            with self.assertRaises(CredentialError):
                self.store.change(OLD, NEW, NEW)
        self.assertEqual(self.store.read(), OLD)
        self.assertFalse(list(self.path.parent.glob('.admin-password-*')))

    def test_concurrent_stale_changes_have_one_commit(self):
        def change(index):
            password = NEW + str(index)
            try:
                DashboardCredentialStore(self.path).change(OLD, password, password)
                return 'committed'
            except CredentialError as exc:
                return exc.status
        with ThreadPoolExecutor(max_workers=2) as executor:
            self.assertCountEqual(executor.map(change, (1, 2)), ['committed', 403])

    def test_invalid_payloads_are_rejected_before_storage(self):
        invalid = [None, [], {}, self.values(extra='ignored'),
                   self.values(confirm_password='different-fixture-pass'), self.values(current_password=5),
                   self.values(new_password='\ud800', confirm_password='\ud800')]
        for value in invalid:
            with self.subTest(kind=type(value).__name__), self.assertRaises(CredentialError) as caught:
                validate_password_change(value)
            self.assertEqual(caught.exception.status, 400)

    def test_unicode_password_is_saved_exactly(self):
        value = '  Mật-khẩu-mới-雪-42  '
        self.store.change(OLD, value, value)
        self.assertEqual(self.store.read(), value)

    def test_simple_long_whitespace_controls_and_empty_passwords_are_exact(self):
        current = OLD
        for value in ('a', 'x' * 257, ' ', 'Mật', 'line1\nline2\r', ''):
            with self.subTest(length=len(value)):
                self.store.change(current, value, value)
                self.assertEqual(self.store.read(), value)
                current = value

    def test_empty_bootstrap_and_same_password_are_supported(self):
        self.path.unlink()
        self.store.initialize('')
        self.assertEqual(self.store.read(), '')
        snapshot = self.store.read_snapshot()
        self.assertEqual(self.store.change('', '', ''), {'changed': False, 'requires_login': False, 'unchanged': True})
        self.assertEqual(self.store.read_snapshot(), snapshot)
        self.store.change('', '1', '1')
        snapshot = self.store.read_snapshot()
        self.assertEqual(self.store.change('1', '1', '1')['unchanged'], True)
        self.assertEqual(self.store.read_snapshot(), snapshot)

    def test_password_storage_and_request_have_resource_bounds(self):
        value = 'x' * 65537
        with self.assertRaises(CredentialError) as caught:
            validate_password_change(self.values(new_password=value, confirm_password=value))
        self.assertEqual(caught.exception.status, 413)
        self.path.write_bytes(value.encode())
        with self.assertRaises(CredentialError):
            self.store.read()


class PasswordWorker:
    def __init__(self, store):
        self.store, self.calls, self.error = store, [], None

    def call(self, method, params=None):
        self.calls.append((method, copy.deepcopy(params)))
        if self.error:
            raise self.error
        if method == 'change_dashboard_password':
            try:
                return self.store.change(params['current_password'], params['new_password'], params['confirm_password'])
            except CredentialError as exc:
                raise RpcError(str(exc), exc.status) from None
        if method == 'status':
            return {'success': True, 'dashboard_hosts': ['192.168.1.3', '100.64.1.2', 'invalid-host', '0.0.0.0']}
        return {'success': True, 'ready': True, 'proxy_running': True}


class DashboardPasswordTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1] / 'tests')
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'admin_password'
        self.store = DashboardCredentialStore(self.path)
        self.store.initialize(OLD, group_id=os.getgid() if hasattr(os, 'getgid') else 10001)
        self.worker = PasswordWorker(self.store)
        self.config = {**CONFIG, 'DASHBOARD_PASSWORD_PATH': str(self.path), 'DASHBOARD_PASSWORD_REQUIRE_ROOT': False}
        self.application = dashboard.create_app(self.config, self.worker)
        self.client = self.application.test_client()

    def login(self, client=None, password=OLD):
        client = client or self.client
        token = client.get('/api/csrf').get_json()['csrf_token']
        response = client.post('/login', data={'password': password, 'csrf_token': token})
        self.assertEqual(response.status_code, 302)
        return client.get('/api/csrf').get_json()['csrf_token']

    def change(self, token, current=OLD, **kwargs):
        return self.client.post('/api/password', json={'current_password': current, 'new_password': NEW, 'confirm_password': NEW},
                                headers={'X-CSRF-Token': token}, **kwargs)

    def test_change_revokes_all_sessions_across_app_instances(self):
        token = self.login()
        second = dashboard.create_app(self.config, self.worker).test_client()
        self.login(second)
        result = self.change(token)
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.get_json(), {'success': True, 'changed': True, 'requires_login': True})
        self.assertEqual(self.client.get('/api/status').status_code, 401)
        self.assertEqual(second.get('/api/status').status_code, 401)
        self.login(second, NEW)
        self.assertEqual(second.get('/api/status').status_code, 200)
        methods = [method for method, params in self.worker.calls]
        self.assertNotIn('stop', methods)
        self.assertNotIn('restart', methods)
        self.assertNotIn('save_settings', methods)

    def test_old_password_fails_new_password_works_after_app_restart(self):
        self.store.change(OLD, NEW, NEW)
        client = dashboard.create_app(self.config, self.worker).test_client()
        token = client.get('/api/csrf').get_json()['csrf_token']
        self.assertEqual(client.post('/login', data={'password': OLD, 'csrf_token': token}).status_code, 401)
        self.login(client, NEW)

    def test_current_password_failure_leaves_session_and_storage_intact(self):
        token = self.login()
        self.assertEqual(self.change(token, current='wrong-fixture-current').status_code, 403)
        self.assertEqual(self.store.read(), OLD)
        self.assertEqual(self.client.get('/api/status').status_code, 200)

    def test_password_change_requires_browser_login_and_csrf(self):
        self.assertEqual(self.change('unused-fixture-token').status_code, 401)
        self.client.post('/api/password', headers={'Authorization': 'Bearer ' + CONFIG['SERVICE_TOKEN']}, json={})
        self.assertFalse(self.worker.calls)
        self.login()
        self.assertEqual(self.change('wrong-fixture-csrf').status_code, 403)
        self.assertFalse(self.worker.calls)

    def test_reauthentication_attempts_are_rate_limited(self):
        token = self.login()
        for index in range(5):
            self.assertEqual(self.change(token, current='wrong-fixture-current').status_code, 403)
        result = self.change(token)
        self.assertEqual(result.status_code, 429)
        self.assertEqual(result.headers['Retry-After'], '300')

    def test_failure_after_commit_clears_session(self):
        token = self.login()
        original = self.worker.call
        def commit_then_fail(method, params):
            original(method, params)
            raise RpcError('Storage sync not confirmed', 503)
        self.worker.call = commit_then_fail
        self.assertEqual(self.change(token).status_code, 503)
        with self.client.session_transaction() as session:
            self.assertNotIn('logged_in', session)
        self.assertEqual(self.store.read(), NEW)

    def test_unreadable_persisted_password_does_not_fallback(self):
        self.path.write_bytes(b'\xff')
        self.assertEqual(self.client.get('/api/csrf').status_code, 503)
        self.assertEqual(self.client.get('/livez').status_code, 200)

    def test_missing_file_uses_bootstrap_only_until_worker_initializes(self):
        self.path.unlink()
        self.login()
        self.store.initialize(OLD)
        self.assertEqual(self.client.get('/api/status').status_code, 401)

    def test_preview_ignores_runtime_password_and_blocks_mutations(self):
        app = dashboard.create_app({**CONFIG, 'PREVIEW': True, 'DASHBOARD_PASSWORD_PATH': str(self.path)}, self.worker)
        client = app.test_client()
        token = self.login(client)
        for path in ('/api/settings', '/api/proxy/stop', '/api/proxies/generate', '/api/password'):
            self.assertEqual(client.post(path, json={}, headers={'X-CSRF-Token': token}).status_code, 403)
        self.assertFalse(self.worker.calls)
        self.assertIn('PREVIEW', client.get('/').text)
        self.assertEqual(client.post('/logout', headers={'X-CSRF-Token': token}).status_code, 302)

    def test_status_uses_validated_real_dashboard_listener_port(self):
        for configured, expected in (('7071', 7071), ('65536', 7070), ('wrong-port', 7070)):
            app = dashboard.create_app({**self.config, 'GUI_PORT': configured}, self.worker)
            client = app.test_client()
            self.login(client)
            self.assertEqual(client.get('/api/status').get_json()['dashboard_port'], expected)

    def test_status_hosts_match_actual_dashboard_bind(self):
        for bind, hosts in (('127.0.0.1', ['127.0.0.1']), ('0.0.0.0', ['192.168.1.3', '100.64.1.2']),
                            ('192.168.1.3', ['192.168.1.3']), ('100.64.1.2', ['100.64.1.2']),
                            ('192.168.1.99', []), ('wrong-bind', ['127.0.0.1'])):
            with self.subTest(bind=bind):
                app = dashboard.create_app({**self.config, 'GUI_BIND': bind}, self.worker)
                client = app.test_client()
                self.login(client)
                status = client.get('/api/status').get_json()
                self.assertEqual(status['dashboard_hosts'], hosts)
                self.assertEqual(status['dashboard_bind'], '127.0.0.1' if bind == 'wrong-bind' else bind)

    def test_empty_password_disables_login_but_keeps_csrf_and_can_be_reenabled(self):
        token = self.login()
        response = self.client.post('/api/password', json={'current_password': OLD, 'new_password': '', 'confirm_password': ''},
                                    headers={'X-CSRF-Token': token})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.store.read(), '')
        anonymous = dashboard.create_app(self.config, self.worker).test_client()
        self.assertEqual(anonymous.get('/').status_code, 200)
        self.assertEqual(anonymous.get('/api/settings').status_code, 200)
        self.assertFalse(anonymous.get('/api/status').get_json()['dashboard_password_required'])
        self.assertEqual(anonymous.post('/api/proxy/stop').status_code, 403)
        csrf = anonymous.get('/api/csrf').get_json()['csrf_token']
        self.assertEqual(anonymous.post('/api/settings', json={}, headers={'X-CSRF-Token': csrf}).status_code, 200)
        response = anonymous.post('/api/password', json={'current_password': '', 'new_password': '1', 'confirm_password': '1'},
                                  headers={'X-CSRF-Token': csrf})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(anonymous.get('/api/status').status_code, 401)
        self.login(anonymous, '1')
        self.assertTrue(anonymous.get('/api/status').get_json()['dashboard_password_required'])

    def test_same_password_request_preserves_revision_and_session(self):
        token = self.login()
        snapshot = self.store.read_snapshot()
        response = self.client.post('/api/password', json={'current_password': OLD, 'new_password': OLD, 'confirm_password': OLD},
                                    headers={'X-CSRF-Token': token})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {'success': True, 'changed': False, 'requires_login': False, 'unchanged': True})
        self.assertEqual(self.store.read_snapshot(), snapshot)
        self.assertEqual(self.client.get('/api/status').status_code, 200)

    def test_empty_current_password_never_matches_nonempty_stored_password(self):
        token = self.login()
        self.assertEqual(self.change(token, current='').status_code, 403)
        self.assertEqual(self.store.read(), OLD)

    def test_no_password_bootstrap_needs_only_session_and_service_secrets(self):
        client = dashboard.create_app({**CONFIG, 'ADMIN_PASSWORD': '', 'DASHBOARD_PASSWORD_PATH': ''}, self.worker).test_client()
        self.assertEqual(client.get('/').status_code, 200)
        self.assertEqual(client.get('/api/status').status_code, 200)
        token = client.get('/api/csrf').get_json()['csrf_token']
        self.assertEqual(client.post('/login', data={'password': '', 'csrf_token': token}).status_code, 302)


class WorkerCredentialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with patch.object(socketserver, 'ThreadingUnixStreamServer', socketserver.ThreadingTCPServer, create=True):
            import worker
            cls.worker = worker

    def server(self):
        return SimpleNamespace(token=CONFIG['SERVICE_TOKEN'], credentials=Mock(),
                               credential_lock=threading.Lock(), credential_attempts=[], service=Mock())

    def request(self, server, params, token=None):
        handler = self.worker.WorkerHandler.__new__(self.worker.WorkerHandler)
        handler.server, handler.request = server, Mock()
        handler.rfile = io.BytesIO(json.dumps({'token': token or CONFIG['SERVICE_TOKEN'],
            'method': 'change_dashboard_password', 'params': params}).encode() + b'\n')
        handler.wfile = io.BytesIO()
        handler.handle()
        return json.loads(handler.wfile.getvalue())

    def values(self):
        return {'current_password': OLD, 'new_password': NEW, 'confirm_password': NEW}

    def test_special_rpc_never_calls_network_dispatch(self):
        server = self.server()
        server.credentials.change.return_value = {'changed': True, 'requires_login': True}
        result = self.request(server, self.values())
        self.assertTrue(result['ok'])
        server.service.dispatch.assert_not_called()
        server.credentials.change.assert_called_once_with(OLD, NEW, NEW)

    def test_special_rpc_authentication_and_validation(self):
        server = self.server()
        self.assertEqual(self.request(server, self.values(), token='wrong-fixture-token')['status'], 401)
        self.assertEqual(self.request(server, {'path': '/untrusted'})['status'], 400)
        server.credentials.change.assert_not_called()
        server.service.dispatch.assert_not_called()

    def test_worker_process_rate_limit_spans_requests(self):
        server = self.server()
        server.credentials.change.side_effect = CredentialError('Current password invalid', 403)
        for index in range(5):
            self.assertEqual(self.request(server, self.values())['status'], 403)
        self.assertEqual(self.request(server, self.values())['status'], 429)
        self.assertEqual(server.credentials.change.call_count, 5)

    def test_unconfigured_store_reports_operational_error(self):
        server = self.server()
        server.credentials = None
        self.assertEqual(self.request(server, self.values())['status'], 503)
        server.service.dispatch.assert_not_called()


if __name__ == '__main__':
    unittest.main()
