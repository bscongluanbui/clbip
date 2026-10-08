"""Dashboard auth/CSRF/readiness tests using an injected offline worker client."""
import copy
import os
import unittest
from unittest.mock import patch

import app as dashboard
from rpc import RpcError

TOKEN = 'dashboard-test-token-' + 'x' * 40
CONFIG = {'TESTING': True, 'SECRET_KEY': 'session-test-key-' + 'y' * 40,
          'ADMIN_PASSWORD': 'Dashboard_Test_42!', 'SERVICE_TOKEN': TOKEN,
          'SESSION_COOKIE_SECURE': True, 'TRUSTED_HOSTS': ['localhost']}


class FakeWorker:
    def __init__(self):
        self.calls = []
        self.responses = {'settings': {'auth_type': 'userpass', 'telegram_bot_token_configured': True},
                          'users': {'users': [{'username': 'tester'}]},
                          'status': {'proxy_running': False, 'desired_state': 'stopped'},
                          'health': {'ready': True, 'desired_state': 'stopped', 'processes': {'expected': 0, 'running': 0}},
                          'telegram_config': {'token': 'test-only-bot-token', 'chat_id': '123', 'allowed_user_ids': [456]}}
        self.error = None

    def call(self, method, params=None):
        self.calls.append((method, copy.deepcopy(params)))
        if self.error:
            raise self.error
        return copy.deepcopy(self.responses.get(method, {'success': True}))


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.worker = FakeWorker()
        self.app = dashboard.create_app(CONFIG, client=self.worker)
        self.client = self.app.test_client()

    def token(self):
        response = self.client.get('/api/csrf')
        self.assertEqual(response.status_code, 200)
        return response.get_json()['csrf_token']

    def login(self):
        token = self.token()
        response = self.client.post('/login', data={'password': CONFIG['ADMIN_PASSWORD'], 'csrf_token': token})
        self.assertEqual(response.status_code, 302)
        return self.token()

    def service_headers(self):
        return {'Authorization': 'Bearer ' + TOKEN}

    def test_import_and_missing_config_fail_closed(self):
        with patch.dict(os.environ, {}, clear=True):
            app = dashboard.create_app({'TESTING': True, 'SECRET_KEY': None, 'ADMIN_PASSWORD': '', 'SERVICE_TOKEN': ''}, self.worker)
        client = app.test_client()
        self.assertEqual(client.get('/livez').status_code, 200)
        self.assertEqual(client.get('/api/status').status_code, 503)
        self.assertEqual(client.get('/readyz').status_code, 503)
        self.assertFalse(self.worker.calls)

    def test_localhost_is_not_an_authentication_bypass(self):
        for address in ('127.0.0.1', '::1', '::ffff:127.0.0.1', '192.0.2.10'):
            with self.subTest(address=address):
                response = self.client.get('/api/status', environ_overrides={'REMOTE_ADDR': address})
                self.assertEqual(response.status_code, 401)
        self.assertFalse(self.worker.calls)

    def test_anonymous_browser_redirects_to_login(self):
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith('/login'))

    def test_valid_service_bearer_authentication(self):
        response = self.client.get('/api/status', headers=self.service_headers())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.worker.calls[-1][0], 'status')

    def test_wrong_or_unicode_service_token_never_authorizes(self):
        for token in ('short', 'wrong-' + 'z' * 40, '雪' * 40):
            with self.subTest(token_type='unicode' if not token.isascii() else 'ascii'):
                response = self.client.get('/api/status', headers={'Authorization': 'Bearer ' + token})
                self.assertEqual(response.status_code, 401)
        self.assertFalse(self.worker.calls)

    def test_service_token_must_have_32_characters(self):
        app = dashboard.create_app({**CONFIG, 'SERVICE_TOKEN': 'short'}, self.worker)
        response = app.test_client().get('/api/status', headers={'Authorization': 'Bearer short'})
        self.assertEqual(response.status_code, 503)
        self.assertFalse(self.worker.calls)

    def test_login_requires_csrf(self):
        response = self.client.post('/login', data={'password': CONFIG['ADMIN_PASSWORD']})
        self.assertEqual(response.status_code, 403)
        self.assertFalse(self.worker.calls)

    def test_unicode_csrf_is_rejected_not_500(self):
        self.token()
        response = self.client.post('/login', data={'password': CONFIG['ADMIN_PASSWORD'], 'csrf_token': '雪' * 40})
        self.assertEqual(response.status_code, 403)

    def test_login_unicode_password_fails_not_500(self):
        response = self.client.post('/login', data={'password': '雪' * 40, 'csrf_token': self.token()})
        self.assertEqual(response.status_code, 401)

    def test_login_rotates_session_and_csrf(self):
        old = self.token()
        with self.client.session_transaction() as session:
            session['untrusted_old_field'] = 'must disappear'
        response = self.client.post('/login', data={'password': CONFIG['ADMIN_PASSWORD'], 'csrf_token': old})
        self.assertEqual(response.status_code, 302)
        with self.client.session_transaction() as session:
            self.assertTrue(session['logged_in'])
            self.assertTrue(session.permanent)
            self.assertNotIn('untrusted_old_field', session)
            self.assertNotEqual(session['csrf_token'], old)
        cookie = response.headers.get('Set-Cookie', '')
        self.assertIn('Secure', cookie)
        self.assertIn('HttpOnly', cookie)
        self.assertIn('SameSite=Strict', cookie)

    def test_login_rate_limit(self):
        token = self.token()
        for _ in range(5):
            response = self.client.post('/login', data={'password': 'incorrect-test-password', 'csrf_token': token})
            self.assertEqual(response.status_code, 401)
        response = self.client.post('/login', data={'password': CONFIG['ADMIN_PASSWORD'], 'csrf_token': token})
        self.assertEqual(response.status_code, 429)

    def test_every_browser_mutation_requires_csrf(self):
        self.login()
        paths = [('/api/settings', 'POST'), ('/api/users', 'POST'), ('/api/users/tester', 'DELETE'),
                 ('/api/proxies/generate', 'POST'), ('/api/proxies/reset', 'POST'), ('/api/proxies/1', 'DELETE'),
                 ('/api/proxies/1/rotate', 'POST'), ('/api/proxies/rotate', 'POST'), ('/api/proxies/delete-all', 'POST'),
                 ('/api/cleanup-ipv6', 'POST'), ('/api/proxy/start', 'POST'), ('/api/proxy/stop', 'POST'),
                 ('/api/proxy/restart', 'POST'), ('/api/proxy/speedtest', 'POST'), ('/api/proxy/speedtest-batch', 'POST'),
                 ('/api/proxy/auto-optimize', 'POST'), ('/api/telegram/test', 'POST'), ('/logout', 'POST')]
        for path, method in paths:
            with self.subTest(path=path):
                response = self.client.open(path, method=method, json={})
                self.assertEqual(response.status_code, 403)
        self.assertFalse(self.worker.calls)

    def test_browser_valid_csrf_passes_and_old_token_fails(self):
        old = self.token()
        token = self.login()
        response = self.client.post('/api/proxy/stop', headers={'X-CSRF-Token': old})
        self.assertEqual(response.status_code, 403)
        response = self.client.post('/api/proxy/stop', headers={'X-CSRF-Token': token})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.worker.calls[-1][0], 'stop')

    def test_service_authenticated_mutation_does_not_require_cookie_csrf(self):
        response = self.client.post('/api/proxy/stop', headers=self.service_headers())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.worker.calls[-1][0], 'stop')

    def test_logout_is_post_csrf_and_clears_session(self):
        token = self.login()
        self.assertEqual(self.client.get('/logout').status_code, 405)
        self.assertEqual(self.client.post('/logout', headers={'X-CSRF-Token': token}).status_code, 302)
        self.assertEqual(self.client.get('/api/status').status_code, 401)

    def test_secure_headers_and_no_store(self):
        response = self.client.get('/api/status', base_url='https://localhost', headers=self.service_headers())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')
        self.assertEqual(response.headers['X-Frame-Options'], 'DENY')
        self.assertEqual(response.headers['Referrer-Policy'], 'no-referrer')
        self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])
        self.assertIn('max-age=', response.headers['Strict-Transport-Security'])
        self.assertEqual(response.headers['Cache-Control'], 'no-store')

    def test_safe_worker_get_values_pass_through_without_passwords(self):
        headers = self.service_headers()
        settings = self.client.get('/api/settings', headers=headers).get_json()
        users = self.client.get('/api/users', headers=headers).get_json()
        self.assertNotIn('telegram_bot_token', settings)
        self.assertNotIn('password', str(users))
        self.assertTrue(settings['telegram_bot_token_configured'])

    def test_telegram_config_is_service_only_even_for_logged_in_admin(self):
        self.login()
        self.assertEqual(self.client.get('/api/internal/telegram-config').status_code, 403)
        response = self.client.get('/api/internal/telegram-config', headers=self.service_headers())
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.worker.calls[-1][0], 'telegram_config')

    def test_readiness_is_503_when_worker_fails_or_not_ready(self):
        self.worker.error = RpcError('offline', 503)
        self.assertEqual(self.client.get('/readyz').status_code, 503)
        self.worker.error = None
        self.worker.responses['health'] = {'ready': False, 'desired_state': 'running'}
        self.assertEqual(self.client.get('/readyz').status_code, 503)

    def test_readiness_allows_verified_intentionally_stopped_state(self):
        response = self.client.get('/readyz')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()['ready'])
        self.worker.responses['health'] = {'ready': True, 'desired_state': 'running', 'processes': {'expected': 2, 'running': 2}}
        self.assertEqual(self.client.get('/readyz').status_code, 200)

    def test_json_must_be_object_and_well_formed(self):
        headers = self.service_headers()
        for value in ([], None, 'string', True, 42):
            with self.subTest(value=value):
                response = self.client.post('/api/settings', data=__import__('json').dumps(value), content_type='application/json', headers=headers)
                self.assertEqual(response.status_code, 400)
        response = self.client.post('/api/settings', data='{broken', content_type='application/json', headers=headers)
        self.assertEqual(response.status_code, 400)
        self.assertFalse(self.worker.calls)

    def test_body_size_limit(self):
        response = self.client.post('/api/settings', json={'large': 'x' * 70000}, headers=self.service_headers())
        self.assertEqual(response.status_code, 413)
        self.assertFalse(self.worker.calls)

    def test_untrusted_host_rejected(self):
        response = self.client.get('/api/status', base_url='http://hostile.example', headers=self.service_headers())
        self.assertEqual(response.status_code, 400)
        self.assertFalse(self.worker.calls)

    def test_idempotency_key_and_reset_pass_to_explicit_worker_method(self):
        headers = {**self.service_headers(), 'Idempotency-Key': 'fixture-reset-001'}
        response = self.client.post('/api/proxies/reset', json={'count': 3, 'recreate': False}, headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.worker.calls[-1], ('generate', {'count': 3, 'recreate': True, '_idempotency_key': 'fixture-reset-001'}))

    def test_arbitrary_worker_method_not_exposed(self):
        response = self.client.post('/api/dispatch', json={'method': 'telegram_config'}, headers=self.service_headers())
        self.assertEqual(response.status_code, 404)
        self.assertFalse(self.worker.calls)

    def test_worker_validation_and_failure_status_preserved(self):
        self.worker.error = RpcError('field invalid', 400)
        response = self.client.post('/api/settings', json={}, headers=self.service_headers())
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['error'], 'field invalid')


if __name__ == '__main__':
    unittest.main()
