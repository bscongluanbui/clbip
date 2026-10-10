"""Offline dead-man's-switch tests: no Telegram or heartbeat endpoint is called."""
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from heartbeat import HeartbeatMonitor, validate_heartbeat_url


URL = 'https://hc-ping.com/11111111-2222-3333-4444-555555555555'


class HeartbeatTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.session = Mock()
        self.response = Mock(status_code=200)
        self.session.post.return_value = self.response
        self.logger = Mock()

    def monitor(self, env=None):
        return HeartbeatMonitor({'HEARTBEAT_URL': URL, **(env or {})},
                                session=self.session, monotonic=lambda: self.now,
                                logger=self.logger)

    def healthy(self):
        return {'healthy': True, 'last_reconcile_monotonic': self.now}

    def test_disabled_without_url_has_no_network_or_session(self):
        with patch('heartbeat.requests.Session', side_effect=AssertionError('No network session')):
            monitor = HeartbeatMonitor({'HEARTBEAT_INTERVAL': 'bad'})
            self.assertFalse(monitor.enabled)
            self.assertEqual(monitor.emit_once(self.healthy), 'disabled')
            monitor.run(threading.Event(), self.healthy)

    def test_healthy_empty_post_and_secret_free_status(self):
        monitor = self.monitor()
        self.assertFalse(self.session.trust_env)
        self.assertEqual(monitor.emit_once(self.healthy), 'sent')
        self.session.post.assert_called_once_with(URL, data=b'', timeout=5.0,
            allow_redirects=False, stream=True, headers={'User-Agent': 'clbip-heartbeat/1.0'})
        self.response.close.assert_called_once()
        self.assertEqual(monitor.status()['successes'], 1)
        self.assertEqual(monitor.status()['last_success_monotonic'], self.now)
        self.assertNotIn(URL, str(monitor.status()))

    def test_unhealthy_stale_and_cached_success_do_not_post(self):
        monitor = self.monitor()
        self.assertEqual(monitor.emit_once(self.healthy), 'sent')
        self.session.post.reset_mock()
        for state, result in [({'healthy': False, 'last_reconcile_monotonic': self.now}, 'unhealthy'),
                              ({'healthy': True, 'last_reconcile_monotonic': self.now - 331}, 'stale')]:
            self.assertEqual(monitor.emit_once(lambda state=state: state), result)
        self.session.post.assert_not_called()
        self.assertEqual(monitor.successes, 1)

    def test_invalid_observations_never_post(self):
        monitor = self.monitor()
        for state in (None, {}, {'healthy': 'true'}, {'healthy': True},
                      {'healthy': True, 'last_reconcile_monotonic': True},
                      {'healthy': True, 'last_reconcile_monotonic': float('nan')},
                      {'healthy': True, 'last_reconcile_monotonic': float('inf')},
                      {'healthy': True, 'last_reconcile_monotonic': -1},
                      {'healthy': True, 'last_reconcile_monotonic': self.now + 1}):
            monitor.emit_once(lambda state=state: state)
        self.session.post.assert_not_called()

    def test_provider_exception_is_redacted_and_not_healthy(self):
        monitor = self.monitor()
        self.assertEqual(monitor.emit_once(Mock(side_effect=RuntimeError(URL))), 'health_unavailable')
        self.session.post.assert_not_called()
        self.assertNotIn(URL, str(monitor.status()))
        self.logger.assert_not_called()

    def test_timeout_error_is_redacted_no_reconcile_retry_or_cached_success(self):
        monitor = self.monitor()
        self.session.post.side_effect = RuntimeError(URL)
        self.assertEqual(monitor.emit_once(self.healthy), 'transport_error')
        self.assertEqual(monitor.attempts, 1)
        self.assertEqual(monitor.successes, 0)
        self.assertIsNone(monitor.last_success_monotonic)
        self.assertNotIn(URL, str(monitor.status()))
        self.logger.assert_not_called()

    def test_non_success_and_redirect_are_not_success_body_never_read(self):
        for code in (301, 302, 307, 400, 429, 500):
            with self.subTest(code=code):
                self.response.status_code = code
                monitor = self.monitor()
                self.assertEqual(monitor.emit_once(self.healthy), 'http_error')
                self.assertEqual(monitor.successes, 0)
        self.response.json.assert_not_called()
        self.response.iter_content.assert_not_called()

    def test_numbers_and_stale_boundary(self):
        monitor = self.monitor({'HEARTBEAT_INTERVAL': '180', 'HEARTBEAT_TIMEOUT': '3'})
        self.assertEqual(monitor.interval, 180)
        self.assertEqual(monitor.stale_after, 360)
        self.assertEqual(monitor.emit_once(lambda: {'healthy': True,
                          'last_reconcile_monotonic': self.now - 360}), 'sent')
        self.now += .1
        self.assertEqual(monitor.emit_once(lambda: {'healthy': True,
                          'last_reconcile_monotonic': 640}), 'stale')

    def test_bad_config_disabled_no_secret_in_errors(self):
        for env in ({'HEARTBEAT_URL': 'http://secret-host/secret-token'},
                    {'HEARTBEAT_URL': 'https://user:secret@host/token'},
                    {'HEARTBEAT_INTERVAL': URL}, {'HEARTBEAT_INTERVAL': '9'},
                    {'HEARTBEAT_TIMEOUT': 'inf'}, {'HEARTBEAT_TIMEOUT': '31'},
                    {'HEARTBEAT_STALE_AFTER': '10'}):
            with self.subTest(env=env):
                monitor = self.monitor(env)
                self.assertFalse(monitor.enabled)
                self.assertEqual(monitor.last_result, 'config_error')
                self.assertNotIn('secret', str(monitor.status()))
                self.assertNotIn(URL, str(monitor.status()))
        self.session.post.assert_not_called()

    def test_file_secret_precedence_and_newline(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'heartbeat_url'
            path.write_text(URL + '\n', encoding='utf-8')
            monitor = self.monitor({'HEARTBEAT_URL': 'http://bad/token', 'HEARTBEAT_URL_FILE': str(path)})
            self.assertTrue(monitor.enabled)
            self.assertEqual(monitor.emit_once(self.healthy), 'sent')
            self.assertNotIn(str(path), str(monitor.status()))

    def test_missing_or_large_file_disables_without_leaking_path_or_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'secret-file'
            for content in (None, 'https://host/' + 'x' * 2049, 'bad\udcff'):
                if content is not None:
                    path.write_bytes(content.encode('utf-8', errors='surrogatepass'))
                monitor = self.monitor({'HEARTBEAT_URL_FILE': str(path)})
                self.assertFalse(monitor.enabled)
                self.assertNotIn(str(path), str(monitor.status()))
        self.session.post.assert_not_called()

    def test_accept_https_explicit_self_hosted_and_strip_trailing_slash(self):
        for url in (URL, 'https://monitor.example.org:8443/ping/project/key/',
                    'https://192.168.1.20/ping/token', 'https://[2001:db8::1]/ping/key'):
            self.assertEqual(validate_heartbeat_url(url), url.rstrip('/'))

    def test_ambiguous_urls_rejected_with_generic_error(self):
        for url in ('http://host/token', 'https://host/token?x=secret',
                    'https://host/token#secret', 'https://host/token/fail',
                    'https://host/token/start', 'https://host/../token',
                    'https://host/%2e%2e/token', 'https://host/%2ftoken',
                    'https://host//token', 'https://user@host/token',
                    'https://host/token\n', 'https://host\\evil/token',
                    'https://host:99999/token', 'https://-host/token', 'https://host/',
                    'https://host/漢字', 'https://host./token'):
            with self.subTest(url=url):
                with self.assertRaisesRegex(ValueError, '^HEARTBEAT_URL invalid$'):
                    validate_heartbeat_url(url)

    def test_run_is_interruptible_and_does_not_send_after_stop(self):
        monitor = self.monitor()
        stop = threading.Event()
        calls = []
        def provider():
            calls.append(True)
            return self.healthy()
        def post(*args, **kwargs):
            stop.set()
            return self.response
        self.session.post.side_effect = post
        monitor.run(stop, provider)
        self.assertEqual(len(calls), 1)
        self.session.close.assert_called_once()
        self.session.post.reset_mock()
        monitor.run(stop, provider)
        self.session.post.assert_not_called()

    def test_health_recovery_resumes_beats_using_new_observation(self):
        monitor = self.monitor()
        self.assertEqual(monitor.emit_once(lambda: {'healthy': False,
                          'last_reconcile_monotonic': self.now}), 'unhealthy')
        self.now += 60
        self.assertEqual(monitor.emit_once(self.healthy), 'sent')
        self.assertEqual(monitor.successes, 1)

    def test_vps_token_header_secret_file_and_redaction(self):
        token = 'x' * 48
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'token'
            path.write_text(token + '\n', encoding='utf-8')
            monitor = self.monitor({'HEARTBEAT_TOKEN_FILE': str(path)})
            self.assertEqual(monitor.emit_once(self.healthy), 'sent')
            self.assertEqual(self.session.post.call_args.kwargs['headers']['Authorization'], 'Bearer ' + token)
            self.assertNotIn(token, str(monitor.status()))
            self.assertNotIn(str(path), str(monitor.status()))

    def test_http_only_explicit_tailscale_overlay(self):
        for url in ('http://100.64.0.1:8088/heartbeat', 'http://100.127.65.53:8088/heartbeat',
                    'http://monitor.tail-example.ts.net:8088/heartbeat',
                    'http://[fd7a:115c:a1e0::1]:8088/heartbeat'):
            with self.subTest(url=url):
                self.assertFalse(self.monitor({'HEARTBEAT_URL': url}).enabled)
                self.assertTrue(self.monitor({'HEARTBEAT_URL': url, 'HEARTBEAT_ALLOW_HTTP': '1'}).enabled)
        for url in ('http://monitor.example.com/heartbeat', 'http://192.168.1.3/heartbeat',
                    'http://127.0.0.1/heartbeat', 'http://100.128.0.1/heartbeat'):
            self.assertFalse(self.monitor({'HEARTBEAT_URL': url, 'HEARTBEAT_ALLOW_HTTP': '1'}).enabled)

    def test_invalid_token_disables_without_token_leak(self):
        for token in ('short', 'x' * 513, 'x' * 32 + '\nvalue', '漢字' * 32):
            monitor = self.monitor({'HEARTBEAT_TOKEN': token})
            self.assertFalse(monitor.enabled)
            self.assertEqual(monitor.config_error, 'HEARTBEAT_TOKEN invalid')
            self.assertNotIn(token, str(monitor.status()))

    def test_shutdown_during_health_snapshot_suppresses_new_post(self):
        monitor = self.monitor()
        stop = threading.Event()
        def provider():
            stop.set()
            return self.healthy()
        monitor.run(stop, provider)
        self.session.post.assert_not_called()
        self.assertEqual(monitor.last_result, 'stopped')
        self.assertEqual(monitor.attempts, 0)


if __name__ == '__main__':
    unittest.main()
