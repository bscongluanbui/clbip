"""Offline dead-man's-switch tests: no Telegram or heartbeat endpoint is called."""
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import requests

from heartbeat import HeartbeatMonitor, validate_heartbeat_url


URL = 'https://hc-ping.com/11111111-2222-3333-4444-555555555555'


class FakeStop:
    """Deterministic event: each wait advances an injected monotonic clock."""
    def __init__(self, advance, *, stop_on_wait=None):
        self.advance = advance
        self.stop_on_wait = stop_on_wait
        self.waits = []
        self.stopped = False

    def is_set(self):
        return self.stopped

    def set(self):
        self.stopped = True

    def wait(self, seconds):
        self.waits.append(seconds)
        if self.stop_on_wait is not None and len(self.waits) >= self.stop_on_wait:
            self.stopped = True
        else:
            self.advance(seconds)
        return self.stopped


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

    def stop(self, *, stop_on_wait=None):
        def advance(seconds):
            self.now += seconds
        return FakeStop(advance, stop_on_wait=stop_on_wait)

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
                self.assertEqual(monitor.emit_once(self.healthy, self.stop()), 'http_error')
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


    def test_transient_transport_retry_recovers_and_rechecks_health(self):
        monitor = self.monitor()
        self.session.post.side_effect = [requests.exceptions.Timeout(URL), self.response]
        provider = Mock(side_effect=self.healthy)
        stop = self.stop()
        self.assertEqual(monitor.emit_once(provider, stop), 'sent')
        self.assertEqual(provider.call_count, 2)
        self.assertEqual(stop.waits, [1.0])
        self.assertEqual(monitor.attempts, 2)
        self.assertEqual(monitor.retries, 1)
        self.assertEqual(monitor.successes, 1)
        self.assertEqual(monitor.last_http_status, 200)
        self.response.close.assert_called_once()

    def test_retryable_http_statuses_retry_but_close_each_response(self):
        for code in (408, 429, 500, 503, 599):
            with self.subTest(code=code):
                monitor = self.monitor()
                rejected = Mock(status_code=code)
                accepted = Mock(status_code=204)
                self.session.post.side_effect = [rejected, accepted]
                self.assertEqual(monitor.emit_once(self.healthy, self.stop()), 'sent')
                self.assertEqual(monitor.attempts, 2)
                self.assertEqual(monitor.retries, 1)
                self.assertEqual(monitor.last_http_status, 204)
                rejected.close.assert_called_once()
                accepted.close.assert_called_once()
                rejected.iter_content.assert_not_called()
                rejected.json.assert_not_called()

    def test_permanent_http_errors_and_redirects_never_retry(self):
        for code in (301, 302, 307, 400, 401, 403, 404, 409):
            with self.subTest(code=code):
                self.session.post.reset_mock()
                self.response.status_code = code
                monitor = self.monitor()
                stop = self.stop()
                self.assertEqual(monitor.emit_once(self.healthy, stop), 'http_error')
                self.assertEqual(self.session.post.call_count, 1)
                self.assertEqual(stop.waits, [])
                self.assertEqual(monitor.retries, 0)
                self.assertEqual(monitor.last_http_status, code)

    def test_transport_failure_exhausts_three_attempts_without_real_sleep(self):
        monitor = self.monitor()
        self.session.post.side_effect = requests.exceptions.ConnectionError(URL)
        stop = self.stop()
        self.assertEqual(monitor.emit_once(self.healthy, stop), 'transport_error')
        self.assertEqual(self.session.post.call_count, 3)
        self.assertEqual(stop.waits, [1.0, 2.0])
        self.assertEqual(monitor.retries, 2)
        self.assertEqual(monitor.successes, 0)
        self.assertIsNone(monitor.last_http_status)

    def test_unhealthy_or_stale_before_retry_suppresses_second_post(self):
        for reason in ('unhealthy', 'stale', 'health_unavailable'):
            with self.subTest(reason=reason):
                self.session.post.reset_mock()
                monitor = self.monitor()
                self.session.post.side_effect = requests.exceptions.Timeout(URL)
                states = [self.healthy(),
                          {'healthy': False} if reason == 'unhealthy' else
                          {'healthy': True, 'last_reconcile_monotonic': self.now - 400}
                          if reason == 'stale' else {'healthy': True}]
                provider = Mock(side_effect=states)
                self.assertEqual(monitor.emit_once(provider, self.stop()), reason)
                self.assertEqual(self.session.post.call_count, 1)
                self.assertEqual(provider.call_count, 2)
                self.assertEqual(monitor.retries, 0)

    def test_stop_during_backoff_suppresses_retry(self):
        monitor = self.monitor()
        self.session.post.side_effect = requests.exceptions.Timeout(URL)
        stop = self.stop(stop_on_wait=1)
        self.assertEqual(monitor.emit_once(self.healthy, stop), 'stopped')
        self.assertEqual(self.session.post.call_count, 1)
        self.assertEqual(monitor.retries, 0)
        self.assertEqual(stop.waits, [1.0])

    def test_cycle_budget_caps_configured_timeout_and_skips_late_retry(self):
        monitor = self.monitor({'HEARTBEAT_TIMEOUT': '30'})
        timeouts = []
        def post(*args, **kwargs):
            timeout = kwargs['timeout']
            timeouts.append(timeout)
            self.now += timeout * 2
            raise requests.exceptions.Timeout(URL)
        self.session.post.side_effect = post
        stop = self.stop()
        self.assertEqual(monitor.emit_once(self.healthy, stop), 'transport_error')
        self.assertEqual(timeouts, [12.5])
        self.assertEqual(stop.waits, [])
        self.assertEqual(monitor.attempts, 1)
        self.assertEqual(monitor.status()['cycle_budget_seconds'], 25.0)

    def test_remaining_cycle_budget_reduces_final_request_timeout(self):
        monitor = self.monitor()
        timeouts = []
        def post(*args, **kwargs):
            timeout = kwargs['timeout']
            timeouts.append(timeout)
            self.now += timeout * 2
            raise requests.exceptions.Timeout(URL)
        self.session.post.side_effect = post
        stop = self.stop()
        self.assertEqual(monitor.emit_once(self.healthy, stop), 'transport_error')
        self.assertEqual(timeouts, [5.0, 5.0, 1.0])
        self.assertEqual(stop.waits, [1.0, 2.0])
        self.assertEqual(self.now, 1025.0)

    def test_fixed_monotonic_cadence_does_not_add_request_duration(self):
        monitor = self.monitor()
        starts = []
        stop = self.stop()
        def post(*args, **kwargs):
            starts.append(self.now)
            self.now += 8.0
            if len(starts) == 3:
                stop.set()
            return self.response
        self.session.post.side_effect = post
        monitor.run(stop, self.healthy)
        self.assertEqual(starts, [1000.0, 1060.0, 1120.0])
        self.assertEqual(stop.waits, [52.0, 52.0])
        self.assertEqual(monitor.cycles, 3)
        self.session.close.assert_called_once()

    def test_long_overrun_skips_missed_ticks_without_tight_loop(self):
        monitor = self.monitor()
        starts = []
        stop = self.stop()
        def post(*args, **kwargs):
            starts.append(self.now)
            self.now += 185.0
            if len(starts) == 2:
                stop.set()
            return self.response
        self.session.post.side_effect = post
        monitor.run(stop, self.healthy)
        self.assertEqual(starts, [1000.0, 1240.0])
        self.assertEqual(stop.waits, [55.0])
        self.assertEqual(monitor.attempts, 2)

    def test_logs_show_transitions_and_http_status_without_secrets(self):
        token = 'VERY_SECRET_TOKEN_' + 'x' * 32
        monitor = self.monitor({'HEARTBEAT_TOKEN': token})
        self.assertEqual(monitor.emit_once(self.healthy, self.stop()), 'sent')
        self.assertEqual(monitor.emit_once(self.healthy, self.stop()), 'sent')
        self.assertEqual(self.logger.info.call_count, 1)
        self.response.status_code = 401
        self.assertEqual(monitor.emit_once(self.healthy, self.stop()), 'http_error')
        self.assertEqual(monitor.emit_once(self.healthy, self.stop()), 'http_error')
        self.assertEqual(self.logger.info.call_count, 2)
        self.session.post.side_effect = requests.exceptions.Timeout(URL + token)
        self.assertEqual(monitor.emit_once(self.healthy, self.stop()), 'transport_error')
        log = str(self.logger.mock_calls)
        self.assertIn('http_status=%s', log)
        self.assertIn('401', log)
        self.assertNotIn(URL, log)
        self.assertNotIn(token, log)
        self.assertNotIn(URL, str(monitor.status()))
        self.assertNotIn(token, str(monitor.status()))


    def test_slow_snapshot_budget_expiry_does_not_report_previous_success(self):
        monitor = self.monitor()
        self.assertEqual(monitor.emit_once(self.healthy, self.stop()), 'sent')
        self.session.post.reset_mock()
        def provider():
            self.now += 26.0
            return self.healthy()
        self.assertEqual(monitor.emit_once(provider, self.stop()), 'cycle_budget_exhausted')
        self.session.post.assert_not_called()
        self.assertEqual(monitor.successes, 1)


if __name__ == '__main__':
    unittest.main()
