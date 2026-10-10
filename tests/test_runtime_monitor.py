"""Read-only dashboard monitoring, fake HTTP only; no local/Internet requests."""
import threading
import unittest
from unittest.mock import Mock, patch

import requests
from runtime_monitor import RuntimeMonitor


class RuntimeMonitorTests(unittest.TestCase):
    def setUp(self):
        self.service = Mock()
        self.session = Mock()
        self.response = Mock(status_code=200)
        self.response.iter_content.return_value = [b'{"alive":true}']
        self.session.get.return_value = self.response

    def monitor(self, env=None):
        return RuntimeMonitor(self.service, env or {}, self.session)

    def test_constructor_no_network_initial_healthy_and_default_url(self):
        monitor = self.monitor()
        self.assertTrue(monitor.healthy)
        self.assertTrue(monitor.enabled)
        self.assertFalse(self.session.trust_env)
        self.assertIsNone(self.session.auth)
        self.session.get.assert_not_called()
        self.service._report_failure.assert_not_called()
        self.assertEqual(monitor._url, 'http://127.0.0.1:7070/livez')

    def test_alive_true_verified_empty_credentials_and_closed_response(self):
        monitor = self.monitor()
        self.assertEqual(monitor.probe_once(), 'alive')
        self.session.get.assert_called_once_with('http://127.0.0.1:7070/livez',
            timeout=(2, 3), allow_redirects=False, stream=True,
            headers={'User-Agent': 'clbip-runtime-monitor/1.0'})
        self.assertEqual(self.session.cookies.clear.call_count, 2)
        self.response.close.assert_called_once()
        self.assertTrue(monitor.healthy)
        self.service._report_resolved.assert_called_once_with('runtime.dashboard',
            'Dashboard đã phục hồi', 'Kiểm tra /livez thành công; alive=true.')
        self.service._report_failure.assert_not_called()

    def test_bind_literal_used_and_wildcards_rewritten_ipv4_ipv6(self):
        for bind, host in [('0.0.0.0', '127.0.0.1'), ('192.168.1.3', '192.168.1.3'),
                           ('::', '[::1]'), ('::1', '[::1]'), ('2001:db8::3', '[2001:db8::3]')]:
            with self.subTest(bind=bind):
                monitor = self.monitor({'GUI_BIND': bind, 'GUI_PORT': '8080'})
                self.assertEqual(monitor._url, f'http://{host}:8080/livez')

    def test_disabled_ignores_unused_bad_config_no_http_session(self):
        with patch('runtime_monitor.requests.Session', side_effect=AssertionError('No session')):
            monitor = RuntimeMonitor(self.service, {'DASHBOARD_MONITOR_ENABLED': '0',
                                     'GUI_BIND': 'secret', 'GUI_PORT': 'bad'})
        self.assertFalse(monitor.enabled)
        self.assertTrue(monitor.healthy)
        self.assertEqual(monitor.probe_once(), 'disabled')
        stop = Mock()
        monitor.run(stop)
        stop.wait.assert_called_once_with()
        self.service._report_failure.assert_not_called()

    def test_bad_config_unhealthy_generic_alert_no_value_leak(self):
        secret = 'https://user:password@secret.example/token'
        for env in ({'GUI_BIND': secret}, {'GUI_BIND': 'localhost'},
                    {'GUI_BIND': '224.0.0.1'}, {'GUI_BIND': 'fe80::1%eth0'},
                    {'GUI_PORT': '0'}, {'GUI_PORT': '65536'}, {'GUI_PORT': '7070.0'},
                    {'GUI_PORT': secret}, {'DASHBOARD_MONITOR_ENABLED': secret}):
            with self.subTest(env=env):
                monitor = self.monitor(env)
                self.assertFalse(monitor.healthy)
                self.assertEqual(monitor.probe_once(), 'config_error')
                self.assertNotIn(secret, str(monitor.status()))
                self.assertNotIn(secret, str(self.service._report_failure.call_args))
        self.session.get.assert_not_called()

    def test_runtime_http_failures_and_recovery(self):
        monitor = self.monitor()
        for code in (301, 302, 401, 404, 503, 500):
            self.response.status_code = code
            self.assertEqual(monitor.probe_once(), 'http_error')
            self.assertFalse(monitor.healthy)
            self.assertEqual(self.service._report_failure.call_args.args[0], 'runtime.dashboard')
            self.assertIn(str(code), self.service._report_failure.call_args.args[2])
        self.response.status_code = 200
        self.assertEqual(monitor.probe_once(), 'alive')
        self.assertTrue(monitor.healthy)
        self.assertEqual(self.response.close.call_count, 7)

    def test_false_truthy_missing_or_non_dict_alive_not_healthy(self):
        monitor = self.monitor()
        for body in (b'{"alive":false}', b'{"alive":1}', b'{"alive":"true"}', b'{}', b'[]', b'null'):
            self.response.iter_content.return_value = [body]
            self.assertEqual(monitor.probe_once(), 'not_alive')
            self.assertFalse(monitor.healthy)

    def test_invalid_json_utf8_and_large_response_bounded_no_body_alerts(self):
        monitor = self.monitor()
        for body in ([b'secret invalid body'], [b'\xff'], [b'x' * 4097], [b'x' * 2048, b'x' * 2049]):
            self.response.iter_content.return_value = body
            self.assertEqual(monitor.probe_once(), 'invalid_response')
            self.assertFalse(monitor.healthy)
            self.assertNotIn('secret invalid body', str(self.service._report_failure.call_args))
        self.response.json.assert_not_called()

    def test_transport_error_types_redacted_not_exception_url(self):
        monitor = self.monitor()
        secret = 'https://user:secret@host/token'
        for error, result in ((requests.Timeout(secret), 'timeout'),
                              (requests.ConnectionError(secret), 'connection_error'),
                              (RuntimeError(secret), 'probe_error')):
            self.session.get.side_effect = error
            self.assertEqual(monitor.probe_once(), result)
            self.assertFalse(monitor.healthy)
            self.assertNotIn(secret, str(self.service._report_failure.call_args))
            self.assertNotIn(secret, str(monitor.status()))

    def test_enqueue_failures_contained_monitor_continues_to_recovery(self):
        monitor = self.monitor()
        self.service._report_failure.side_effect = RuntimeError('secret')
        self.service._report_resolved.side_effect = RuntimeError('secret')
        self.response.status_code = 503
        self.assertEqual(monitor.probe_once(), 'http_error')
        self.assertFalse(monitor.healthy)
        self.response.status_code = 200
        self.assertEqual(monitor.probe_once(), 'alive')
        self.assertTrue(monitor.healthy)

    def test_shutdown_before_grace_no_probe_session_closed(self):
        monitor = self.monitor()
        stop = threading.Event()
        stop.set()
        monitor.run(stop)
        self.session.get.assert_not_called()
        self.session.close.assert_called_once()

    def test_first_probe_after_grace_and_periodic_wait_interruptible(self):
        monitor = self.monitor()
        stop = Mock()
        stop.wait.side_effect = [False, True]
        stop.is_set.return_value = False
        monitor.run(stop)
        self.assertEqual(stop.wait.call_args_list[0].args, (30,))
        self.assertEqual(stop.wait.call_args_list[1].args, (30,))
        self.session.get.assert_called_once()
        self.session.close.assert_called_once()

    def test_config_failure_run_reports_once_then_waits_for_stop(self):
        monitor = self.monitor({'GUI_PORT': 'secret'})
        stop = Mock()
        monitor.run(stop)
        self.service._report_failure.assert_called_once()
        stop.wait.assert_called_once_with()
        self.session.get.assert_not_called()

    def test_stop_during_stream_no_false_recovery(self):
        monitor = self.monitor()
        stop = threading.Event()
        def chunks(chunk_size):
            stop.set()
            yield b'{"alive":true}'
        self.response.iter_content.side_effect = chunks
        self.assertEqual(monitor.probe_once(stop), 'stopped')
        self.service._report_resolved.assert_not_called()
        self.response.close.assert_called_once()

    def test_inflight_http_does_not_reuse_cached_success_health(self):
        monitor = self.monitor()
        self.assertTrue(monitor.healthy)
        def get(*args, **kwargs):
            self.assertFalse(monitor.healthy)
            return self.response
        self.session.get.side_effect = get
        self.assertEqual(monitor.probe_once(), 'alive')
        self.assertTrue(monitor.healthy)

    def test_slow_response_does_not_certify_health(self):
        monitor = self.monitor()
        with patch('runtime_monitor.time.monotonic', side_effect=[100.0, 109.0]):
            self.assertEqual(monitor.probe_once(), 'timeout')
        self.assertFalse(monitor.healthy)
        self.service._report_resolved.assert_not_called()
        self.response.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
