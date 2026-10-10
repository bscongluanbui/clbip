"""Offline tests for the standalone, read-only host heartbeat agent."""
from contextlib import redirect_stdout
import io
from pathlib import Path
import signal
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

from heartbeat import HeartbeatMonitor
from scripts.host_heartbeat import DashboardProbe, main, validate_dashboard_url


ENV = {'HEARTBEAT_URL': 'http://100.76.59.88:8088/heartbeat',
       'HEARTBEAT_ALLOW_HTTP': '1', 'HEARTBEAT_TOKEN': 'x' * 48}
LOCAL = 'http://127.0.0.1:7070/readyz'
LIVENESS = 'http://127.0.0.1:7070/heartbeatz'
LIVE_BODY = b'{"alive":true,"worker_alive":true,"progress_fresh":true}'


class HostHeartbeatTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.session = Mock()
        self.response = Mock(status_code=200, headers={})
        self.response.iter_content.return_value = [b'{"ready":true}']
        self.session.get.return_value = self.response
        self.logger = Mock()
        self.probes = []

    def tearDown(self):
        for probe in self.probes:
            probe.close()

    def probe(self, env=None, **kwargs):
        probe = DashboardProbe({'LOCAL_DASHBOARD_URL': LOCAL} if env is None else env, session=self.session,
                               monotonic=lambda: self.now, logger=self.logger, **kwargs)
        self.probes.append(probe)
        return probe

    def test_default_constructor_makes_no_http(self):
        with patch('scripts.host_heartbeat.requests.Session') as session_factory:
            probe = DashboardProbe({})
            self.probes.append(probe)
            session_factory.assert_not_called()
        self.session.get.assert_not_called()

    def test_healthy_response_is_fresh_read_only_and_closed(self):
        probe = self.probe()
        self.assertFalse(self.session.trust_env)
        self.assertEqual(probe.snapshot(), {'healthy': True, 'last_reconcile_monotonic': self.now})
        self.session.get.assert_called_once_with(LOCAL, timeout=(2, 5),
            allow_redirects=False, stream=True,
            headers={'Accept': 'application/json', 'User-Agent': 'clbip-host-heartbeat/1.0'})
        self.response.iter_content.assert_called_once_with(chunk_size=1024)
        self.response.close.assert_called_once()
        self.session.post.assert_not_called()
        self.assertEqual(probe.last_result, 'ready')

    def test_each_positive_response_advances_stamp_not_cached_success(self):
        probe = self.probe()
        self.assertEqual(probe.snapshot()['last_reconcile_monotonic'], 1000)
        self.now += 60
        self.assertEqual(probe.snapshot()['last_reconcile_monotonic'], 1060)
        self.response.status_code = 503
        self.assertEqual(probe.snapshot(), {'healthy': False, 'last_reconcile_monotonic': 0.0})
        self.assertEqual(self.session.get.call_count, 3)

    def test_only_literal_ready_true_is_ready(self):
        probe = self.probe()
        for payload in (b'{}', b'[]', b'true', b'null', b'{"ready":false}',
                        b'{"ready":1}', b'{"ready":"true"}', b'{"success":true}'):
            with self.subTest(payload=payload):
                self.response.iter_content.return_value = [payload]
                self.assertFalse(probe.snapshot()['healthy'])
                self.assertEqual(probe.last_result, 'not_ready')

    def test_invalid_json_utf8_and_nonstandard_numbers_fail_closed(self):
        probe = self.probe()
        for payload in (b'', b'not json', b'\xff', b'{"ready":true',
                        b'{"ready":true,"value":NaN}', b'{"ready":true,"value":Infinity}'):
            with self.subTest(payload=payload):
                self.response.iter_content.return_value = [payload]
                self.assertFalse(probe.snapshot()['healthy'])
                self.assertEqual(probe.last_result, 'probe_failed')
        self.assertEqual(self.response.close.call_count, 6)

    def test_non_success_and_redirect_do_not_read_body_or_follow(self):
        probe = self.probe()
        for code in (201, 204, 301, 302, 307, 401, 403, 429, 500, 503):
            with self.subTest(code=code):
                self.response.status_code = code
                self.assertFalse(probe.snapshot()['healthy'])
                self.assertEqual(probe.last_result, 'http_error')
        self.response.iter_content.assert_not_called()
        self.assertEqual(self.response.close.call_count, 10)

    def test_transport_errors_do_not_reuse_healthy_or_leak_values(self):
        probe = self.probe()
        self.assertTrue(probe.snapshot()['healthy'])
        self.session.get.side_effect = RuntimeError('SECRET ' + LOCAL)
        self.assertFalse(probe.snapshot()['healthy'])
        self.assertEqual(probe.last_result, 'probe_failed')
        self.assertNotIn('SECRET', str(self.logger.mock_calls))
        self.assertNotIn(LOCAL, str(self.logger.mock_calls))

    def test_streaming_failure_always_closes_response(self):
        probe = self.probe()
        def chunks():
            yield b'{"ready":'
            raise TimeoutError('Secret URL')
        self.response.iter_content.return_value = chunks()
        self.assertFalse(probe.snapshot()['healthy'])
        self.response.close.assert_called_once()

    def test_advertised_oversize_or_invalid_length_not_read(self):
        probe = self.probe()
        for value in ('4097', '99999999999', '-1', 'garbage', ''):
            with self.subTest(value=value):
                self.response.headers = {'Content-Length': value}
                self.assertFalse(probe.snapshot()['healthy'])
                self.assertEqual(probe.last_result, 'invalid_body')
        self.response.iter_content.assert_not_called()

    def test_body_limit_accepts_exact_4096_and_rejects_one_more(self):
        probe = self.probe()
        payload = b'{"ready":true}'
        self.response.iter_content.return_value = [payload, b' ' * (4096 - len(payload))]
        self.assertTrue(probe.snapshot()['healthy'])
        self.response.iter_content.return_value = [payload, b' ' * (4097 - len(payload))]
        self.assertFalse(probe.snapshot()['healthy'])
        self.assertEqual(probe.last_result, 'invalid_body')

    def test_empty_chunks_are_ignored_and_chunks_must_be_bytes(self):
        probe = self.probe()
        self.response.iter_content.return_value = [b'', b'{"ready":', b'', b'true}']
        self.assertTrue(probe.snapshot()['healthy'])
        self.response.iter_content.return_value = ['{"ready":true}']
        self.assertFalse(probe.snapshot()['healthy'])
        self.assertEqual(probe.last_result, 'invalid_body')

    def test_body_deadline_rejects_late_success_and_closes(self):
        probe = self.probe()
        def chunks():
            self.now += 8
            yield b'{"ready":true}'
        self.response.iter_content.return_value = chunks()
        self.assertFalse(probe.snapshot()['healthy'])
        self.assertEqual(probe.last_result, 'timeout')
        self.response.close.assert_called_once()

    def test_slow_trickle_without_chunks_is_bounded_one_request_and_late_discarded(self):
        release = threading.Event()
        started = threading.Event()
        probe = self.probe(deadline=.03)
        def slow_get(*args, **kwargs):
            started.set()
            release.wait(2)
            return self.response
        self.session.get.side_effect = slow_get
        try:
            began = time.monotonic()
            self.assertFalse(probe.snapshot()['healthy'])
            self.assertLess(time.monotonic() - began, .5)
            self.assertTrue(started.is_set())
            self.assertEqual(probe.last_result, 'timeout')
            self.assertFalse(probe.snapshot()['healthy'])
            self.assertEqual(probe.last_result, 'probe_in_flight')
            self.session.get.assert_called_once()
            release.set()
            probe._thread.join(1)
            # The old ready response cannot be used as the next observation.
            self.session.get.side_effect = TimeoutError('fresh request fails')
            self.assertFalse(probe.snapshot()['healthy'])
            self.assertEqual(self.session.get.call_count, 2)
        finally:
            release.set()
            if probe._thread is not None:
                probe._thread.join(1)

    def test_close_suppresses_new_requests(self):
        probe = self.probe()
        probe.close()
        self.assertFalse(probe.snapshot()['healthy'])
        self.assertEqual(probe.last_result, 'stopped')
        self.session.get.assert_not_called()

    def test_close_during_request_suppresses_success(self):
        probe = self.probe()
        self.session.get.side_effect = lambda *a, **kw: (probe.close() or self.response)
        self.assertFalse(probe.snapshot()['healthy'])
        self.assertEqual(probe.last_result, 'stopped')
        self.response.close.assert_called_once()

    def test_logs_only_on_state_change_and_recovery(self):
        probe = self.probe()
        self.response.status_code = 503
        probe.snapshot()
        probe.snapshot()
        self.logger.warning.assert_called_once_with('Dashboard %s probe failed: %s', 'readiness', 'http_error')
        self.response.status_code = 200
        probe.snapshot()
        self.logger.info.assert_called_once_with('Dashboard %s recovered', 'readiness')

    def test_local_url_validation_accepts_only_explicit_local_ip(self):
        for value in (LOCAL, LIVENESS, 'http://192.168.1.3:7070/heartbeatz',
                      'http://[::1]:7070/heartbeatz', 'http://127.1.2.3/readyz', 'http://192.168.1.3:7070/readyz',
                      'http://10.0.0.1/readyz', 'http://172.16.0.1/readyz',
                      'http://172.31.255.255:65535/readyz', 'http://[::1]:7070/readyz',
                      'http://[fc00::1]/readyz', 'http://[fd7a:115c:a1e0::1]/readyz'):
            with self.subTest(value=value):
                self.assertEqual(validate_dashboard_url(value), value)

    def test_local_url_validation_rejects_dns_public_cgnat_linklocal_and_ambiguity(self):
        for value in ('https://127.0.0.1/readyz', 'http://localhost/readyz',
                      'http://100.76.59.88/readyz', 'http://8.8.8.8/readyz',
                      'http://169.254.169.254/readyz', 'http://172.32.0.1/readyz',
                      'http://[fe80::1]/readyz', 'http://[2001:db8::1]/readyz',
                      'http://[::ffff:127.0.0.1]/readyz', 'http://0.0.0.0/readyz',
                      'http://user:pass@127.0.0.1/readyz', 'http://127.0.0.1/api/settings',
                      'http://127.0.0.1/livez', LIVENESS + '/', LIVENESS + '?secret=value',
                      LIVENESS + '#secret', 'http://localhost/heartbeatz',
                      'http://127.0.0.1/%68eartbeatz',
                      LOCAL + '/', LOCAL + '?', LOCAL + '#', LOCAL + '?secret=value',
                      LOCAL + '#secret', LOCAL + '\n', ' ' + LOCAL,
                      'http://127.0.0.1:/readyz', 'http://127.0.0.1:0/readyz',
                      'http://127.0.0.1:65536/readyz', 'http://127.0.0.1/%72eadyz',
                      'http://[::1%25eth0]/readyz', 'http://127.0.0.1\\host/readyz',
                      'http://2130706433/readyz', 'http://127.000.000.001/readyz', '', None):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, '^LOCAL_DASHBOARD_URL invalid$'):
                    validate_dashboard_url(value)

    def test_monitor_never_posts_after_failed_probe_or_cached_success(self):
        probe = self.probe()
        beat_session = Mock()
        beat_session.post.return_value = Mock(status_code=204)
        monitor = HeartbeatMonitor(ENV, session=beat_session, monotonic=lambda: self.now)
        self.assertEqual(monitor.emit_once(probe.snapshot), 'sent')
        self.response.status_code = 503
        self.assertEqual(monitor.emit_once(probe.snapshot), 'unhealthy')
        self.assertEqual(beat_session.post.call_count, 1)
        self.now += 60
        self.response.status_code = 200
        self.assertEqual(monitor.emit_once(probe.snapshot), 'sent')
        self.assertEqual(beat_session.post.call_count, 2)

    def test_default_target_is_liveness_not_pool_readiness(self):
        self.response.iter_content.return_value = [LIVE_BODY]
        probe = self.probe({})
        self.assertEqual(probe.mode, 'liveness')
        self.assertTrue(probe.snapshot()['healthy'])
        self.assertEqual(probe.last_result, 'alive')
        self.assertEqual(self.session.get.call_args.args[0], LIVENESS)

    def test_liveness_keeps_beat_when_pool_is_unready_or_rebuilding(self):
        self.response.iter_content.return_value = [
            b'{"alive":true,"worker_alive":true,"progress_fresh":true,"ready":false}'
        ]
        probe = self.probe({})
        beat_session = Mock()
        beat_session.post.return_value = Mock(status_code=204)
        monitor = HeartbeatMonitor(ENV, session=beat_session, monotonic=lambda: self.now)
        self.assertEqual(monitor.emit_once(probe.snapshot), 'sent')
        self.assertEqual(probe.last_result, 'alive')
        beat_session.post.assert_called_once()
        self.assertEqual(self.session.get.call_args.args[0], LIVENESS)

    def test_legacy_readyz_503_never_falls_back_to_livez_or_heartbeatz(self):
        probe = self.probe({'LOCAL_DASHBOARD_URL': LOCAL})
        self.response.status_code = 503
        beat_session = Mock()
        monitor = HeartbeatMonitor(ENV, session=beat_session, monotonic=lambda: self.now)
        self.assertEqual(monitor.emit_once(probe.snapshot), 'unhealthy')
        self.assertEqual(probe.mode, 'readiness')
        self.assertEqual(probe.last_result, 'http_error')
        self.assertEqual(self.session.get.call_args.args[0], LOCAL)
        self.session.get.assert_called_once()
        beat_session.post.assert_not_called()

    def test_legacy_readyz_does_not_accept_liveness_flags_as_ready(self):
        probe = self.probe({'LOCAL_DASHBOARD_URL': LOCAL})
        self.response.iter_content.return_value = [LIVE_BODY]
        self.assertFalse(probe.snapshot()['healthy'])
        self.assertEqual(probe.last_result, 'not_ready')
        self.assertEqual(self.session.get.call_args.args[0], LOCAL)

    def test_liveness_dead_dashboard_worker_and_stale_progress_suppress_beat(self):
        probe = self.probe({})
        beat_session = Mock()
        monitor = HeartbeatMonitor(ENV, session=beat_session, monotonic=lambda: self.now)
        for flag, expected in (('alive', 'dashboard_not_alive'),
                               ('worker_alive', 'worker_not_alive'),
                               ('progress_fresh', 'progress_stale')):
            with self.subTest(flag=flag):
                self.response.iter_content.return_value = [
                    LIVE_BODY.replace(('"' + flag + '":true').encode(),
                                      ('"' + flag + '":false').encode())
                ]
                self.assertEqual(monitor.emit_once(probe.snapshot), 'unhealthy')
                self.assertEqual(probe.last_result, expected)
        beat_session.post.assert_not_called()

    def test_liveness_requires_all_three_literal_boolean_flags(self):
        probe = self.probe({})
        for payload in (b'{}', b'[]', b'true', b'null', b'{"ready":true}',
                        b'{"alive":true,"worker_alive":true}',
                        b'{"alive":true,"worker_alive":true,"progress_fresh":1}',
                        b'{"alive":1,"worker_alive":true,"progress_fresh":true}',
                        b'{"alive":true,"worker_alive":"true","progress_fresh":true}',
                        b'{"alive":true,"worker_alive":true,"progress_fresh":null}'):
            with self.subTest(payload=payload):
                self.response.iter_content.return_value = [payload]
                self.assertFalse(probe.snapshot()['healthy'])
                self.assertEqual(probe.last_result, 'invalid_liveness')

    def test_liveness_success_is_fresh_each_time_and_http_error_discards_success(self):
        probe = self.probe({})
        self.response.iter_content.return_value = [LIVE_BODY]
        self.assertEqual(probe.snapshot()['last_reconcile_monotonic'], 1000)
        self.now += 60
        self.assertEqual(probe.snapshot()['last_reconcile_monotonic'], 1060)
        self.response.status_code = 503
        self.assertEqual(probe.snapshot(), {'healthy': False, 'last_reconcile_monotonic': 0.0})
        self.assertEqual(self.session.get.call_count, 3)
        self.assertEqual(self.session.get.call_args.args[0], LIVENESS)

    def test_liveness_does_not_accept_legacy_ready_true_as_live(self):
        probe = self.probe({})
        self.assertFalse(probe.snapshot()['healthy'])
        self.assertEqual(probe.last_result, 'invalid_liveness')

    def test_liveness_late_body_and_transport_failure_never_reuse_success(self):
        probe = self.probe({})
        self.response.iter_content.return_value = [LIVE_BODY]
        self.assertTrue(probe.snapshot()['healthy'])
        def chunks():
            self.now += 8
            yield LIVE_BODY
        self.response.iter_content.return_value = chunks()
        self.assertFalse(probe.snapshot()['healthy'])
        self.assertEqual(probe.last_result, 'timeout')
        self.session.get.side_effect = TimeoutError('SECRET ' + LIVENESS)
        self.assertFalse(probe.snapshot()['healthy'])
        self.assertEqual(probe.last_result, 'probe_failed')
        self.assertNotIn('SECRET', str(self.logger.mock_calls))
        self.assertNotIn(LIVENESS, str(self.logger.mock_calls))
        self.assertEqual(self.response.close.call_count, 2)

    def test_liveness_logs_mode_reason_and_recovery_without_url(self):
        probe = self.probe({})
        self.response.iter_content.return_value = [
            b'{"alive":true,"worker_alive":true,"progress_fresh":false}'
        ]
        probe.snapshot()
        probe.snapshot()
        self.logger.warning.assert_called_once_with(
            'Dashboard %s probe failed: %s', 'liveness', 'progress_stale')
        self.response.iter_content.return_value = [LIVE_BODY]
        probe.snapshot()
        self.logger.info.assert_called_once_with('Dashboard %s recovered', 'liveness')
        self.assertNotIn(LIVENESS, str(self.logger.mock_calls))

    def test_check_is_offline_and_no_config_values_printed(self):
        session = Mock()
        output = io.StringIO()
        with patch('heartbeat.requests.Session', return_value=session), redirect_stdout(output):
            self.assertEqual(main(['--check'], environ=ENV), 0)
        self.assertEqual(output.getvalue(), 'HOST_HEARTBEAT_CONFIG=OK NETWORK=NONE\n')
        session.get.assert_not_called()
        session.post.assert_not_called()
        self.assertNotIn(ENV['HEARTBEAT_TOKEN'], output.getvalue())

    def test_check_requires_enabled_valid_external_heartbeat(self):
        for env in ({}, {'HEARTBEAT_URL': 'invalid'}, {**ENV, 'HEARTBEAT_TOKEN': 'short'},
                    {**ENV, 'HEARTBEAT_INTERVAL': '0'}, {**ENV, 'HEARTBEAT_TIMEOUT': '31'}):
            with self.subTest(env=env), patch('heartbeat.requests.Session') as session:
                self.assertEqual(main(['--check'], environ=env), 2)
                session.return_value.get.assert_not_called()
                session.return_value.post.assert_not_called()

    def test_check_invalid_local_target_fails_before_session_creation(self):
        with patch('heartbeat.requests.Session') as session:
            self.assertEqual(main(['--check'], environ={**ENV,
                             'LOCAL_DASHBOARD_URL': 'http://localhost/readyz'}), 2)
            session.assert_not_called()

    def test_check_file_secrets_are_supported_without_http_or_env_file_parsing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'token'
            path.write_text('a' * 48 + '\n', encoding='utf-8')
            env = {**ENV, 'HEARTBEAT_TOKEN': 'bad', 'HEARTBEAT_TOKEN_FILE': str(path)}
            session = Mock()
            with patch('heartbeat.requests.Session', return_value=session):
                self.assertEqual(main(['--check'], environ=env), 0)
            session.get.assert_not_called()
            session.post.assert_not_called()
            path.unlink()
            with patch('heartbeat.requests.Session') as session:
                self.assertEqual(main(['--check'], environ=env), 2)
                session.assert_not_called()

    def test_main_signal_stops_loop_and_restores_handlers(self):
        stop = threading.Event()
        probe, monitor = Mock(), Mock(enabled=True, config_error='')
        registered = {}
        original = object()
        def install(signum, handler):
            registered.setdefault(signum, []).append(handler)
        def run(event, provider):
            self.assertIs(event, stop)
            self.assertEqual(provider, probe.snapshot)
            registered[signal.SIGTERM][0](signal.SIGTERM, None)
            self.assertTrue(event.is_set())
        monitor.run.side_effect = run
        with patch('scripts.host_heartbeat.DashboardProbe', return_value=probe), \
             patch('scripts.host_heartbeat.HeartbeatMonitor', return_value=monitor), \
             patch('scripts.host_heartbeat.signal.getsignal', return_value=original), \
             patch('scripts.host_heartbeat.signal.signal', side_effect=install):
            self.assertEqual(main([], environ=ENV, stop_event=stop), 0)
        for signum in (signal.SIGTERM, signal.SIGINT):
            self.assertIs(registered[signum][-1], original)
        probe.close.assert_called_once()
        monitor.session.close.assert_called_once()

    def test_pre_stopped_event_makes_no_http(self):
        stop = threading.Event()
        stop.set()
        session = Mock()
        with patch('heartbeat.requests.Session', return_value=session):
            self.assertEqual(main([], environ=ENV, stop_event=stop), 0)
        session.get.assert_not_called()
        session.post.assert_not_called()


if __name__ == '__main__':
    unittest.main()
