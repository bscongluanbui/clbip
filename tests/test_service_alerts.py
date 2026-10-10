"""Offline notification integration: fake NIC/engine and durable SQLite only."""
import json
import subprocess
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import test_service as fixtures
from test_diagnostics_service import measured_dns
from service import OperationError, ProxyService
from validation import ValidationError


class RecordingAlerts:
    """Capture producer calls without executing Telegram HTTP or a sender thread."""
    def __init__(self, events=None):
        self.calls = []
        self.active = set()
        self.events = events if events is not None else []

    def failure(self, key, title, detail=''):
        self.calls.append(('failure', key, title, detail))
        self.active.add(key)
        self.events.append(('alert_failure', key))

    def resolve(self, key, title, detail=''):
        self.calls.append(('resolve', key, title, detail))
        self.active.discard(key)
        self.events.append(('alert_resolve', key))

    def event(self, key, title, detail=''):
        self.calls.append(('event', key, title, detail))
        self.events.append(('alert_event', key))

    def status(self):
        return {'pending': len(self.calls), 'active_incidents': len(self.active)}

    def matching(self, action, key):
        return [call for call in self.calls if call[:2] == (action, key)]


class ServiceAlertsTests(unittest.TestCase):
    tearDown = fixtures.ServiceTests.tearDown
    generate = fixtures.ServiceTests.generate

    def setUp(self):
        fixtures.ServiceTests.setUp(self)
        self.real_alerts = self.service.alerts
        self.alerts = RecordingAlerts(self.events)
        self.service.alerts = self.alerts

    def run_cycles(self, count=1, on_wait=None):
        """Run the real reconciler loop for bounded cycles with no sleeping."""
        completed = 0

        def wait(_timeout):
            nonlocal completed
            completed += 1
            if on_wait:
                on_wait(completed)
            if completed >= count:
                self.service.stop_event.set()
            return self.service.stop_event.is_set()

        with patch.object(self.service.stop_event, 'wait', side_effect=wait):
            self.service.run_reconciler()
        self.assertEqual(completed, count)

    def test_validation_failure_and_same_operation_success_resolve(self):
        with self.assertRaises(ValidationError):
            self.service.dispatch('generate', {'count': True})
        self.assertTrue(self.alerts.matching('failure', 'operation:generate'))
        result = self.generate()
        self.assertTrue(result['success'])
        self.assertTrue(self.alerts.matching('resolve', 'operation:generate'))
        self.assertNotIn('operation:generate', self.alerts.active)

    def test_unexpected_exception_does_not_queue_request_or_exception_secrets(self):
        secret = 'fixture-password-and-token-do-not-send'

        def generate(_params):
            raise RuntimeError(secret)

        with patch.object(self.service, 'generate', new=generate):
            with self.assertRaises(RuntimeError):
                self.service.dispatch('generate', {'password': secret, 'token': secret})
        calls = self.alerts.matching('failure', 'operation:generate')
        self.assertTrue(calls)
        self.assertNotIn(secret, json.dumps(calls))

    def test_false_success_result_is_an_alert_not_a_success_resolution(self):

        def start(_params):
            return {'success': False, 'message': 'fixture failure'}

        with patch.object(self.service, 'start', new=start):
            result = self.service.dispatch('start', {})
        self.assertFalse(result['success'])
        self.assertTrue(self.alerts.matching('failure', 'operation:start'))
        self.assertFalse(self.alerts.matching('resolve', 'operation:start'))

    def test_alert_storage_failure_does_not_replace_operation_result_or_exception(self):
        broken = Mock()
        broken.failure.side_effect = OSError('fixture outbox unavailable')
        broken.resolve.side_effect = OSError('fixture outbox unavailable')
        broken.event.side_effect = OSError('fixture outbox unavailable')
        self.service.alerts = broken
        with self.assertRaises(ValidationError):
            self.service.dispatch('generate', {'count': True})
        self.assertTrue(self.generate()['success'])

    def test_successful_reads_do_not_create_failure_or_event_alerts(self):
        self.generate()
        self.alerts.calls.clear()
        for method in ('settings', 'users', 'proxies', 'status', 'events'):
            self.service.dispatch(method, {})
        self.assertFalse([call for call in self.alerts.calls if call[0] in {'failure', 'event'}])

    def test_read_and_enqueue_do_not_send_http_while_mutation_lock_is_held(self):
        self.service.alerts = self.real_alerts
        with patch('alerts.send_telegram_message', side_effect=AssertionError('HTTP on producer path')), \
                patch('requests.sessions.Session.request', side_effect=AssertionError('HTTP on producer path')):
            with self.service.lock:
                with self.assertRaises(ValidationError):
                    self.service.dispatch('generate', {'count': True})
                self.service.dispatch('status', {})
        self.assertGreaterEqual(self.real_alerts.status()['queued'], 1)

    def test_reconcile_failure_then_real_healthy_cycle_resolves(self):
        self.generate()
        self.alerts.calls.clear()
        self.net.failure = 'probe'
        self.service.last_probe = 0
        self.service.last_base_probe = 0
        self.run_cycles(2, on_wait=lambda cycle: setattr(self.net, 'failure', None) if cycle == 1 else None)
        failure = self.alerts.matching('failure', 'network.reconcile')
        resolution = self.alerts.matching('resolve', 'network.reconcile')
        self.assertTrue(failure)
        self.assertTrue(resolution)
        self.assertLess(self.alerts.calls.index(failure[0]), self.alerts.calls.index(resolution[0]))
        self.assertNotIn('network.reconcile', self.alerts.active)

    def test_prefix_confirmation_waiting_does_not_announce_network_recovery(self):
        self.generate()
        self.alerts.failure('network.reconcile', 'fixture outage')
        self.alerts.calls.clear()
        self.net.system[0]['address'] = '2606:4700:2::1'
        state = self.store.read()
        state['settings']['source_change_confirmations'] = 2
        self.store.write(state)
        self.service.last_base_probe = 0
        self.run_cycles()
        self.assertFalse(self.engine.running)
        self.assertTrue(self.service.source_candidates)
        self.assertFalse(self.alerts.matching('resolve', 'network.reconcile'))
        self.assertFalse(self.alerts.matching('event', 'prefix.renumber'))

    def test_prefix_renumber_event_follows_durable_successful_commit(self):
        self.generate()
        self.net.system[0]['address'] = '2606:4700:2::1'
        state = self.store.read()
        state['settings']['source_change_confirmations'] = 1
        self.store.write(state)
        self.service.last_base_probe = 0
        self.events.clear()
        self.alerts.calls.clear()
        self.service.reconcile()
        event = self.alerts.matching('event', 'prefix.renumber')
        self.assertTrue(event)
        commit = next(index for index, value in enumerate(self.events)
                      if value == ('commit', 'prefix.renumber'))
        notify = next(index for index, value in enumerate(self.events)
                      if value == ('alert_event', 'prefix.renumber'))
        self.assertLess(commit, notify)
        self.assertEqual(self.store.read()['proxies'][0]['subnet'], '2606:4700:2::')

    def test_failed_renumber_transaction_does_not_emit_success_event(self):
        self.generate()
        self.net.system[0]['address'] = '2606:4700:2::1'
        state = self.store.read()
        state['settings']['source_change_confirmations'] = 1
        self.store.write(state)
        self.service.last_base_probe = 0
        self.engine.fail_restart_once = True
        self.alerts.calls.clear()
        with self.assertRaises(OperationError):
            self.service.reconcile()
        self.assertFalse(self.alerts.matching('event', 'prefix.renumber'))

    def test_alias_restore_and_engine_recovery_events_require_successful_activation(self):
        self.generate()
        self.engine.running = False
        self.alerts.calls.clear()
        self.service.last_probe = self.service.last_base_probe = time.time()
        with patch.object(self.net, 'restore_proxy_addresses', return_value={'restored': 1, 'failed': 0}):
            self.service.reconcile()
        self.assertTrue(self.engine.running)
        self.assertTrue(self.alerts.matching('event', 'ipv6.alias_restored'))
        self.assertTrue(self.alerts.matching('event', 'engine.recovered'))

    def test_failed_restore_or_activation_never_announces_alias_recovery(self):
        self.generate()
        self.service.last_probe = self.service.last_base_probe = time.time()
        for failed_restore in (True, False):
            with self.subTest(failed_restore=failed_restore):
                self.alerts.calls.clear()
                self.engine.fail_restart_once = not failed_restore
                with patch.object(self.net, 'restore_proxy_addresses', return_value={
                        'restored': 1, 'failed': int(failed_restore)}):
                    with self.assertRaises(OperationError):
                        self.service.reconcile()
                self.assertFalse(self.alerts.matching('event', 'ipv6.alias_restored'))

    def test_startup_rebuild_notification_is_after_fresh_pool_commit(self):
        self.generate(count=1)
        state = self.store.read()
        state['settings'].update(startup_rebuild_enabled=True, startup_proxy_count=2)
        state['manual_stop'] = False
        self.store.write(state)
        self.service = ProxyService(store=self.store, net=self.net, proxy=self.engine)
        self.service.alerts = self.alerts
        self.alerts.calls.clear()
        self.service.reconcile()
        current = self.store.read()
        self.assertEqual(current['startup_recovery']['phase'], 'done')
        self.assertEqual(len(current['proxies']), 2)
        self.assertTrue(self.alerts.matching('event', 'startup.rebuilt'))

    def test_manual_stop_and_cancelled_operation_do_not_report_network_outage(self):
        self.generate()
        self.service.dispatch('stop', {})
        self.alerts.calls.clear()
        self.run_cycles()
        self.assertFalse(self.alerts.matching('failure', 'network.reconcile'))
        self.assertFalse(self.alerts.matching('resolve', 'network.reconcile'))
        self.service.stop_event.clear()

        def cancelled(_params):
            # A Stop request arrives after dispatch has cleared stale flags.
            self.service.cancel_operation.set()
            raise OperationError('Đã hủy bởi Stop')

        with patch.object(self.service, 'generate', new=cancelled):
            with self.assertRaises(OperationError):
                self.service.dispatch('generate', {'password': 'fixture'})
        self.assertFalse(self.alerts.matching('failure', 'operation:generate'))

    def test_heartbeat_snapshot_is_lightweight_not_a_nic_probe(self):
        self.generate()
        with patch.object(self.net, 'get_ipv6_addresses', side_effect=AssertionError('snapshot performed NIC work')), \
                patch.object(self.engine, 'running_instances', side_effect=AssertionError('snapshot performed process work')):
            snapshot = self.service.heartbeat_snapshot()
        self.assertIsInstance(snapshot, dict)
        self.assertIn('healthy', snapshot)

    def test_heartbeat_does_not_claim_healthy_running_pool_with_unready_engine(self):
        self.generate()
        self.service._cache_observation(processes={'ready': False, 'running': 0, 'expected': 1})
        self.assertFalse(self.service.heartbeat_snapshot()['healthy'])

    def test_heartbeat_does_not_claim_healthy_with_uncertain_ownership(self):
        self.generate()
        state = self.store.read()
        state['uncertain_addresses'] = [{'address': fixtures.POOL + '999', 'interface': 'eth0',
                                         'prefix_len': 128, 'creation': 'unknown', 'operation_id': 'fixture-op'}]
        self.store.write(state)
        self.assertFalse(self.service.heartbeat_snapshot()['healthy'])

    def test_nested_dns_partial_failure_reports_then_verified_dns_success_resolves(self):
        self.generate()
        measured = measured_dns()
        measured['resolvers'][0]['probes'][0].update(success=False, outcome='timeout', answers=[])
        measured['resolvers'][0]['summary'].update(success_count=1, error_count=1)
        self.alerts.calls.clear()
        with patch('service.probe_dns', return_value=measured), \
                patch('validation.socket.getaddrinfo', side_effect=AssertionError('No DNS outside mocked probe')), \
                patch.object(self.service, '_resource_observation', return_value={'observation': 'fixture'}):
            result = self.service.dispatch('diagnostics', {'target_url': 'https://www.bing.com/?private=DO_NOT_ALERT'})
        self.assertTrue(result['success'])  # Measurement finished, not all probes succeeded.
        self.assertTrue(self.alerts.matching('failure', 'operation:diagnostics'))
        self.assertFalse(self.alerts.matching('resolve', 'operation:diagnostics'))
        self.assertNotIn('DO_NOT_ALERT', json.dumps(self.alerts.calls))
        with patch('service.probe_dns', return_value=measured_dns()), \
                patch.object(self.service, '_resource_observation', return_value={'observation': 'fixture'}):
            self.service.dispatch('diagnostics', {})
        self.assertTrue(self.alerts.matching('resolve', 'operation:diagnostics'))

    def test_empty_dns_measurement_does_not_claim_recovery(self):
        measured = measured_dns()
        measured['resolvers'] = []
        self.alerts.failure('operation:diagnostics', 'fixture unresolved measurement')
        self.alerts.calls.clear()
        with patch('service.probe_dns', return_value=measured), \
                patch.object(self.service, '_resource_observation', return_value={'observation': 'fixture'}):
            self.service.dispatch('diagnostics', {})
        self.assertFalse(self.alerts.matching('resolve', 'operation:diagnostics'))

    def test_batch_partial_failure_reports_counts_then_all_success_resolves(self):
        self.generate(count=2)
        first_id = self.store.read()['proxies'][0]['id']
        self.alerts.calls.clear()

        def partly_failed(proxy, _settings, _users, _url):
            return {'success': proxy['id'] == first_id, 'port': proxy['port'], 'total_time': .1, 'ttfb': .1,
                    'error': 'private-request-secret-must-not-appear-in-alert'}

        with patch('service.target_url', return_value='https://www.bing.com/?private=DO_NOT_ALERT'), \
                patch.object(self.service, '_test_one', new=partly_failed):
            result = self.service.dispatch('speedtest_batch', {'max_test': 2})
        self.assertTrue(result['success'])
        self.assertEqual(result['total_failed'], 1)
        calls = self.alerts.matching('failure', 'operation:speedtest_batch')
        self.assertTrue(calls)
        self.assertFalse(self.alerts.matching('resolve', 'operation:speedtest_batch'))
        self.assertNotIn('private-request-secret', json.dumps(calls))
        self.assertNotIn('DO_NOT_ALERT', json.dumps(calls))
        with patch('service.target_url', return_value='https://www.bing.com'), \
                patch.object(self.service, '_test_one', return_value={'success': True, 'total_time': .1, 'ttfb': .1}):
            self.service.dispatch('speedtest_batch', {'max_test': 2})
        self.assertTrue(self.alerts.matching('resolve', 'operation:speedtest_batch'))

    def test_proxy_probe_timeout_then_actual_success_reports_port_recovery_without_secrets(self):
        self.generate()
        state = self.store.read()
        proxy = state['proxies'][0]
        key = 'diagnostic:' + str(proxy['port'])
        self.alerts.calls.clear()
        with patch('service.subprocess.run', side_effect=subprocess.TimeoutExpired('curl', 35, stderr='DO_NOT_ALERT')):
            result = self.service._test_one(proxy, state['settings'], state['users'],
                                            'https://www.bing.com/?private=DO_NOT_ALERT')
        self.assertFalse(result['success'])
        self.assertTrue(self.alerts.matching('failure', key))
        self.assertNotIn('DO_NOT_ALERT', json.dumps(self.alerts.calls))
        metrics = {'dns_lookup': .01, 'tcp_connect': .02, 'tls_handshake': .04,
                   'total_time': .06, 'ttfb': .05, 'http_code': '200',
                   'http_connect_code': 200, 'speed_download': 1000,
                   'size_download': 2000, 'remote_ip': '127.0.0.1'}
        completed = SimpleNamespace(stdout=json.dumps(metrics), returncode=0, stderr='')
        with patch('service.subprocess.run', return_value=completed):
            result = self.service._test_one(proxy, state['settings'], state['users'], 'https://www.bing.com')
        self.assertTrue(result['success'])
        self.assertTrue(self.alerts.matching('resolve', key))

    def configure_telegram(self):
        state = self.store.read()
        state['settings'].update(telegram_bot_token='123456789:offline_fixture_token_keep_private',
                                 telegram_chat_id='-100123456789')
        self.store.write(state)
        return state['settings']

    def test_manual_telegram_failure_then_success_runs_without_mutation_lock_and_redacts_token(self):
        settings = self.configure_telegram()
        secret = settings['telegram_bot_token']

        def failed_sender(_message, *, settings):
            self.assertFalse(self.service.lock._is_owned())
            self.assertEqual(settings['telegram_bot_token'], secret)
            raise RuntimeError(secret)

        with patch('telegram_notify.send_telegram_message', new=failed_sender):
            with self.assertRaises(OperationError):
                self.service.dispatch('telegram_test', {})
        self.assertTrue(self.alerts.matching('failure', 'operation:telegram_test'))
        self.assertNotIn(secret, json.dumps(self.alerts.calls))

        def successful_sender(_message, *, settings):
            self.assertFalse(self.service.lock._is_owned())
            self.assertEqual(settings['telegram_bot_token'], secret)
            return True, 'fixture sent'

        with patch('telegram_notify.send_telegram_message', new=successful_sender):
            self.assertTrue(self.service.dispatch('telegram_test', {})['success'])
        self.assertTrue(self.alerts.matching('resolve', 'operation:telegram_test'))

    def test_manual_telegram_test_can_send_while_other_operation_holds_mutation_lock(self):
        self.configure_telegram()
        entered, release = threading.Event(), threading.Event()
        results, errors = [], []

        def blocked_sender(_message, *, settings):
            self.assertFalse(self.service.lock._is_owned())
            entered.set()
            if not release.wait(5):
                raise RuntimeError('fixture sender release missing')
            return True, 'fixture sent'

        def dispatch():
            try:
                results.append(self.service.dispatch('telegram_test', {}))
            except Exception as exc:
                errors.append(exc)

        with patch('telegram_notify.send_telegram_message', new=blocked_sender):
            thread = threading.Thread(target=dispatch)
            try:
                with self.service.lock:
                    thread.start()
                    self.assertTrue(entered.wait(3), 'manual Telegram send waited behind network mutation lock')
                    release.set()
                    thread.join(3)
                    self.assertFalse(thread.is_alive())
            finally:
                release.set()
                thread.join(5)
        self.assertEqual(errors, [])
        self.assertTrue(results[0]['success'])


if __name__ == '__main__':
    unittest.main()
