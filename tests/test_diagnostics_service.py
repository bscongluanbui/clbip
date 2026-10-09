"""Offline diagnostics API/service and DNS-setting activation contracts.

The service fixture uses isolated SQLite and fake NIC/engine implementations;
resolver probes, passive observation and curl are injected, never live calls.
"""
import copy
import json
import subprocess
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import app as dashboard
import test_dashboard as web_fixtures
import test_service as fixtures
from service import OperationError
from validation import ValidationError


def measured_dns():
    probe = {'success': True, 'outcome': 'ok', 'round': 1, 'elapsed_ms': 25,
             'rcode': 0, 'rcode_name': 'NOERROR', 'transport': 'udp',
             'answers': [{'address': '2606:4700::1111', 'ttl': 300}]}
    return {'domain': 'www.bing.com', 'timeout_seconds': 3, 'rounds': 2, 'elapsed_ms': 50,
            'resolvers': [{'resolver': '127.0.0.1', 'probes': [probe, {**probe, 'round': 2}],
                           'summary': {'sample_count': 2, 'success_count': 2, 'error_count': 0,
                                       'p50_ms': 25, 'p95_ms': 25, 'p99_ms': 25}}]}


class DiagnosticsServiceTests(unittest.TestCase):
    tearDown = fixtures.ServiceTests.tearDown
    generate = fixtures.ServiceTests.generate
    names = fixtures.ServiceTests.names

    def setUp(self):
        fixtures.ServiceTests.setUp(self)
        self.generate(count=2)
        self.events.clear()
        self.resource_patch = patch.object(self.service, '_resource_observation',
                                           return_value={'observation': 'fixture'})
        self.resource_patch.start()
        self.addCleanup(self.resource_patch.stop)

    def call(self, params=None):
        return self.service.dispatch('diagnostics', {} if params is None else params)

    def assert_pool_preserved(self, before):
        current = self.store.read()
        for key in ('proxies', 'managed_addresses', 'users', 'desired_state', 'manual_stop',
                    'pending_operation', 'uncertain_addresses', 'prefix_state', 'startup_recovery'):
            self.assertEqual(current[key], before[key], key)
        self.assertTrue(self.engine.running)

    def test_probe_uses_configured_resolvers_without_state_engine_or_network_mutation(self):
        before, config = self.store.read(), copy.deepcopy(self.engine.config)
        aliases = copy.deepcopy(self.net.aliases)
        with patch('service.probe_dns', return_value=measured_dns()) as probe, \
                patch('validation.socket.getaddrinfo', side_effect=AssertionError('No system DNS')), \
                patch.object(self.store, 'write', wraps=self.store.write) as write:
            result = self.call({'target_url': 'https://www.bing.com/?private=SECRET'})
        probe.assert_called_once_with('https://www.bing.com/?private=SECRET',
                                      [before['settings'][k] for k in ('dns1', 'dns2', 'dns3')],
                                      timeout=3, rounds=2)
        write.assert_not_called()
        self.assertEqual(self.store.read(), before)
        self.assertEqual(self.engine.config, config)
        self.assertEqual(self.net.aliases, aliases)
        self.assertEqual(self.events, [])
        self.assertTrue(result['success'])
        self.assertFalse(result['runtime_changed'])
        self.assertFalse(result['dns']['cache_confirmed'])
        self.assertEqual(result['dns']['query_type'], 'AAAA')
        self.assertEqual(result['dns']['results'][0]['addresses'], ['2606:4700::1111'])
        self.assertEqual(result['history']['scope'], 'speedtest_only')
        self.assertNotIn('SECRET', json.dumps(result))

    def test_unknown_params_reject_before_resolver_or_state_write(self):
        for params in ({'timeout': 60}, {'_idempotency_key': 'unexpected'}, {'port': 10000}):
            with self.subTest(params=params), patch('service.probe_dns') as probe, \
                    patch.object(self.store, 'write') as write:
                with self.assertRaises(ValidationError):
                    self.call(params)
                probe.assert_not_called()
                write.assert_not_called()

    def test_invalid_url_private_literal_and_fragment_reject_before_probe(self):
        for url in ('http://www.bing.com', 'https://www.bing.com/#secret',
                    'https://127.0.0.1/', 'https://user:pass@www.bing.com'):
            with self.subTest(url=url), patch('service.probe_dns') as probe:
                with self.assertRaises(ValidationError):
                    self.call({'target_url': url})
                probe.assert_not_called()
        self.assertEqual(self.events, [])

    def test_public_ip_target_is_not_dns_hostname_and_never_opens_socket(self):
        with patch('diagnostics.socket.socket', side_effect=AssertionError('No socket')), \
                patch('validation.socket.getaddrinfo', side_effect=AssertionError('No system DNS')):
            with self.assertRaises(ValueError):
                self.call({'target_url': 'https://1.1.1.1'})
        self.assertFalse(self.service.diagnostic_lock.locked())
        self.assertEqual(self.events, [])

    def test_explicit_diagnostic_budget_is_bounded_and_not_engine_timeout(self):
        for configured, expected in ((1, 1), (5, 3), (15, 3), (30, 3)):
            state = self.store.read()
            state['settings']['timeout_dns'] = configured
            self.store.write(state)
            with self.subTest(configured=configured), patch('service.probe_dns', return_value=measured_dns()) as probe:
                self.call()
                self.assertEqual(probe.call_args.kwargs['timeout'], expected)
                self.assertEqual(probe.call_args.kwargs['rounds'], 2)

    def test_diagnostics_does_not_wait_for_network_mutation_lock(self):
        result, errors = [], []
        def run():
            try:
                result.append(self.call())
            except Exception as exc:
                errors.append(exc)
        with patch('service.probe_dns', return_value=measured_dns()), self.service.lock:
            thread = threading.Thread(target=run)
            thread.start()
            thread.join(3)
            completed_without_lock = not thread.is_alive()
        thread.join(3)
        self.assertTrue(completed_without_lock)
        self.assertEqual(errors, [])
        self.assertTrue(result[0]['success'])

    def test_one_diagnostic_inflight_does_not_block_status_and_rejects_duplicate(self):
        entered, release = threading.Event(), threading.Event()
        results, errors = [], []
        def blocked_probe(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise RuntimeError('Fixture deadline')
            return measured_dns()
        def run():
            try:
                results.append(self.call())
            except Exception as exc:
                errors.append(exc)
        with patch('service.probe_dns', side_effect=blocked_probe):
            thread = threading.Thread(target=run)
            thread.start()
            try:
                self.assertTrue(entered.wait(3))
                status = self.service.dispatch('status', {})
                self.assertEqual(status['total_proxies'], 2)
                self.assertFalse(self.service.cancel_operation.is_set())
                with self.assertRaises(OperationError):
                    self.call()
            finally:
                release.set()
                thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 1)
        self.assertFalse(self.service.diagnostic_lock.locked())
        self.assertEqual(self.events, [])

    def test_probe_exception_releases_lock_and_preserves_store(self):
        before = self.store.read()
        with patch('service.probe_dns', side_effect=RuntimeError('Injected probe failure')):
            with self.assertRaises(RuntimeError):
                self.call()
        self.assertFalse(self.service.diagnostic_lock.locked())
        self.assertEqual(self.store.read(), before)
        with patch('service.probe_dns', return_value=measured_dns()):
            self.assertTrue(self.call()['success'])

    def test_dns_setting_change_activates_engine_once_without_replacing_pool(self):
        before = self.store.read()
        result = self.service.dispatch('save_settings', {'timeout_dns': 5})
        self.assertTrue(result['restarted'])
        self.assertTrue(result['engine_config_changed'])
        self.assertEqual(result['changed_fields'], ['timeout_dns'])
        self.assertEqual(self.names().count('activate'), 1)
        self.assertEqual(self.engine.config['settings']['timeout_dns'], 5)
        self.assertEqual(self.store.read()['settings']['timeout_dns'], 5)
        self.assertEqual(self.store.read()['settings']['thread_limit'], before['settings']['thread_limit'])
        self.assert_pool_preserved(before)
        self.assertFalse(set(self.names()) & {'add', 'remove', 'generate', 'dad', 'probe'})
        self.events.clear()
        noop = self.service.dispatch('save_settings', {'timeout_dns': 5})
        self.assertFalse(noop['changed'])
        self.assertFalse(noop['restarted'])
        self.assertEqual(self.events, [])

    def test_failed_dns_setting_change_restores_fifteen_second_config_and_pool(self):
        before, config = self.store.read(), copy.deepcopy(self.engine.config)
        self.engine.fail_restart_once = True
        with self.assertRaises(OperationError):
            self.service.dispatch('save_settings', {'timeout_dns': 5})
        self.assertEqual(self.store.read()['settings']['timeout_dns'], 15)
        self.assertEqual(self.engine.config, config)
        self.assert_pool_preserved(before)
        self.assertIn('rollback_config', self.names())
        self.assertIn('start', self.names())
        self.assertFalse(set(self.names()) & {'add', 'remove', 'generate', 'dad', 'probe'})

    def test_curl_connect_response_has_priority_over_transport_exit_in_probe_history(self):
        state = self.store.read()
        metrics = {'dns_lookup': 0, 'tcp_connect': .01, 'tls_handshake': 0,
                   'total_time': .05, 'ttfb': 0, 'http_code': '000',
                   'http_connect_code': 407, 'speed_download': 0,
                   'size_download': 0, 'remote_ip': '127.0.0.1'}
        completed = SimpleNamespace(stdout=json.dumps(metrics), returncode=56, stderr='SECRET')
        with patch('service.subprocess.run', return_value=completed):
            result = self.service._test_one(state['proxies'][0], state['settings'], state['users'],
                                           'https://www.bing.com/?secret=PRIVATE')
        self.assertFalse(result['success'])
        report = self.service.diagnostic_history.summary()
        self.assertEqual(report['error_categories'], {'proxy_auth': 1})
        self.assertEqual(report['by_domain'][0]['domain'], 'www.bing.com')
        self.assertNotIn('PRIVATE', json.dumps(report))
        self.assertNotIn('SECRET', json.dumps(report))

    def test_curl_timeout_os_error_and_malformed_output_are_distinct_history_errors(self):
        state = self.store.read()
        cases = ((subprocess.TimeoutExpired('curl', 35), 'timeout'),
                 (OSError('PRIVATE'), 'transport'),
                 (None, 'invalid_response'))
        for failure, category in cases:
            with self.subTest(category=category), patch('service.subprocess.run') as run:
                if failure is not None:
                    run.side_effect = failure
                else:
                    run.return_value = SimpleNamespace(stdout='SECRET_NOT_JSON', returncode=0, stderr='PRIVATE')
                result = self.service._test_one(state['proxies'][0], state['settings'], state['users'],
                                               'https://www.bing.com')
                self.assertFalse(result['success'])
                self.assertEqual(result['error_type'], category)
        report = self.service.diagnostic_history.summary()
        self.assertEqual(report['error_categories'], {'timeout': 1, 'transport': 1, 'invalid_response': 1})
        self.assertEqual(report['latency_sample_count'], 0)
        self.assertIsNone(report['p95_ms'])
        self.assertNotIn('SECRET', json.dumps(report))
        self.assertNotIn('PRIVATE', json.dumps(report))


class DiagnosticsDashboardTests(unittest.TestCase):
    token = web_fixtures.DashboardTests.token
    login = web_fixtures.DashboardTests.login

    def setUp(self):
        self.worker = web_fixtures.FakeWorker()
        self.app = dashboard.create_app({**web_fixtures.CONFIG, 'DASHBOARD_PASSWORD_PATH': ''}, client=self.worker)
        self.client = self.app.test_client()

    def test_diagnostic_post_requires_authentication(self):
        response = self.client.post('/api/proxy/diagnostics', json={'target_url': 'https://www.bing.com'})
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.worker.calls, [])

    def test_browser_diagnostic_post_requires_csrf(self):
        self.login()
        for headers in ({}, {'X-CSRF-Token': 'wrong'}):
            with self.subTest(headers=headers):
                response = self.client.post('/api/proxy/diagnostics', json={}, headers=headers)
                self.assertEqual(response.status_code, 403)
        self.assertEqual(self.worker.calls, [])

    def test_csrf_protected_post_ignores_idempotency_header_and_is_not_gettable(self):
        csrf = self.login()
        params = {'target_url': 'https://www.bing.com'}
        for _ in range(2):
            response = self.client.post('/api/proxy/diagnostics', json=params,
                                        headers={'X-CSRF-Token': csrf, 'Idempotency-Key': 'same-key'})
            self.assertEqual(response.status_code, 200)
        self.assertEqual(self.worker.calls, [('diagnostics', params), ('diagnostics', params)])
        response = self.client.get('/api/proxy/diagnostics')
        self.assertEqual(response.status_code, 405)

    def test_service_bearer_diagnostic_request_has_no_mutation_journal_param(self):
        response = self.client.post('/api/proxy/diagnostics', json={},
                                    headers={'Authorization': 'Bearer ' + web_fixtures.TOKEN,
                                             'Idempotency-Key': 'ignored'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.worker.calls, [('diagnostics', {})])


if __name__ == '__main__':
    unittest.main()
