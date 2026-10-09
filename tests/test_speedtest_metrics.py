"""curl timing/unit contract without subprocess, HTTP, DNS, or NIC activity."""
import copy
import json
import subprocess
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from service import ProxyService
from diagnostics import DiagnosticHistory
from validation import DEFAULT_SETTINGS


class SpeedtestMetricsTests(unittest.TestCase):
    def setUp(self):
        self.service = ProxyService.__new__(ProxyService)
        self.service.diagnostic_history = DiagnosticHistory(max_samples=200)
        self.proxy = {'id': 1, 'protocol': 'http', 'ipv6': '2606:4700:1::10', 'port': 10000}
        self.settings = {**DEFAULT_SETTINGS, 'auth_type': 'none', 'listener_ipv4': '0.0.0.0'}
        self.metrics = {'dns_lookup': 0.01, 'tcp_connect': 0.02, 'tls_handshake': 0.06,
                        'ttfb': 0.08, 'total_time': 0.1, 'http_code': '200',
                        'speed_download': 1048576, 'size_download': 65536, 'remote_ip': '127.0.0.1'}

    def perform(self, metrics=None, returncode=0, settings=None, users=None, protocol='http'):
        result = SimpleNamespace(stdout=json.dumps(self.metrics if metrics is None else metrics),
                                 stderr='', returncode=returncode)
        with patch('service.subprocess.run', return_value=result) as run:
            data = self.service._test_one({**self.proxy, 'protocol': protocol},
                                         settings or self.settings, users or [], 'https://www.bing.com')
        return data, run.call_args

    def test_fields_units_and_peer_identity_are_explicit(self):
        original = copy.deepcopy(self.metrics)
        data, call = self.perform()
        self.assertTrue(data['success'])
        for field in ('dns_lookup', 'tcp_connect', 'tls_handshake', 'ttfb', 'total_time'):
            self.assertEqual(data[field], self.metrics[field])
        self.assertEqual(data['speed_bytes_per_second'], 1048576)
        self.assertEqual(data['speed_kbps'], 1024)  # Legacy name stores KiB/s.
        self.assertEqual(data['speed_mbps'], 8.389)
        self.assertEqual(data['download_bytes'], 65536)
        self.assertEqual(data['remote_ip'], '127.0.0.1')
        self.assertEqual(data['proxy_peer_ip'], '127.0.0.1')
        self.assertEqual(data['remote_ip_role'], 'proxy_peer')
        self.assertEqual(data['ipv6'], self.proxy['ipv6'])
        self.assertNotEqual(data['proxy_peer_ip'], data['ipv6'])
        self.assertEqual(data['timing_scope'], 'curl_via_proxy')
        self.assertEqual(data['transfer_rate_scope'], 'sample_response')
        self.assertEqual(data['target_host'], 'www.bing.com')
        self.assertEqual(self.metrics, original)
        command = call.args[0]
        output_format = command[command.index('--write-out') + 1]
        for token in ('time_namelookup', 'time_connect', 'time_appconnect', 'time_starttransfer',
                      'time_total', 'speed_download', 'size_download', 'remote_ip'):
            self.assertIn('%{' + token + '}', output_format)
        self.assertEqual(command[command.index('--proto') + 1], '=https')
        self.assertEqual(call.kwargs['timeout'], 35)

    def test_no_auth_does_not_reuse_saved_credentials(self):
        data, call = self.perform(users=[{'username': 'fixture', 'password': 'Private_42!'}])
        self.assertTrue(data['success'])
        self.assertEqual(call.kwargs['input'], '')
        self.assertNotIn('Private_42!', json.dumps(data))

    def test_userpass_stays_in_stdin_not_argv_or_result(self):
        settings = {**self.settings, 'auth_type': 'userpass'}
        user = {'username': 'fixture', 'password': 'Private_42!'}
        data, call = self.perform(settings=settings, users=[user])
        self.assertEqual(call.kwargs['input'], 'proxy-user = "fixture:Private_42!"\n')
        self.assertNotIn(user['password'], ' '.join(call.args[0]))
        self.assertNotIn(user['password'], json.dumps(data))

    def test_protocol_and_specific_listener_have_correct_peer_address(self):
        for protocol, expected in [('http', 'http'), ('dual', 'http'), ('socks5', 'socks5h')]:
            with self.subTest(protocol=protocol):
                settings = {**self.settings, 'listener_ipv4': '192.168.5.8'}
                data, call = self.perform(settings=settings, protocol=protocol,
                                          metrics={**self.metrics, 'remote_ip': '192.168.5.8'})
                command = call.args[0]
                self.assertEqual(command[command.index('--proxy') + 1], f'{expected}://192.168.5.8:10000')
                self.assertEqual(data['proxy_peer_ip'], '192.168.5.8')

    def test_curl_transport_or_target_http_failure_does_not_become_success(self):
        for code, curl_status in [('200', 7), ('503', 0), ('000', 28)]:
            with self.subTest(code=code, curl_status=curl_status):
                data, _ = self.perform(metrics={**self.metrics, 'http_code': code}, returncode=curl_status)
                self.assertFalse(data['success'])
                self.assertEqual(data['error'], 'Proxy transport/auth/DNS/target failed')

    def test_invalid_metrics_fail_closed_without_raw_stdout_or_stderr(self):
        for metrics in ([], {'speed_download': -1}, {'ttfb': float('nan')},
                        {'total_time': float('inf')}, {'dns_lookup': None}, {'remote_ip': 'not-an-ip'}):
            with self.subTest(metrics=metrics):
                data, _ = self.perform(metrics=metrics)
                self.assertFalse(data['success'])
                self.assertEqual(data['error'], 'Proxy probe failed')
                self.assertNotIn('remote_ip', data)

    def test_timeout_invalid_json_and_os_failure_report_probe_failure(self):
        for failure in (OSError('fixture'), subprocess.TimeoutExpired('curl', 35), None):
            with self.subTest(failure=failure), patch('service.subprocess.run') as run:
                if failure:
                    run.side_effect = failure
                else:
                    run.return_value = SimpleNamespace(stdout='not-json', returncode=0)
                data = self.service._test_one(self.proxy, self.settings, [], 'https://www.bing.com')
                self.assertFalse(data['success'])
                self.assertEqual(data['error'], 'Proxy probe failed')

    def test_missing_peer_on_failed_curl_is_not_invented(self):
        data, _ = self.perform(metrics={**self.metrics, 'remote_ip': ''}, returncode=7)
        self.assertFalse(data['success'])
        self.assertEqual(data['proxy_peer_ip'], '')
