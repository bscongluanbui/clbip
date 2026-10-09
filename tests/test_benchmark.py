"""Benchmark tests are mocked: they create no proxy or Internet traffic."""
import contextlib
import io
import json
from pathlib import Path
import shutil
import subprocess
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import uuid

from scripts import benchmark as bench


def proxy_records(count):
    return [{'url': f'http://USER:PASSWORD@127.0.0.1:{10000 + index}',
             'expected_ipv6': f'2001:db8::{index + 1:x}'} for index in range(count)]


def health_payload():
    return {'ready': True, 'desired_state': 'running', 'proxy_count': 200, 'service_count': 200,
            'metrics': {'worker': {'rss_bytes': 4096, 'fd_count': 8},
                        'proxy_children': {'rss_bytes': 8192, 'fd_count': 16, 'process_count': 2},
                        'ndp': {'neighbor_count': 3, 'states': {'REACHABLE': 2, 'STALE': 1},
                                'interfaces': {'eth0': {'neighbor_count': 3, 'states': {'REACHABLE': 2, 'STALE': 1}}}}}}


class BenchmarkValidationTests(unittest.TestCase):
    def test_default_matrix_and_custom_counts(self):
        self.assertEqual(bench.DEFAULT_COUNTS, [25, 50, 100, 200])
        self.assertEqual(bench.parse_counts('1,10,20'), [1, 10, 20])
        for value in ['', '0', '1,1', '2,1', '1, 2', '-1', '1025', '1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                bench.parse_counts(value)

    def test_http_and_remote_dns_socks_contract(self):
        records = proxy_records(2)
        records[1]['url'] = 'socks5h://USER:PASSWORD@127.0.0.1:20001'
        result = bench.validate_proxies(records)
        self.assertEqual([x['protocol'] for x in result], ['http', 'socks5h'])
        self.assertEqual(result[0]['endpoint'], '127.0.0.1:10000')
        self.assertNotIn('PASSWORD', result[0]['endpoint'])

    def test_proxy_input_rejects_other_protocols_injection_and_duplicates(self):
        urls = ['socks5://127.0.0.1:20000', 'https://127.0.0.1:10000',
                'http://127.0.0.1:0', 'http://127.0.0.1:65536',
                'http://127.0.0.1:10000/path', 'http://127.0.0.1:10000?url=x',
                'http://USER:@127.0.0.1:10000', 'http://USER@127.0.0.1:10000',
                'http://127.0.0.1:10000\nproxy=x']
        for url in urls:
            with self.subTest(url=url), self.assertRaises(ValueError):
                bench.validate_proxies([{'url': url, 'expected_ipv6': '2001:db8::1'}])
        with self.assertRaises(ValueError):
            bench.validate_proxies(proxy_records(1) * 2)
        with self.assertRaises(ValueError):
            bench.validate_proxies([{'url': 'http://127.0.0.1:10000', 'expected_ipv6': '::ffff:192.0.2.1'}])

    def test_probe_requires_https_no_credentials_fragment_private_literal(self):
        self.assertEqual(bench.validate_probe_url('https://api64.ipify.org'), 'https://api64.ipify.org')
        for value in ['http://api64.ipify.org', 'https://USER:PASS@api64.ipify.org',
                      'https://api64.ipify.org:8443', 'https://api64.ipify.org/#x',
                      'https://127.0.0.1', 'https://[::1]', 'https://[ff02::1]']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                bench.validate_probe_url(value)

    def test_service_token_never_goes_to_remote_dns_or_redirect_url(self):
        self.assertEqual(bench.validate_health_url('http://127.0.0.1:7070/api/proxy/health'),
                         'http://127.0.0.1:7070/api/proxy/health')
        self.assertEqual(bench.validate_health_url('http://[::1]:7070/api/proxy/health'),
                         'http://[::1]:7070/api/proxy/health')
        for value in ['http://localhost:7070/api/proxy/health', 'https://example.org:443/api/proxy/health',
                      'http://127.0.0.1/api/proxy/health', 'http://127.0.0.1:7070/api/health',
                      'http://127.0.0.1:7070/api/proxy/health?next=x']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                bench.validate_health_url(value)


class BenchmarkSampleTests(unittest.TestCase):
    def fake_curl(self, response=b'2001:db8::1\n200', code=0):
        def run(command, **kwargs):
            kwargs['stdout'].write(response)
            return SimpleNamespace(returncode=code)
        return run

    def test_credentials_only_stdin_https_verify_no_redirect_env_bypass(self):
        with patch.object(bench.subprocess, 'run', side_effect=self.fake_curl()) as runner, \
             patch.dict(bench.os.environ, {'HTTPS_PROXY': 'http://other', 'NO_PROXY': '*', 'SSL_CERT_FILE': '/injected'}):
            result = bench.sample('http://USER:PASSWORD@127.0.0.1:10000', 'https://api64.ipify.org')
        self.assertTrue(result['ok'])
        command = runner.call_args.args[0]
        kwargs = runner.call_args.kwargs
        self.assertEqual(command[:4], ['curl', '--disable', '--config', '-'])
        self.assertNotIn('PASSWORD', str(command))
        self.assertIn(b'USER:PASSWORD', kwargs['input'])
        self.assertNotIn('HTTPS_PROXY', kwargs['env'])
        self.assertNotIn('NO_PROXY', kwargs['env'])
        self.assertNotIn('SSL_CERT_FILE', kwargs['env'])
        self.assertNotIn('--insecure', command)
        self.assertNotIn('--location', command)
        self.assertEqual(command[command.index('--noproxy') + 1], '')
        self.assertEqual(kwargs['timeout'], 20)

    def test_socks5h_without_pysocks(self):
        with patch.object(bench.subprocess, 'run', side_effect=self.fake_curl()) as runner:
            self.assertTrue(bench.sample('socks5h://USER:PASSWORD@127.0.0.1:20000', 'https://api64.ipify.org')['ok'])
        self.assertIn(b'socks5h://', runner.call_args.kwargs['input'])

    def test_3xx_is_failure_even_if_response_body_looks_like_ipv6(self):
        with patch.object(bench.subprocess, 'run', side_effect=self.fake_curl(b'2001:db8::1\n302')):
            self.assertEqual(bench.sample('http://127.0.0.1:1', 'https://api64.ipify.org')['error_type'], 'ProbeHTTP')

    def test_response_curl_failure_and_timeout_are_redacted(self):
        cases = [(self.fake_curl(b'x' * 5000), 'ResponseTooLarge'),
                 (self.fake_curl(code=28), 'CurlError'),
                 (self.fake_curl(b'192.0.2.1\n200'), 'AddressValueError'),
                 (self.fake_curl(b'::ffff:192.0.2.1\n200'), 'ValueError')]
        for side_effect, error in cases:
            with self.subTest(error=error), patch.object(bench.subprocess, 'run', side_effect=side_effect):
                result = bench.sample('http://USER:PASSWORD@127.0.0.1:1', 'https://api64.ipify.org')
                self.assertEqual(result['error_type'], error)
                self.assertNotIn('PASSWORD', json.dumps(result))
        with patch.object(bench.subprocess, 'run', side_effect=subprocess.TimeoutExpired('PASSWORD', 20)):
            result = bench.sample('http://USER:PASSWORD@127.0.0.1:1', 'https://api64.ipify.org')
        self.assertEqual(result['error_type'], 'TimeoutExpired')
        self.assertNotIn('PASSWORD', json.dumps(result))


class BenchmarkMatrixTests(unittest.TestCase):
    def matching(self, url, _target):
        source = int(url.rsplit(':', 1)[1]) - 10000 + 1
        return {'ok': True, 'source': f'2001:db8::{source:x}', 'latency_ms': float(source)}

    def test_matrix_selects_all_listeners_every_round_and_redacts_credentials(self):
        proxies = bench.validate_proxies(proxy_records(200))
        observed = []
        observed_lock = threading.Lock()
        def sampled(url, target):
            # Mock.call_count increments race between concurrent workers; count
            # actual side-effect invocations under a lock instead.
            with observed_lock:
                observed.append(url)
            return self.matching(url, target)
        with patch.object(bench, 'sample', side_effect=sampled):
            report = bench.run_matrix(proxies, 'https://api64.ipify.org', [25, 50, 100, 200], rounds=2)
        self.assertTrue(report['ok'])
        self.assertEqual(len(observed), (25 + 50 + 100 + 200) * 2)
        self.assertEqual([x['sample_count'] for x in report['stages']], [50, 100, 200, 400])
        self.assertNotIn('PASSWORD', json.dumps(report))
        self.assertFalse(report['metrics_complete'])
        self.assertEqual(report['count_mode'], 'participating_listener_records')

    def test_one_total_concurrency_cap_not_pool_per_listener(self):
        active, maximum = 0, 0
        lock = threading.Lock()
        def controlled(url, target):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(.005)
            result = self.matching(url, target)
            with lock:
                active -= 1
            return result
        with patch.object(bench, 'sample', side_effect=controlled):
            report = bench.run_matrix(bench.validate_proxies(proxy_records(10)), 'https://api64.ipify.org', [10], rounds=3, concurrency=3)
        self.assertTrue(report['ok'])
        self.assertEqual(maximum, 3)
        self.assertEqual(active, 0)

    def test_source_mismatch_stops_later_stages_and_counts_as_error(self):
        with patch.object(bench, 'sample', return_value={'ok': True, 'source': '2001:db8::ffff', 'latency_ms': 1}):
            report = bench.run_matrix(bench.validate_proxies(proxy_records(3)), 'https://api64.ipify.org', [1, 2, 3])
        self.assertFalse(report['ok'])
        self.assertEqual(report['unrun_counts'], [2, 3])
        self.assertEqual(report['stages'][0]['source_mismatch_count'], 5)
        self.assertEqual(report['stages'][0]['error_rate'], 1)
        self.assertEqual(report['stages'][0]['error_types'], {'SourceMismatch': 5})

    def test_continue_after_errors_still_fails_final_result(self):
        with patch.object(bench, 'sample', return_value={'ok': False, 'error_type': 'TimeoutExpired', 'latency_ms': 1}):
            report = bench.run_matrix(bench.validate_proxies(proxy_records(2)), 'https://api64.ipify.org', [1, 2], continue_on_error=True)
        self.assertFalse(report['ok'])
        self.assertEqual(report['unrun_counts'], [])
        self.assertEqual(len(report['stages']), 2)
        self.assertIsNone(report['stages'][0]['p95_ms'])

    def test_p50_and_nearest_rank_p95(self):
        observations = [{'ok': True, 'source_matches': True, 'latency_ms': i} for i in range(1, 21)]
        result = bench.summarize(observations)
        self.assertEqual(result['p50_ms'], 10.5)
        self.assertEqual(result['p95_ms'], 19)

    def test_bounds_rejected_before_traffic(self):
        proxies = bench.validate_proxies(proxy_records(2))
        for counts, rounds, concurrency in [([3], 1, 1), ([1, 1], 1, 1), ([1], 101, 1), ([1], 1, 33)]:
            with self.subTest(counts=counts), patch.object(bench, 'sample') as sample, self.assertRaises(ValueError):
                bench.run_matrix(proxies, 'https://api64.ipify.org', counts, rounds, concurrency)
            sample.assert_not_called()

    def test_health_snapshots_include_observed_metrics_not_secrets_or_fake_zero(self):
        payload = health_payload()
        payload.update({'password': 'PASSWORD', 'errors': ['TOKEN'], 'uncertain_addresses': ['PRIVATE']})
        projected = bench.project_health(payload)
        self.assertTrue(projected['metrics_complete'])
        self.assertEqual(projected['active_proxy_count'], 200)
        self.assertEqual(projected['metrics']['ndp']['neighbor_count'], 3)
        self.assertNotIn('PASSWORD', json.dumps(projected))
        self.assertNotIn('TOKEN', json.dumps(projected))
        payload['metrics']['worker']['rss_bytes'] = None
        projected = bench.project_health(payload)
        self.assertFalse(projected['metrics_complete'])
        self.assertIsNone(projected['metrics']['worker']['rss_bytes'])

    def test_health_failure_before_stage_creates_no_traffic(self):
        with patch.object(bench, 'sample') as sample:
            report = bench.run_matrix(bench.validate_proxies(proxy_records(2)), 'https://api64.ipify.org', [1, 2], health=lambda: {'ok': False})
        sample.assert_not_called()
        self.assertFalse(report['metrics_complete'])
        self.assertFalse(report['ok'])

    def test_health_api_bearer_is_not_followed_or_logged(self):
        session, response = Mock(), Mock()
        response.status_code = 200
        response.iter_content.return_value = [json.dumps(health_payload()).encode()]
        session.get.return_value = response
        with patch.object(bench.requests, 'Session', return_value=session):
            result = bench.health_snapshot('http://127.0.0.1:7070/api/proxy/health', 'TOKEN')
        self.assertTrue(result['metrics_complete'])
        self.assertFalse(session.trust_env)
        self.assertEqual(session.get.call_args.kwargs['headers'], {'Authorization': 'Bearer TOKEN'})
        self.assertFalse(session.get.call_args.kwargs['allow_redirects'])
        self.assertNotIn('TOKEN', json.dumps(result))
        response.close.assert_called_once()
        session.close.assert_called_once()

    def test_health_redirect_or_oversize_is_failure(self):
        for code, chunks, error in [(302, [], 'HealthHTTP'), (200, [b'x' * (bench.HEALTH_LIMIT + 1)], 'HealthResponseTooLarge')]:
            session, response = Mock(), Mock()
            response.status_code = code
            response.iter_content.return_value = chunks
            session.get.return_value = response
            with patch.object(bench.requests, 'Session', return_value=session):
                self.assertEqual(bench.health_snapshot('http://127.0.0.1:7070/api/proxy/health', 'TOKEN')['error_type'], error)


class BenchmarkCliTests(unittest.TestCase):
    def setUp(self):
        # Ordinary workspace paths work with Windows sandbox ACLs; resolve before cleanup.
        self.root = Path(__file__).resolve().parents[1]
        self.directory = self.root / 'tests' / ('.benchmark-' + uuid.uuid4().hex)
        self.directory.mkdir()
        self.input = self.directory / 'proxies.json'
        self.input.write_text(json.dumps(proxy_records(2)), encoding='utf-8')
        self.output = self.directory / 'result.json'

    def tearDown(self):
        resolved = self.directory.resolve()
        self.assertEqual(resolved.parent, (self.root / 'tests').resolve())
        shutil.rmtree(resolved)

    def test_cli_writes_reopenable_redacted_report_exit_zero(self):
        with patch.object(bench, 'sample', side_effect=BenchmarkMatrixTests().matching), contextlib.redirect_stdout(io.StringIO()) as stdout:
            status = bench.main(['--proxies', str(self.input), '--counts', '1,2', '--rounds', '2', '--output', str(self.output)])
        self.assertEqual(status, 0)
        reopened = json.loads(self.output.read_text(encoding='utf-8'))
        self.assertTrue(reopened['ok'])
        self.assertNotIn('PASSWORD', self.output.read_text(encoding='utf-8') + stdout.getvalue())

    def test_default_matrix_needs_200_records_and_fails_before_traffic(self):
        with patch.object(bench, 'sample') as sample, contextlib.redirect_stderr(io.StringIO()) as stderr, self.assertRaises(SystemExit) as raised:
            bench.main(['--proxies', str(self.input), '--output', str(self.output)])
        self.assertEqual(raised.exception.code, 2)
        self.assertNotIn('PASSWORD', stderr.getvalue())
        sample.assert_not_called()

    def test_output_cannot_destroy_credential_input(self):
        original = self.input.read_bytes()
        with patch.object(bench, 'sample') as sample, contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            bench.main(['--proxies', str(self.input), '--counts', '1', '--output', str(self.input)])
        self.assertEqual(self.input.read_bytes(), original)
        sample.assert_not_called()

    def test_incomplete_metrics_exit_two_without_fake_capacity_claim(self):
        token = self.directory / 'token'
        token.write_text('A' * 48, encoding='utf-8')
        observation = bench.project_health(health_payload())
        observation['metrics_complete'] = False
        with patch.object(bench, 'sample', side_effect=BenchmarkMatrixTests().matching), \
             patch.object(bench, 'health_snapshot', return_value=observation), contextlib.redirect_stdout(io.StringIO()):
            status = bench.main(['--proxies', str(self.input), '--counts', '1,2', '--output', str(self.output),
                                 '--health-url', 'http://127.0.0.1:7070/api/proxy/health', '--token-file', str(token)])
        self.assertEqual(status, 2)
        self.assertFalse(json.loads(self.output.read_text())['metrics_complete'])


if __name__ == '__main__':
    unittest.main()
