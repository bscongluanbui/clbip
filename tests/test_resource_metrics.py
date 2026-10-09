"""Resource observation fixtures; no Docker, NIC, subprocess, or host changes."""
import copy
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import resource_metrics as metrics


HEADER = '  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n'


def tcp_line(port, state='01', address='00000000'):
    return f'  0: {address}:{port:04X} 00000000:01BB {state} 00000000:00000000 00:00000000 00000000 0 0 123 1\n'


class ResourceMetricsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.proc, self.cg = self.root / 'proc', self.root / 'cgroup'
        (self.proc / 'self' / 'fd').mkdir(parents=True)
        (self.proc / 'net').mkdir()
        self.cg.mkdir()
        self.now = 100.0
        self.proxies = [{'port': 10001, 'protocol': 'http'}, {'port': 10002, 'protocol': 'dual', 'socks_port': 20002}]
        self.write(self.proc / 'self' / 'cgroup', '0::/\n')
        self.mount(self.cg)
        self.write(self.proc / 'self' / 'status', 'VmRSS:\t2048 kB\nThreads:\t5\n')
        self.write(self.proc / 'self' / 'limits', 'Max open files            65535                65535                files\n')
        for name in ('0', '1', '2'):
            self.write(self.proc / 'self' / 'fd' / name, '')
        self.write(self.proc / 'net' / 'tcp', HEADER + tcp_line(10001, '0A') + tcp_line(10001) + tcp_line(10001, '08') + tcp_line(2222))
        self.write(self.proc / 'net' / 'tcp6', HEADER + tcp_line(20002, '01', '0' * 32))
        self.v2()
        self.sampler = self.make_sampler()

    @staticmethod
    def write(path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='ascii')

    def mount(self, mountpoint, root='/', version=2, controllers='rw'):
        self.write(self.proc / 'self' / 'mountinfo',
                   f'29 23 0:26 {root} {mountpoint.as_posix()} rw - cgroup{2 if version == 2 else ""} cgroup {controllers}\n')

    def v2(self, directory=None, current=1024, limit='4096', events=7, memory=256 * 1024**2, memory_limit=1024**3):
        directory = directory or self.cg
        for name, value in (('pids.current', current), ('pids.max', limit), ('pids.events', f'max {events}\n'),
                            ('pids.peak', current + 8), ('memory.current', memory), ('memory.max', memory_limit)):
            self.write(directory / name, str(value))

    def make_sampler(self):
        return metrics.ResourceMetricsSampler(proc_root=self.proc, cgroup_root=self.cg,
                                             clock=lambda: self.now + 1000, monotonic=lambda: self.now)

    def sample(self, **kwargs):
        return self.sampler.collect(self.proxies, {'rss_bytes': 9000, 'fd_count': 12, 'process_count': 4}, **kwargs)

    def test_v2_fields_and_listener_port_scope(self):
        result = self.sample(configured_limit=8192)
        self.assertEqual(result['observation'], 'live')
        self.assertFalse(result['cached'])
        self.assertEqual(result['observed_at'], 1100)
        self.assertEqual(result['threads']['current'], 1024)
        self.assertEqual(result['threads']['limit'], 4096)
        self.assertEqual(result['threads']['configured_limit'], 4096)
        self.assertEqual(result['threads']['requested_limit'], 8192)
        self.assertEqual(result['threads']['utilization_percent'], 25)
        self.assertEqual(result['threads']['peak'], 1032)
        self.assertEqual(result['threads']['peak_source'], 'cgroup')
        self.assertEqual(result['threads']['events_max'], 7)
        self.assertIsNone(result['threads']['events_max_delta'])
        self.assertEqual(result['memory']['current_bytes'], 256 * 1024**2)
        self.assertEqual(result['memory']['utilization_percent'], 25)
        self.assertEqual(result['worker']['rss_bytes'], 2048 * 1024)
        self.assertEqual(result['worker']['thread_count'], 5)
        self.assertEqual(result['worker']['fd_count'], 3)
        self.assertEqual(result['worker']['fd_limit'], 65535)
        self.assertEqual(result['engine']['fd_count'], 12)
        self.assertEqual(result['sockets']['established'], 2)
        self.assertEqual(result['sockets']['close_wait'], 1)
        self.assertEqual(result['sockets']['listen'], 1)
        self.assertEqual(result['sockets']['total'], 3)
        self.assertNotIn('2222', result['sockets']['by_port'])
        self.assertIsNone(result['sockets']['oldest_close_wait_seconds'])
        self.assertEqual(result['alerts'], [])
        self.assertEqual(result['errors'], [])

    def test_visible_ancestor_limit_beats_leaf(self):
        child = self.cg / 'tenant' / 'worker'
        self.v2(child, current=100, limit=4096)
        self.write(self.cg / 'tenant' / 'pids.max', '2000')
        self.write(self.cg / 'pids.max', '1829')
        self.write(self.cg / 'memory.max', '536870912')
        self.write(self.proc / 'self' / 'cgroup', '0::/tenant/worker\n')
        result = self.sample()
        self.assertEqual(result['threads']['current'], 100)
        self.assertEqual(result['threads']['configured_limit'], 4096)
        self.assertEqual(result['threads']['limit'], 1829)
        self.assertEqual(result['memory']['limit_bytes'], 536870912)
        self.assertEqual(result['threads']['limit_visibility'], 'visible_ancestors_only')

    def test_mount_root_mapping_and_namespace_root_fallback(self):
        self.mount(self.cg, root='/docker/fixture')
        self.write(self.proc / 'self' / 'cgroup', '0::/docker/fixture\n')
        self.assertEqual(self.sample()['threads']['current'], 1024)
        self.write(self.proc / 'self' / 'cgroup', '0::/\n')
        self.assertEqual(self.sample(force=True)['threads']['current'], 1024)

    def test_cgroup_namespace_unmapped_parent_fallback_stays_on_mountroot(self):
        self.write(self.proc / 'self' / 'cgroup', '0::/../../docker/fixture\n')
        self.assertEqual(self.sample()['threads']['current'], 1024)

    def test_missing_mapped_leaf_does_not_mislabel_hostroot_as_worker(self):
        self.write(self.proc / 'self' / 'cgroup', '0::/missing-worker\n')
        result = self.sample()
        self.assertIsNone(result['threads']['current'])
        self.assertIsNone(result['memory']['current_bytes'])

    def test_no_mountinfo_uses_standard_cgroup_mount_fallback(self):
        (self.proc / 'self' / 'mountinfo').unlink()
        self.assertEqual(self.sample()['threads']['current'], 1024)

    def test_unlimited_limits_are_not_a_fake_zero(self):
        self.write(self.cg / 'pids.max', 'max')
        self.write(self.cg / 'memory.max', 'max')
        result = self.sample()
        self.assertIsNone(result['threads']['limit'])
        self.assertTrue(result['threads']['limit_observed'])
        self.assertIsNone(result['threads']['utilization_percent'])
        self.assertEqual(result['threads']['level'], 'ok')
        self.assertIsNone(result['memory']['limit_bytes'])
        self.assertEqual(result['memory']['level'], 'ok')

    def test_optional_peak_falls_back_to_observed_peak_and_never_claims_kernel_peak(self):
        (self.cg / 'pids.peak').unlink()
        self.assertEqual(self.sample()['threads']['peak_source'], 'sampled')
        self.write(self.cg / 'pids.current', '1100')
        self.assertEqual(self.sample(force=True)['threads']['peak'], 1100)
        self.write(self.cg / 'pids.current', '1000')
        self.assertEqual(self.sample(force=True)['threads']['peak'], 1100)

    def test_events_delta_counter_reset_and_missing_observation(self):
        self.sample()
        self.write(self.cg / 'pids.events', 'max 10\n')
        sample = self.sample(force=True)
        self.assertEqual(sample['threads']['events_max_delta'], 3)
        self.assertIn('threads_denied', [item['code'] for item in sample['alerts']])
        self.write(self.cg / 'pids.events', 'max 1\n')
        sample = self.sample(force=True)
        self.assertTrue(sample['threads']['counter_reset'])
        self.assertIsNone(sample['threads']['events_max_delta'])
        (self.cg / 'pids.events').unlink()
        self.assertIsNone(self.sample(force=True)['threads']['events_max'])
        self.write(self.cg / 'pids.events', 'max 8\n')
        self.assertIsNone(self.sample(force=True)['threads']['events_max_delta'])

    def test_event_history_resets_on_cgroup_identity_change(self):
        self.sample()
        self.v2(self.cg / 'new', events=100)
        self.write(self.proc / 'self' / 'cgroup', '0::/new\n')
        self.assertIsNone(self.sample(force=True)['threads']['events_max_delta'])

    def test_thresholds_and_zero_limit_do_not_divide_by_zero(self):
        for current, limit, expected in ((79, 100, 'ok'), (80, 100, 'warning'),
                                         (90, 100, 'critical'), (101, 100, 'critical'), (1, 0, 'critical')):
            with self.subTest(current=current, limit=limit):
                self.write(self.cg / 'pids.current', str(current))
                self.write(self.cg / 'pids.max', str(limit))
                self.assertEqual(self.sample(force=True)['threads']['level'], expected)

    def test_invalid_counter_remains_null_with_unavailable_level(self):
        for value in ('-1', 'abc', '3.5', ''):
            with self.subTest(value=value):
                self.write(self.cg / 'pids.current', value)
                result = self.sample(force=True)
                self.assertIsNone(result['threads']['current'])
                self.assertEqual(result['threads']['level'], 'unavailable')
                self.assertTrue(result['threads']['errors'])

    def test_invalid_limit_is_not_misreported_as_unlimited(self):
        self.write(self.cg / 'pids.max', 'unknown')
        result = self.sample()
        self.assertIsNone(result['threads']['limit'])
        self.assertFalse(result['threads']['limit_observed'])
        self.assertEqual(result['threads']['level'], 'unavailable')

    def test_cache_ttl_returns_deepcopies_and_updates_passed_engine_only(self):
        result = self.sample(configured_limit=4096)
        self.write(self.cg / 'pids.current', '4000')
        result['threads']['current'] = -1
        result['engine']['fd_count'] = -1
        self.now += 4
        with patch.object(self.sampler, '_observe', wraps=self.sampler._observe) as observe:
            cached = self.sampler.collect(self.proxies, {'fd_count': 20}, configured_limit=8192)
            observe.assert_not_called()
            self.assertEqual(cached['threads']['current'], 1024)
            self.assertEqual(cached['threads']['requested_limit'], 8192)
            self.assertEqual(cached['engine']['fd_count'], 20)
            self.assertTrue(cached['cached'])
            self.assertEqual(cached['observation'], 'cached')
            self.now += 2
            self.assertEqual(self.sample()['threads']['current'], 4000)
            self.assertEqual(observe.call_count, 1)

    def test_cache_does_not_recompute_denial_delta_on_poll(self):
        self.sample()
        self.write(self.cg / 'pids.events', 'max 9\n')
        result = self.sample(force=True)
        self.assertEqual(result['threads']['events_max_delta'], 2)
        self.assertEqual(self.sample()['threads']['events_max_delta'], 2)
        self.now += 6
        self.assertEqual(self.sample()['threads']['events_max_delta'], 0)

    def test_pool_port_changes_invalidate_socket_cache(self):
        self.sample()
        result = self.sampler.collect([{'port': 2222}])
        self.assertFalse(result['cached'])
        self.assertEqual(result['sockets']['established'], 1)
        self.assertNotIn('10001', result['sockets']['by_port'])

    def test_contention_never_waits_or_starts_second_observation(self):
        self.sample()
        self.sampler._lock.acquire()
        self.addCleanup(self.sampler._lock.release)
        with patch.object(self.sampler, '_observe') as observe:
            self.assertTrue(self.sample(force=True)['cached'])
            result = self.sampler.collect([{'port': 4444}], force=True)
            observe.assert_not_called()
        self.assertEqual(result['observation'], 'unavailable')
        self.assertIsNone(result['sockets']['total'])

    def test_v1_pids_and_memory_controllers(self):
        pids, memory = self.root / 'v1pids', self.root / 'v1memory'
        self.write(pids / 'group' / 'pids.current', '222')
        self.write(pids / 'group' / 'pids.max', '300')
        self.write(pids / 'group' / 'pids.events', 'max 4\n')
        self.write(pids / 'pids.max', '250')
        self.write(memory / 'group' / 'memory.usage_in_bytes', '1000')
        self.write(memory / 'group' / 'memory.limit_in_bytes', str((1 << 63) - 4096))
        self.write(memory / 'memory.limit_in_bytes', '10000')
        self.write(self.proc / 'self' / 'cgroup', '5:pids:/group\n6:memory:/group\n')
        self.write(self.proc / 'self' / 'mountinfo',
                   f'29 23 0:26 / {pids.as_posix()} rw - cgroup cgroup rw,pids\n'
                   f'30 23 0:27 / {memory.as_posix()} rw - cgroup cgroup rw,memory\n')
        result = self.sample()
        self.assertEqual(result['threads']['cgroup_version'], 1)
        self.assertEqual(result['threads']['current'], 222)
        self.assertEqual(result['threads']['limit'], 250)
        self.assertEqual(result['threads']['configured_limit'], 300)
        self.assertIsNone(result['memory']['configured_limit_bytes'])
        self.assertEqual(result['memory']['limit_bytes'], 10000)

    def test_empty_pool_is_known_zero_without_tcp_files(self):
        (self.proc / 'net' / 'tcp').unlink()
        (self.proc / 'net' / 'tcp6').unlink()
        result = self.sampler.collect([])
        self.assertEqual(result['sockets']['total'], 0)
        self.assertEqual(result['sockets']['errors'], [])

    def test_missing_one_tcp_table_does_not_publish_partial_zero(self):
        (self.proc / 'net' / 'tcp6').unlink()
        result = self.sample()
        self.assertIsNone(result['sockets']['total'])
        self.assertIsNone(result['sockets']['established'])
        self.assertIsNone(result['sockets']['by_port'])
        self.assertTrue(result['sockets']['errors'])

    def test_malformed_or_oversized_tcp_table_is_unavailable(self):
        for value in ('bad header\n', HEADER + 'short row\n', HEADER + ' ' * (metrics._MAX_SOCKET_BYTES + 1)):
            with self.subTest(size=len(value)):
                self.write(self.proc / 'net' / 'tcp', value)
                self.assertIsNone(self.sample(force=True)['sockets']['total'])

    def test_missing_proc_cgroup_reports_null_without_commands(self):
        (self.proc / 'self' / 'cgroup').unlink()
        with patch('subprocess.run', side_effect=AssertionError('No process may be started')):
            result = self.sample()
        self.assertIsNone(result['threads']['current'])
        self.assertIsNone(result['threads']['events_max_delta'])
        self.assertEqual(result['threads']['level'], 'unavailable')
        self.assertTrue(result['errors'])

    def test_ports_are_strict_and_dual_uses_default_socks_port(self):
        self.assertEqual(metrics._ports([{'port': 10001, 'protocol': 'dual'}, {'port': '10002'},
                                        {'port': True, 'protocol': 'dual'}, {'port': 65536}, None]), (10001, 20001))

    def test_engine_metrics_are_deepcopied(self):
        source = {'rss_bytes': 10, 'fd_count': 1, 'errors': ['fixture']}
        original = copy.deepcopy(source)
        self.sampler.collect(self.proxies, source)['engine']['errors'].append('new')
        self.assertEqual(source, original)

    def test_module_wrapper_uses_default_sampler_and_forwards_requested_limit(self):
        with patch.object(metrics, '_DEFAULT_SAMPLER', self.sampler):
            self.assertEqual(metrics.collect_resource_metrics(self.proxies, configured_limit=4096)['threads']['requested_limit'], 4096)


if __name__ == '__main__':
    unittest.main()
