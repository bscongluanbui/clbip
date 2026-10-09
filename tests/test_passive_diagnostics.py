"""Offline counters: initial/missing/reset are null; no process/socket mutation."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from passive_diagnostics import PassiveDiagnosticsSampler


class PassiveDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.proc, self.cg, self.net = [self.root / n for n in ('proc', 'cg', 'net')]
        self.now = 10.0
        self.write(self.proc / 'self/cgroup', '0::/\n')
        self.cpu(1000000, 3, 100000)
        self.nic(1000000, 2000000)
        self.tcp(10, 20, 30, 40)
        self.write(self.net / 'eth0/speed', '100\n')
        self.sampler = PassiveDiagnosticsSampler(proc_root=self.proc, cgroup_root=self.cg,
            net_root=self.net, monotonic=lambda: self.now)

    @staticmethod
    def write(path, text):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding='ascii')

    def cpu(self, usage, count=3, throttled=100000):
        self.write(self.cg / 'cpu.stat', f'usage_usec {usage}\nnr_throttled {count}\nthrottled_usec {throttled}\n')

    def nic(self, rx, tx, drops=0):
        self.write(self.proc / 'net/dev', f'Inter-| Receive |Transmit\n face |bytes packets errs drop fifo frame compressed multicast | bytes packets errs drop fifo colls carrier compressed\neth0: {rx} 1 0 {drops} 0 0 0 0 {tx} 2 0 {drops} 0 0 0 0\n')

    def tcp(self, overflow, drops, syn, retrans):
        self.write(self.proc / 'net/netstat', f'TcpExt: ListenOverflows ListenDrops TCPSynRetrans\nTcpExt: {overflow} {drops} {syn}\n')
        self.write(self.proc / 'net/snmp', f'Tcp: RetransSegs\nTcp: {retrans}\n')

    def test_first_sample_is_not_zero_and_scopes_are_explicit(self):
        s = self.sampler.collect('eth0')
        self.assertTrue(s['cpu']['available'])
        self.assertIsNone(s['cpu']['usage_percent_one_core'])
        self.assertIsNone(s['cpu']['throttled_events_delta'])
        self.assertEqual(s['cpu']['scope'], 'worker_cgroup')
        self.assertIsNone(s['network']['interfaces'][0]['rx_mbps'])
        self.assertIsNone(s['network']['tcp']['listen_overflows_delta'])
        self.assertEqual(s['network']['scope'], 'host_network_namespace')
        self.assertEqual(s['network']['interfaces'][0]['speed_mbps'], 100)

    def test_deltas_units_cpu_one_core_and_no_active_io(self):
        self.sampler.collect('eth0')
        self.now += 5
        self.cpu(11000000, 5, 400000)
        self.nic(2000000, 4000000, 2)
        self.tcp(12, 23, 34, 45)
        with patch('subprocess.run', side_effect=AssertionError('No command')), patch('socket.socket', side_effect=AssertionError('No socket')):
            s = self.sampler.collect('eth0')
        self.assertEqual(s['cpu']['usage_percent_one_core'], 200)
        self.assertEqual(s['cpu']['throttled_events_delta'], 2)
        self.assertEqual(s['cpu']['throttled_seconds_delta'], .3)
        self.assertEqual(s['network']['interfaces'][0]['rx_mbps'], 1.6)
        self.assertEqual(s['network']['interfaces'][0]['tx_mbps'], 3.2)
        self.assertEqual(s['network']['interfaces'][0]['rx_dropped_delta'], 2)
        self.assertEqual(s['network']['tcp']['listen_overflows_delta'], 2)
        self.assertEqual(s['network']['tcp']['retrans_segments_delta'], 5)

    def test_cache_does_not_advance_delta_or_return_shared_mutable_data(self):
        s = self.sampler.collect('eth0')
        s['cpu']['available'] = False
        self.now += 4
        self.cpu(9999999)
        s = self.sampler.collect('eth0')
        self.assertTrue(s['cached'])
        self.assertTrue(s['cpu']['available'])
        self.assertIsNone(s['cpu']['usage_percent_one_core'])
        self.now += 1
        self.assertFalse(self.sampler.collect('eth0')['cached'])

    def test_counter_reset_nulls_affected_deltas_then_recovers(self):
        self.sampler.collect('eth0')
        self.now += 5
        self.cpu(10, 0, 0)
        self.nic(100, 200)
        self.tcp(0, 0, 0, 0)
        s = self.sampler.collect('eth0')
        self.assertTrue(s['cpu']['counter_reset'])
        self.assertTrue(s['network']['counter_reset'])
        self.assertIsNone(s['cpu']['usage_percent_one_core'])
        self.assertIsNone(s['network']['interfaces'][0]['rx_mbps'])
        self.assertIsNone(s['network']['tcp']['listen_drops_delta'])
        self.now += 5
        self.cpu(1000010)
        self.nic(1100, 2200)
        self.tcp(1, 1, 1, 1)
        s = self.sampler.collect('eth0')
        self.assertEqual(s['cpu']['usage_percent_one_core'], 20)
        self.assertEqual(s['network']['tcp']['listen_drops_delta'], 1)

    def test_missing_counters_are_unavailable_not_zero(self):
        (self.cg / 'cpu.stat').unlink()
        (self.proc / 'net/dev').unlink()
        (self.proc / 'net/netstat').unlink()
        (self.proc / 'net/snmp').unlink()
        s = self.sampler.collect('eth0')
        self.assertFalse(s['cpu']['available'])
        self.assertFalse(s['network']['available'])
        self.assertIsNone(s['network']['tcp']['retrans_segments_delta'])
        self.assertTrue(s['cpu']['errors'])

    def test_partial_tcp_missing_does_not_erase_valid_nic(self):
        (self.proc / 'net/netstat').unlink()
        s = self.sampler.collect('eth0')
        self.assertTrue(s['network']['available'])
        self.assertIsNone(s['network']['tcp']['listen_overflows_delta'])
        self.assertEqual(s['network']['interfaces'][0]['interface'], 'eth0')

    def test_invalid_interface_cannot_escape_net_root(self):
        for name in ('../eth0', '.', '..', '', '-bad', 'eth0\n'):
            self.assertFalse(self.sampler.collect(name)['network']['available'])

    def test_lock_contention_never_blocks_or_probes(self):
        self.sampler._lock.acquire()
        try:
            s = self.sampler.collect('eth0')
            self.assertFalse(s['network']['available'])
            self.assertIn('in progress', s['network']['errors'][0])
        finally:
            self.sampler._lock.release()

    def test_cgroup_switch_does_not_compare_to_previous_worker(self):
        self.sampler.collect('eth0')
        self.write(self.cg / 'other/cpu.stat', 'usage_usec 3000000\nnr_throttled 0\nthrottled_usec 0\n')
        self.write(self.proc / 'self/cgroup', '0::/other\n')
        self.now += 5
        self.assertIsNone(self.sampler.collect('eth0')['cpu']['usage_percent_one_core'])

    def test_v1_cpuacct_nanoseconds_and_throttle_nanoseconds(self):
        (self.cg / 'cpu.stat').unlink()
        cpu = self.cg / 'cpu'
        acct = self.cg / 'acct'
        self.write(cpu / 'cpu.stat', 'nr_throttled 2\nthrottled_time 100000000\n')
        self.write(acct / 'cpuacct.usage', '1000000000\n')
        self.write(self.proc / 'self/cgroup', '2:cpu:/\n3:cpuacct:/\n')
        self.write(self.proc / 'self/mountinfo', f'1 0 0:1 / {cpu.as_posix()} rw - cgroup cgroup rw,cpu\n2 0 0:2 / {acct.as_posix()} rw - cgroup cgroup rw,cpuacct\n')
        self.sampler.collect('eth0')
        self.now += 5
        self.write(acct / 'cpuacct.usage', '3500000000\n')
        self.write(cpu / 'cpu.stat', 'nr_throttled 3\nthrottled_time 400000000\n')
        s = self.sampler.collect('eth0')
        self.assertEqual(s['cpu']['usage_percent_one_core'], 50)
        self.assertEqual(s['cpu']['throttled_seconds_delta'], .3)


if __name__ == '__main__':
    unittest.main()
