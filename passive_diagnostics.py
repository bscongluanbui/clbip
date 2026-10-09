"""Bounded passive CPU/NIC/TCP deltas; no subprocess, socket or background job.

CPU is worker-cgroup scope; NIC/TCP counters are shared network namespace scope.
The first sample, a reset, or a missing counter produces null, never invented zero.
"""
import copy
from pathlib import Path
import re
import threading
import time

from resource_metrics import _locations, _number, _text


def _pairs(path):
    result = {}
    for line in _text(path).splitlines():
        key, value = line.split()
        if not value.isdigit():
            raise ValueError('Invalid counter')
        result[key] = int(value)
    return result


def _protocol(path, protocol):
    lines = _text(path, 256 * 1024).splitlines()
    for i in range(0, len(lines) - 1, 2):
        names, values = lines[i].split(), lines[i + 1].split()
        if names and names[0] == protocol + ':' and values and values[0] == names[0]:
            if len(names) != len(values):
                raise ValueError('Counter header mismatch')
            return {key: int(value) for key, value in zip(names[1:], values[1:]) if value.isdigit()}
    raise ValueError('Protocol counters absent')


def _delta(current, previous):
    if current is None or previous is None or current < previous:
        return None
    return current - previous


class PassiveDiagnosticsSampler:
    def __init__(self, *, proc_root='/proc', cgroup_root='/sys/fs/cgroup', net_root='/sys/class/net',
                 monotonic=time.monotonic, ttl_seconds=5):
        self.proc, self.cg, self.net = Path(proc_root), Path(cgroup_root), Path(net_root)
        self.monotonic, self.ttl = monotonic, max(1, min(float(ttl_seconds), 60))
        self._lock = threading.Lock()
        self._cached, self._interface, self._at = None, None, float('-inf')
        self._previous_cpu, self._previous_network = None, None

    @staticmethod
    def empty():
        return {
            'cpu': {'available': False, 'usage_percent_one_core': None, 'sample_seconds': None,
                    'throttled_events_delta': None, 'throttled_seconds_delta': None,
                    'counter_reset': False, 'scope': 'worker_cgroup', 'errors': []},
            'network': {'available': False, 'interfaces': [], 'tcp': {}, 'sample_seconds': None,
                        'counter_reset': False, 'scope': 'host_network_namespace',
                        'note': 'NIC/TCP counters include other host applications; NIC drops are not Internet packet loss.',
                        'errors': []}, 'cached': False}

    def collect(self, interface):
        now = self.monotonic()
        if self._cached is not None and interface == self._interface and now - self._at < self.ttl:
            result = copy.deepcopy(self._cached)
            result['cached'] = True
            return result
        if not self._lock.acquire(blocking=False):
            if self._cached is not None and interface == self._interface:
                result = copy.deepcopy(self._cached)
                result['cached'] = True
                return result
            result = self.empty()
            result['network']['errors'].append('Passive observation in progress')
            return result
        try:
            now = self.monotonic()
            if self._cached is not None and interface == self._interface and now - self._at < self.ttl:
                result = copy.deepcopy(self._cached)
                result['cached'] = True
                return result
            result = self.empty()
            self._cpu(result['cpu'], now)
            self._network(result['network'], interface, now)
            self._cached, self._interface, self._at = result, interface, now
            return copy.deepcopy(result)
        finally:
            self._lock.release()

    def _cpu(self, result, now):
        try:
            locations = _locations(self.proc, self.cg)
            leaf, _, version = locations['cpu']
            values = _pairs(leaf / 'cpu.stat')
            usage = values.get('usage_usec') if version == 2 else None
            if version == 1 and 'cpuacct' in locations:
                usage = _number(locations['cpuacct'][0] / 'cpuacct.usage') / 1000
            current = {'identity': (str(leaf), version), 'at': now, 'usage': usage,
                       'throttled': values.get('nr_throttled'),
                       'throttled_us': values.get('throttled_usec') if version == 2 else
                       (values['throttled_time'] / 1000 if 'throttled_time' in values else None)}
            previous = self._previous_cpu
            if previous and previous['identity'] == current['identity'] and now > previous['at']:
                seconds = now - previous['at']
                result['sample_seconds'] = round(seconds, 3)
                du = _delta(usage, previous['usage'])
                dt = _delta(current['throttled_us'], previous['throttled_us'])
                result['usage_percent_one_core'] = round(du / 1e6 / seconds * 100, 2) if du is not None else None
                result['throttled_events_delta'] = _delta(current['throttled'], previous['throttled'])
                result['throttled_seconds_delta'] = round(dt / 1e6, 6) if dt is not None else None
                result['counter_reset'] = any(current[k] is not None and previous[k] is not None and current[k] < previous[k]
                                              for k in ('usage', 'throttled', 'throttled_us'))
            self._previous_cpu = current
            result['available'] = usage is not None
        except (OSError, ValueError, KeyError, UnicodeError):
            self._previous_cpu = None
            result['errors'].append('Worker CPU counters unavailable')

    def _network(self, result, interface, now):
        if not isinstance(interface, str) or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}', interface):
            self._previous_network = None
            result['errors'].append('Interface observation unavailable')
            return
        counters = {}
        try:
            for line in _text(self.proc / 'net' / 'dev', 256 * 1024).splitlines():
                name, sep, fields = line.rpartition(':')
                if sep and name.strip() == interface:
                    nums = fields.split()
                    if len(nums) != 16 or not all(x.isdigit() for x in nums):
                        raise ValueError('Invalid NIC counters')
                    counters = {key: int(nums[index]) for key, index in
                                (('rx_bytes', 0), ('tx_bytes', 8), ('rx_errors', 2), ('tx_errors', 10),
                                 ('rx_dropped', 3), ('tx_dropped', 11))}
                    break
            if not counters:
                raise ValueError('Interface counters absent')
        except (OSError, ValueError, UnicodeError):
            result['errors'].append('NIC counters unavailable')
        tcp = {}
        for filename, protocol, mapping in (
            ('netstat', 'TcpExt', {'ListenOverflows': 'listen_overflows', 'ListenDrops': 'listen_drops', 'TCPSynRetrans': 'syn_retrans'}),
            ('snmp', 'Tcp', {'RetransSegs': 'retrans_segments'})):
            try:
                values = _protocol(self.proc / 'net' / filename, protocol)
                tcp.update({dst: values.get(src) for src, dst in mapping.items()})
            except (OSError, ValueError, UnicodeError):
                result['errors'].append(protocol + ' counters unavailable')
                tcp.update({dst: None for dst in mapping.values()})
        speed = None
        try:
            value = _text(self.net / interface / 'speed').strip()
            if value.isdigit() and int(value) > 0:
                speed = int(value)
        except (OSError, ValueError, UnicodeError):
            pass
        nic = {'interface': interface, 'speed_mbps': speed, 'rx_mbps': None, 'tx_mbps': None,
               **{key + '_delta': None for key in ('rx_errors', 'tx_errors', 'rx_dropped', 'tx_dropped')}}
        result['tcp'] = {key + '_delta': None for key in tcp}
        result['tcp']['totals'] = tcp
        previous = self._previous_network
        if previous and previous['interface'] == interface and now > previous['at']:
            seconds = now - previous['at']
            result['sample_seconds'] = round(seconds, 3)
            for key in counters:
                delta = _delta(counters[key], previous['nic'].get(key))
                if key in ('rx_bytes', 'tx_bytes'):
                    nic[key[:2] + '_mbps'] = round(delta * 8 / seconds / 1e6, 3) if delta is not None else None
                else:
                    nic[key + '_delta'] = delta
            for key in tcp:
                result['tcp'][key + '_delta'] = _delta(tcp[key], previous['tcp'].get(key))
            result['counter_reset'] = any(value is not None and old is not None and value < old
                for value, old in [(v, previous['nic'].get(k)) for k, v in counters.items()] +
                                  [(v, previous['tcp'].get(k)) for k, v in tcp.items()])
        result['interfaces'] = [nic]
        result['available'] = bool(counters) or any(v is not None for v in tcp.values())
        self._previous_network = {'at': now, 'interface': interface, 'nic': counters, 'tcp': tcp}
