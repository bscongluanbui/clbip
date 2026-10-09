"""Passive, cached Linux resource observation. No commands or runtime mutation.

PID cgroups count tasks (including threads), not just process IDs. Limits are
the minimum of readable ancestors; hidden host ancestors remain unknowable.
TCP observations cover the pool's incoming listener ports only. CLOSE-WAIT is
a state, not proof of a leak, and /proc/net/tcp does not provide socket age.
"""
import copy
from pathlib import Path, PurePosixPath
import re
import threading
import time


_STATES = {'01': 'ESTABLISHED', '02': 'SYN_SENT', '03': 'SYN_RECV',
           '04': 'FIN_WAIT1', '05': 'FIN_WAIT2', '06': 'TIME_WAIT',
           '07': 'CLOSE', '08': 'CLOSE_WAIT', '09': 'LAST_ACK',
           '0A': 'LISTEN', '0B': 'CLOSING', '0C': 'NEW_SYN_RECV'}
_MAX_SOCKET_BYTES = 8 * 1024 * 1024


def _ports(proxies):
    result = set()
    for proxy in proxies or []:
        if not isinstance(proxy, dict):
            continue
        values = [proxy.get('port')]
        if proxy.get('protocol') == 'dual':
            port = proxy.get('port')
            values.append(proxy.get('socks_port', port + 10000)
                          if isinstance(port, int) and not isinstance(port, bool) else proxy.get('socks_port'))
        for value in values:
            if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535:
                result.add(value)
    return tuple(sorted(result))


def _text(path, limit=65536):
    with path.open('r', encoding='ascii') as handle:
        value = handle.read(limit + 1)
    if len(value) > limit:
        raise ValueError('Observation exceeds the read budget')
    return value


def _number(path, *, unlimited=False):
    value = _text(path).strip()
    if unlimited and value == 'max':
        return None
    if not re.fullmatch(r'[0-9]+', value):
        raise ValueError('Counter is not a nonnegative integer')
    return int(value)


def _unescape_mount(value):
    return re.sub(r'\\(040|011|012|134)', lambda m: chr(int(m.group(1), 8)), value)


def _relative(membership, mount_root):
    path, root = PurePosixPath(membership), PurePosixPath(mount_root)
    if '..' in path.parts or '..' in root.parts or not path.is_absolute() or not root.is_absolute():
        return None
    try:
        return path.relative_to(root)
    except ValueError:
        return None


def _locations(proc_root, fallback_root):
    """Find namespace-visible controller directories without assuming host paths."""
    groups = []
    for line in _text(proc_root / 'self' / 'cgroup').splitlines():
        fields = line.split(':', 2)
        if len(fields) != 3:
            continue
        groups.append((2 if fields[0] == '0' and not fields[1] else 1,
                       set(fields[1].split(',')), fields[2]))
    mounts = []
    try:
        for line in _text(proc_root / 'self' / 'mountinfo', 1024 * 1024).splitlines():
            left, sep, right = line.partition(' - ')
            before, after = left.split(), right.split()
            if not sep or len(before) < 5 or len(after) < 3 or after[0] not in ('cgroup', 'cgroup2'):
                continue
            mounts.append((2 if after[0] == 'cgroup2' else 1,
                           _unescape_mount(before[3]), Path(_unescape_mount(before[4])),
                           set(after[2].split(','))))
    except (OSError, ValueError, UnicodeError):
        pass
    found = {}
    for version, controllers, membership in groups:
        for mount_version, root, mountpoint, mount_controllers in mounts:
            if version != mount_version:
                continue
            relevant = {'pids', 'memory', 'cpu'} if version == 2 else controllers & mount_controllers & {'pids', 'memory', 'cpu', 'cpuacct'}
            if not relevant:
                continue
            relative = _relative(membership, root)
            # A cgroup namespace can expose '/' while mountinfo retains the host
            # root, or mask the host hierarchy completely. Use the mount root
            # only when the controller counter is actually readable there.
            candidates = [mountpoint / str(relative)] if relative is not None else []
            if relative is None or str(relative) == '.':
                candidates.append(mountpoint)
            for controller in relevant:
                filename = {'pids': 'pids.current', 'memory': 'memory.current' if version == 2 else 'memory.usage_in_bytes',
                            'cpu': 'cpu.stat', 'cpuacct': 'cpuacct.usage'}[controller]
                for candidate in candidates:
                    if (candidate / filename).is_file():
                        found[controller] = (candidate, mountpoint, version)
                        break
        if version == 2:
            relative = _relative(membership, '/')
            candidates = [fallback_root / str(relative)] if relative is not None else []
            if relative is None or str(relative) == '.':
                candidates.append(fallback_root)
            for controller, filename in (('pids', 'pids.current'), ('memory', 'memory.current'), ('cpu', 'cpu.stat')):
                if controller not in found:
                    for candidate in candidates:
                        if (candidate / filename).is_file():
                            found[controller] = (candidate, fallback_root, 2)
                            break
    return found


def _limits(leaf, boundary, filename, *, v1_memory=False):
    leaf_value = _number(leaf / filename, unlimited=True)
    limits = []
    node = leaf
    while True:
        try:
            value = _number(node / filename, unlimited=True)
            # The v1 unlimited memory sentinel is page-rounded LONG_MAX.
            if value is not None and not (v1_memory and value >= (1 << 60)):
                limits.append(value)
        except (OSError, ValueError, UnicodeError):
            if node == leaf:
                raise
        if node == boundary or node.parent == node:
            break
        node = node.parent
    if v1_memory and leaf_value is not None and leaf_value >= (1 << 60):
        leaf_value = None
    return leaf_value, min(limits) if limits else None


def _level(current, limit, observed=False):
    if current is None or not observed:
        return None, 'unavailable'
    if limit is None:
        return None, 'ok'
    ratio = round(100 * current / limit, 2) if limit > 0 else (100.0 if current else 0.0)
    return ratio, 'critical' if ratio >= 90 else ('warning' if ratio >= 80 else 'ok')


def _worker(proc_root):
    result = {'rss_bytes': None, 'fd_count': None, 'thread_count': None, 'fd_limit': None, 'errors': []}
    try:
        status = _text(proc_root / 'self' / 'status')
        rss = re.search(r'^VmRSS:\s*([0-9]+)\s+kB\s*$', status, re.MULTILINE)
        threads = re.search(r'^Threads:\s*([0-9]+)\s*$', status, re.MULTILINE)
        result['rss_bytes'] = int(rss.group(1)) * 1024 if rss else None
        result['thread_count'] = int(threads.group(1)) if threads else None
        result['fd_count'] = sum(1 for _ in (proc_root / 'self' / 'fd').iterdir())
    except (OSError, ValueError, UnicodeError):
        result['errors'].append('Worker process observation unavailable')
    try:
        match = re.search(r'^Max open files\s+(\S+)\s+', _text(proc_root / 'self' / 'limits'), re.MULTILINE)
        if match and match.group(1).isdigit():
            result['fd_limit'] = int(match.group(1))
    except (OSError, ValueError, UnicodeError):
        result['errors'].append('Worker FD limit observation unavailable')
    return result


def _sockets(proc_root, ports):
    result = {'established': 0, 'close_wait': 0, 'total': 0, 'listen': 0, 'states': {},
              'by_port': {}, 'oldest_close_wait_seconds': None, 'scope': 'pool_listener_ports',
              'age_observation': 'not_available_in_proc_net_tcp', 'errors': []}
    if not ports:
        return result
    wanted = set(ports)
    try:
        for filename in ('tcp', 'tcp6'):
            lines = _text(proc_root / 'net' / filename, _MAX_SOCKET_BYTES).splitlines()
            if not lines or 'local_address' not in lines[0]:
                raise ValueError('Invalid TCP table')
            for line in lines[1:]:
                fields = line.split()
                if len(fields) < 10:
                    raise ValueError('Incomplete TCP table')
                port = int(fields[1].rsplit(':', 1)[1], 16)
                if port not in wanted:
                    continue
                state = _STATES.get(fields[3], 'UNKNOWN')
                result['states'][state] = result['states'].get(state, 0) + 1
                per_port = result['by_port'].setdefault(str(port), {'established': 0, 'close_wait': 0,
                                                                 'total': 0, 'listen': 0})
                key = {'ESTABLISHED': 'established', 'CLOSE_WAIT': 'close_wait', 'LISTEN': 'listen'}.get(state)
                if key:
                    result[key] += 1
                    per_port[key] += 1
                if state != 'LISTEN':
                    result['total'] += 1
                    per_port['total'] += 1
    except (OSError, ValueError, IndexError, UnicodeError):
        for key in ('established', 'close_wait', 'total', 'listen', 'states', 'by_port'):
            result[key] = None
        result['errors'].append('Pool TCP observation incomplete or unavailable')
    return result


class ResourceMetricsSampler:
    """At most one bounded /proc snapshot per TTL; contenders never wait on IO."""
    def __init__(self, ttl_seconds=5.0, *, proc_root='/proc', cgroup_root='/sys/fs/cgroup',
                 clock=time.time, monotonic=time.monotonic):
        self.ttl_seconds = max(1.0, min(float(ttl_seconds), 60.0))
        self.proc_root, self.cgroup_root = Path(proc_root), Path(cgroup_root)
        self.clock, self.monotonic = clock, monotonic
        self._lock = threading.Lock()
        self._cached, self._cache_key, self._collected_at = None, None, float('-inf')
        self._event_identity, self._last_events, self._sampled_peak = None, None, None

    @staticmethod
    def _with_engine(sample, engine_metrics, cached, configured_limit=None):
        result = copy.deepcopy(sample)
        result['engine'] = copy.deepcopy(engine_metrics) if isinstance(engine_metrics, dict) else {
            'rss_bytes': None, 'fd_count': None, 'process_count': None,
            'errors': ['Owned proxy process observation not supplied']}
        result['cached'] = cached
        result['threads']['requested_limit'] = configured_limit
        if cached and result['observation'] == 'live':
            result['observation'] = 'cached'
        return result

    def collect(self, proxies=None, engine_metrics=None, *, force=False, configured_limit=None):
        key, now = _ports(proxies), self.monotonic()
        if not force and self._cached is not None and key == self._cache_key and now - self._collected_at < self.ttl_seconds:
            return self._with_engine(self._cached, engine_metrics, True, configured_limit)
        if not self._lock.acquire(blocking=False):
            if self._cached is not None and key == self._cache_key:
                return self._with_engine(self._cached, engine_metrics, True, configured_limit)
            result = self._empty()
            result['errors'].append('Resource observation in progress')
            return self._with_engine(result, engine_metrics, False, configured_limit)
        try:
            # Recheck after acquiring; another collector may have just finished.
            if not force and self._cached is not None and key == self._cache_key and now - self._collected_at < self.ttl_seconds:
                return self._with_engine(self._cached, engine_metrics, True, configured_limit)
            sample = self._observe(key)
            self._cached, self._cache_key, self._collected_at = sample, key, self.monotonic()
            return self._with_engine(sample, engine_metrics, False, configured_limit)
        finally:
            self._lock.release()

    def _empty(self):
        return {'observed_at': self.clock(), 'observation': 'unavailable',
                'cache_ttl_seconds': self.ttl_seconds, 'errors': [], 'alerts': [],
                'threads': {'current': None, 'limit': None, 'configured_limit': None, 'peak': None,
                            'peak_source': None, 'events_max': None, 'events_max_delta': None,
                            'counter_reset': False, 'utilization_percent': None, 'level': 'unavailable',
                            'cgroup_version': None, 'scope': 'worker_cgroup',
                            'limit_visibility': 'visible_ancestors_only', 'limit_observed': False, 'errors': []},
                'memory': {'current_bytes': None, 'limit_bytes': None, 'configured_limit_bytes': None,
                           'utilization_percent': None, 'level': 'unavailable',
                           'scope': 'worker_cgroup', 'limit_observed': False, 'errors': []},
                'worker': {'rss_bytes': None, 'fd_count': None, 'thread_count': None, 'fd_limit': None, 'errors': []},
                'sockets': {'established': None, 'close_wait': None, 'total': None, 'listen': None,
                            'states': None, 'by_port': None, 'oldest_close_wait_seconds': None,
                            'scope': 'pool_listener_ports', 'age_observation': 'not_available_in_proc_net_tcp', 'errors': []}}

    def _observe(self, ports):
        result = self._empty()
        try:
            locations = _locations(self.proc_root, self.cgroup_root)
        except (OSError, ValueError, UnicodeError):
            locations = {}
        threads, memory = result['threads'], result['memory']
        if 'pids' in locations:
            leaf, boundary, version = locations['pids']
            threads['cgroup_version'] = version
            identity = (str(leaf), version)
            if identity != self._event_identity:
                self._last_events, self._sampled_peak = None, None
                self._event_identity = identity
            try:
                threads['current'] = _number(leaf / 'pids.current')
                self._sampled_peak = max(self._sampled_peak or 0, threads['current'])
                threads['configured_limit'], threads['limit'] = _limits(leaf, boundary, 'pids.max')
                threads['limit_observed'] = True
            except (OSError, ValueError, UnicodeError):
                threads['errors'].append('Thread counter or limit observation unavailable')
            try:
                threads['peak'] = _number(leaf / 'pids.peak')
                threads['peak_source'] = 'cgroup'
            except (OSError, ValueError, UnicodeError):
                threads['peak'], threads['peak_source'] = self._sampled_peak, 'sampled'
            try:
                events = dict(line.split() for line in _text(leaf / 'pids.events').splitlines())
                value = events['max']
                if not value.isdigit():
                    raise ValueError('Invalid denial counter')
                threads['events_max'] = int(value)
                if self._last_events is not None:
                    if threads['events_max'] >= self._last_events:
                        threads['events_max_delta'] = threads['events_max'] - self._last_events
                    else:
                        threads['counter_reset'] = True
                self._last_events = threads['events_max']
            except (OSError, ValueError, KeyError, UnicodeError):
                self._last_events = None
                threads['errors'].append('Thread denial counter observation unavailable')
        else:
            threads['errors'].append('PID cgroup observation unavailable')
        threads['utilization_percent'], threads['level'] = _level(threads['current'], threads['limit'], threads['limit_observed'])
        if 'memory' in locations:
            leaf, boundary, version = locations['memory']
            try:
                memory['current_bytes'] = _number(leaf / ('memory.current' if version == 2 else 'memory.usage_in_bytes'))
                memory['configured_limit_bytes'], memory['limit_bytes'] = _limits(
                    leaf, boundary, 'memory.max' if version == 2 else 'memory.limit_in_bytes', v1_memory=version == 1)
                memory['limit_observed'] = True
            except (OSError, ValueError, UnicodeError):
                memory['errors'].append('Memory cgroup observation unavailable')
        else:
            memory['errors'].append('Memory cgroup observation unavailable')
        memory['utilization_percent'], memory['level'] = _level(memory['current_bytes'], memory['limit_bytes'], memory['limit_observed'])
        result['worker'], result['sockets'] = _worker(self.proc_root), _sockets(self.proc_root, ports)
        for name, section in (('threads', threads), ('memory', memory), ('worker', result['worker']), ('sockets', result['sockets'])):
            result['errors'].extend(section['errors'])
            if section.get('level') in ('warning', 'critical'):
                result['alerts'].append({'code': name + '_high', 'level': section['level'],
                                         'message': f'{name}: {section["utilization_percent"]}% of the visible limit'})
        if threads['events_max_delta'] is not None and threads['events_max_delta'] > 0:
            result['alerts'].append({'code': 'threads_denied', 'level': 'critical',
                                     'message': f'{threads["events_max_delta"]} tasks denied since the previous sample'})
        if threads['current'] is not None or memory['current_bytes'] is not None or result['worker']['rss_bytes'] is not None:
            result['observation'] = 'live'
        return result


_DEFAULT_SAMPLER = ResourceMetricsSampler()


def collect_resource_metrics(proxies=None, engine_metrics=None, *, configured_limit=None):
    """Collect (or reuse) a five-second snapshot without launching a process."""
    return _DEFAULT_SAMPLER.collect(proxies, engine_metrics, configured_limit=configured_limit)
