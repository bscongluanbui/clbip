"""Bounded, on-demand DNS measurements and privacy-preserving probe history.

DNS probes bypass the host resolver: every UDP/TCP socket connects to a
configured numeric resolver. Repeated-query timing is an observation, not proof
of cache hits. No background monitoring, network/config mutation, or subprocess.
"""
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor
import errno
import ipaddress
import math
import re
import secrets
import socket
import struct
import threading
import time
from urllib.parse import urlsplit


MAX_UDP_BYTES = 4096
MAX_TCP_BYTES = 65535
MAX_RECORDS = 512
RCODES = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN',
          4: 'NOTIMP', 5: 'REFUSED', 6: 'YXDOMAIN', 7: 'YXRRSET',
          8: 'NXRRSET', 9: 'NOTAUTH', 10: 'NOTZONE', 16: 'BADVERS'}


class DNSPacketError(ValueError):
    """An untrusted response did not satisfy the DNS query/packet contract."""


def normalize_domain(value):
    """Canonical hostname only, with no resolver lookup or URL secrets."""
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError('Invalid diagnostic hostname')
    if any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError('Invalid diagnostic hostname')
    if '://' in value:
        try:
            parsed = urlsplit(value)
            if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError('Invalid diagnostic URL')
            if parsed.port not in (None, 443) or parsed.fragment:
                raise ValueError('Invalid diagnostic URL')
            value = parsed.hostname
        except ValueError:
            raise ValueError('Invalid diagnostic URL') from None
    value = value.removesuffix('.')
    try:
        value = value.encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise ValueError('Invalid diagnostic hostname') from None
    if not value or len(value) > 253:
        raise ValueError('Invalid diagnostic hostname')
    for label in value.split('.'):
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label):
            raise ValueError('Invalid diagnostic hostname')
    return value


def parse_resolver(value):
    """Return numeric IP, port and socket family; never call getaddrinfo."""
    if not isinstance(value, str) or not value or len(value) > 128 or '%' in value:
        raise ValueError('Resolver must be a numeric IP[:port]')
    host, port = value, 53
    if value.startswith('['):
        match = re.fullmatch(r'\[([^\]]+)\](?::([0-9]+))?', value)
        if not match:
            raise ValueError('Resolver must be a numeric IP[:port]')
        host, raw_port = match.groups()
        port = int(raw_port) if raw_port is not None else 53
    elif value.count(':') == 1:
        host, raw_port = value.rsplit(':', 1)
        if not re.fullmatch(r'[0-9]+', raw_port):
            raise ValueError('Resolver port is invalid')
        port = int(raw_port)
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        raise ValueError('Resolver must be a numeric IP[:port]') from None
    if not 1 <= port <= 65535 or address.is_unspecified or address.is_multicast:
        raise ValueError('Resolver address/port is invalid')
    if value.startswith('[') and address.version != 6:
        raise ValueError('Bracketed resolver must be IPv6')
    return str(address), port, socket.AF_INET6 if address.version == 6 else socket.AF_INET


def _wire_name(domain):
    return b''.join(bytes([len(x)]) + x.encode('ascii') for x in domain.split('.')) + b'\0'


def _read_name(packet, offset, end=None):
    """Decode labels/compression with message, RDATA, name and hop bounds."""
    end = len(packet) if end is None else end
    cursor, consumed, hops, size = offset, None, 0, 1
    labels, seen = [], set()
    while True:
        if cursor >= end or cursor < 12 or cursor in seen:
            raise DNSPacketError('Invalid compressed name')
        seen.add(cursor)
        length = packet[cursor]
        if length & 0xc0 == 0xc0:
            if cursor + 2 > end:
                raise DNSPacketError('Truncated name pointer')
            pointer = ((length & 0x3f) << 8) | packet[cursor + 1]
            # RFC 1035 compression references a prior occurrence, not a future
            # byte or the header. This also rules out pointer cycles.
            if pointer < 12 or pointer >= cursor:
                raise DNSPacketError('Invalid name pointer')
            if consumed is None:
                consumed = cursor + 2
            cursor, end = pointer, len(packet)
            hops += 1
            if hops > 128:
                raise DNSPacketError('Too many name pointers')
            continue
        if length & 0xc0:
            raise DNSPacketError('Unsupported name label')
        cursor += 1
        if length == 0:
            return '.'.join(labels).lower(), consumed if consumed is not None else cursor
        if length > 63 or cursor + length > end:
            raise DNSPacketError('Truncated name label')
        raw = packet[cursor:cursor + length]
        # Preserve DNS label boundaries: dots inside a wire label must not make
        # an attacker-controlled question appear equal to the requested name.
        if not re.fullmatch(rb'[A-Za-z0-9_*-]+', raw):
            raise DNSPacketError('Unsupported name bytes')
        labels.append(raw.decode('ascii'))
        size += length + 1
        if size > 255 or len(labels) > 127:
            raise DNSPacketError('DNS name too long')
        cursor += length


def parse_dns_response(packet, query_id, domain):
    """Validate the exact AAAA question and decode relevant answer RR data."""
    domain = normalize_domain(domain)
    if not isinstance(packet, bytes) or not 12 <= len(packet) <= MAX_TCP_BYTES:
        raise DNSPacketError('Invalid DNS packet length')
    ident, flags, qcount, acount, ncount, arcount = struct.unpack('!6H', packet[:12])
    if ident != query_id or not flags & 0x8000 or flags & 0x7800 or flags & 0x0040:
        raise DNSPacketError('DNS response identity/header mismatch')
    if qcount != 1 or acount + ncount + arcount > MAX_RECORDS:
        raise DNSPacketError('Invalid DNS section counts')
    name, offset = _read_name(packet, 12)
    if offset + 4 > len(packet):
        raise DNSPacketError('Truncated DNS question')
    qtype, qclass = struct.unpack('!2H', packet[offset:offset + 4])
    if name != domain.lower().rstrip('.') or qtype != 28 or qclass != 1:
        raise DNSPacketError('DNS question mismatch')
    offset += 4
    result = {'rcode': flags & 15, 'rcode_name': RCODES.get(flags & 15, 'UNKNOWN'),
              'truncated': bool(flags & 0x0200), 'answers': [], 'cnames': []}
    if result['truncated']:
        # Truncated UDP RR bodies can legitimately end mid-record; the exact
        # transaction/question is already checked before requesting TCP.
        return result
    answers, cnames, extended_rcode, seen_opt = [], [], 0, False
    for section, count in (('answer', acount), ('authority', ncount), ('additional', arcount)):
        for _ in range(count):
            owner, offset = _read_name(packet, offset)
            if offset + 10 > len(packet):
                raise DNSPacketError('Truncated resource record')
            kind, rrclass, ttl, length = struct.unpack('!HHIH', packet[offset:offset + 10])
            offset += 10
            stop = offset + length
            if stop > len(packet):
                raise DNSPacketError('Truncated resource data')
            if kind == 41:
                if section != 'additional' or owner or seen_opt:
                    raise DNSPacketError('Invalid OPT record')
                seen_opt = True
                extended_rcode = ttl >> 24
            elif kind == 28 and rrclass == 1:
                if length != 16:
                    raise DNSPacketError('Invalid AAAA record length')
                addr = ipaddress.IPv6Address(packet[offset:stop])
                if section == 'answer':
                    answers.append({'name': owner, 'address': str(addr), 'ttl': ttl,
                                    'is_global': bool(addr.is_global and not addr.is_multicast and
                                                      not addr.is_reserved and not addr.is_site_local)})
            elif kind == 5 and rrclass == 1:
                target, consumed = _read_name(packet, offset, stop)
                if consumed != stop or not target:
                    raise DNSPacketError('Invalid CNAME resource data')
                if section == 'answer':
                    cnames.append({'name': owner, 'target': target, 'ttl': ttl})
            offset = stop
    if offset != len(packet):
        raise DNSPacketError('Trailing DNS packet bytes')
    result['rcode'] |= extended_rcode << 4
    result['rcode_name'] = RCODES.get(result['rcode'], 'UNKNOWN')
    reachable, current, chain = {domain}, domain, []
    for _ in range(MAX_RECORDS):
        aliases = [row for row in cnames if row['name'] == current]
        if not aliases:
            break
        if len({row['target'] for row in aliases}) != 1:
            raise DNSPacketError('Conflicting CNAME records')
        row = aliases[0]
        if row['target'] in reachable:
            raise DNSPacketError('Cyclic CNAME chain')
        chain.append(row)
        current = row['target']
        reachable.add(current)
    result['answers'] = [row for row in answers if row['name'] in reachable]
    result['cnames'] = chain
    return result


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise socket.timeout()
    return remaining


def _recv_exact(sock, count, deadline):
    chunks = bytearray()
    while len(chunks) < count:
        sock.settimeout(_remaining(deadline))
        data = sock.recv(count - len(chunks))
        if not data:
            raise DNSPacketError('DNS TCP connection ended before frame')
        chunks.extend(data)
    return bytes(chunks)


def _tcp_response(address, family, packet, deadline):
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(_remaining(deadline))
        sock.connect(address)
        sock.settimeout(_remaining(deadline))
        sock.sendall(struct.pack('!H', len(packet)) + packet)
        length = struct.unpack('!H', _recv_exact(sock, 2, deadline))[0]
        if not 12 <= length <= MAX_TCP_BYTES:
            raise DNSPacketError('Invalid DNS TCP frame length')
        return _recv_exact(sock, length, deadline)


def query_resolver(domain, resolver, timeout=3):
    """One AAAA query; UDP and optional TCP share a single deadline."""
    domain = normalize_domain(domain)
    host, port, family = parse_resolver(resolver)
    timeout = _bounded_timeout(timeout)
    address = (host, port, 0, 0) if family == socket.AF_INET6 else (host, port)
    ident = secrets.randbits(16)
    packet = struct.pack('!6H', ident, 0x0100, 1, 0, 0, 0) + _wire_name(domain) + struct.pack('!2H', 28, 1)
    started = time.monotonic()
    deadline = started + timeout
    report = {'success': False, 'outcome': 'network_error', 'rcode': None, 'rcode_name': None,
              'query_type': 'AAAA',
              'transport': 'udp', 'truncated': False, 'answers': [], 'cnames': []}
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(_remaining(deadline))
            sock.connect(address)  # Kernel filters datagrams from other peers.
            sock.settimeout(_remaining(deadline))
            sock.send(packet)
            sock.settimeout(_remaining(deadline))
            response = sock.recv(MAX_UDP_BYTES + 1)
        if len(response) > MAX_UDP_BYTES:
            raise DNSPacketError('Oversized DNS UDP response')
        parsed = parse_dns_response(response, ident, domain)
        if parsed['truncated']:
            report['truncated'] = True
            report['transport'] = 'tcp'
            parsed = parse_dns_response(_tcp_response(address, family, packet, deadline), ident, domain)
            if parsed['truncated']:
                raise DNSPacketError('Truncated DNS TCP response')
        report.update(parsed)
        # Record that UDP required fallback even though the TCP answer is full.
        report['truncated'] = report['transport'] == 'tcp'
        if parsed['rcode'] != 0:
            report['outcome'] = 'nxdomain' if parsed['rcode'] == 3 else 'dns_error'
        elif not parsed['answers']:
            report['outcome'] = 'no_aaaa'
        else:
            report.update(success=True, outcome='ok')
    except (socket.timeout, TimeoutError):
        report['outcome'] = 'timeout'
    except DNSPacketError:
        report['outcome'] = 'invalid_response'
    except OSError as exc:
        if exc.errno == errno.ECONNREFUSED:
            report['outcome'] = 'connection_refused'
        elif exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
            report['outcome'] = 'unreachable'
    report['elapsed_ms'] = round((time.monotonic() - started) * 1000, 3)
    return report


def _bounded_timeout(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError('Diagnostic DNS timeout must be numeric')
    return min(5.0, max(1.0, float(value)))


def _percentile(values, percentile):
    if not values:
        return None
    ordered = sorted(values)
    return round(ordered[max(0, math.ceil(percentile * len(ordered)) - 1)], 3)


def _statistics(probes):
    latencies = [row['elapsed_ms'] for row in probes if row.get('success') is True and
                 isinstance(row.get('elapsed_ms'), (int, float))]
    return {'sample_count': len(probes), 'success_count': sum(row.get('success') is True for row in probes),
            'error_count': sum(row.get('success') is not True for row in probes),
            'p50_ms': _percentile(latencies, .5), 'p95_ms': _percentile(latencies, .95),
            'p99_ms': _percentile(latencies, .99), 'latency_sample_count': len(latencies),
            'percentile_method': 'nearest_rank', 'latency_scope': 'successful_queries_only',
            'outcomes': dict(Counter(row.get('outcome', 'unknown') for row in probes))}


def probe_dns(target_url, resolvers, *, timeout=3, rounds=2):
    """Measure configured resolvers twice, at most three simultaneous sockets.

    Caller validates the target URL policy without resolving it. A maximum of
    three configured numeric resolvers is accepted. The two rounds per resolver
    are sequential; TCP fallback never receives an extra timeout budget.
    """
    domain = normalize_domain(target_url)
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        pass
    else:
        raise ValueError('DNS diagnostics requires a hostname, not an IP literal')
    if not isinstance(resolvers, (list, tuple)) or not 1 <= len(resolvers) <= 3:
        raise ValueError('Diagnostics accepts one to three numeric resolvers')
    if isinstance(rounds, bool) or rounds != 2:
        raise ValueError('Diagnostics uses exactly two DNS rounds')
    timeout = _bounded_timeout(timeout)
    for resolver in resolvers:
        parse_resolver(resolver)
    started = time.monotonic()
    def perform(resolver):
        host, port, _ = parse_resolver(resolver)
        probes = [dict(query_resolver(domain, resolver, timeout), round=index + 1) for index in range(2)]
        return {'resolver': resolver, 'host': host, 'port': port, 'probes': probes,
                'summary': _statistics(probes), 'cache_confirmed': False}
    with ThreadPoolExecutor(max_workers=min(3, len(resolvers)), thread_name_prefix='dns-diagnostic') as pool:
        results = list(pool.map(perform, resolvers))
    all_probes = [row for result in results for row in result['probes']]
    return {'domain': domain, 'query_type': 'AAAA', 'timeout_seconds': timeout, 'rounds': 2,
            'resolvers': results, 'summary': _statistics(all_probes), 'cache_confirmed': False,
            'scope': 'configured_resolver_aaaa_only',
            'elapsed_ms': round((time.monotonic() - started) * 1000, 3)}


def _error_category(probe):
    if probe.get('success') is True:
        return None
    known = {'timeout', 'proxy_connect', 'proxy_auth', 'proxy_rejected', 'dns', 'tls',
             'empty_response', 'transport', 'target_http', 'invalid_response', 'unknown'}
    try:
        connect = int(probe.get('http_connect_code', 0))
        code = int(probe.get('http_code', 0))
    except (TypeError, ValueError, OverflowError):
        return 'invalid_response'
    if connect == 407:
        return 'proxy_auth'
    if connect == 403:
        return 'proxy_rejected'
    if connect >= 400:
        return 'proxy_connect'
    supplied = probe.get('error_type')
    if isinstance(supplied, str) and supplied in known:
        return supplied
    curl = probe.get('curl_exit')
    if isinstance(curl, int) and not isinstance(curl, bool):
        mapped = {5: 'dns', 6: 'dns', 7: 'proxy_connect', 28: 'timeout', 35: 'tls',
                  51: 'tls', 58: 'tls', 60: 'tls', 52: 'empty_response', 55: 'transport',
                  56: 'transport', 97: 'proxy_connect'}
        if curl in mapped:
            return mapped[curl]
    if code >= 400:
        return 'target_http'
    return 'unknown'


class DiagnosticHistory:
    """A <=200-row in-memory window of manager speedtests, not browser traffic."""
    def __init__(self, max_samples=200):
        if isinstance(max_samples, bool) or not isinstance(max_samples, int) or not 1 <= max_samples <= 200:
            raise ValueError('Diagnostic history limit must be 1..200')
        self.max_samples = max_samples
        self._rows = deque(maxlen=max_samples)
        self._lock = threading.Lock()

    def record(self, probe, domain=None):
        if not isinstance(probe, dict):
            raise ValueError('Diagnostic sample must be an object')
        raw_domain = domain if domain is not None else probe.get('target_host', probe.get('domain', ''))
        try:
            hostname = normalize_domain(raw_domain)
        except ValueError:
            hostname = 'unknown'
        port = probe.get('port')
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            port = None
        latency = probe.get('latency_ms')
        if latency is None:
            seconds = probe.get('total_time')
            latency = seconds * 1000 if isinstance(seconds, (int, float)) and not isinstance(seconds, bool) else None
        if isinstance(latency, bool) or not isinstance(latency, (int, float)) or not math.isfinite(latency) or latency < 0:
            latency = None
        row = {'domain': hostname, 'port': port, 'success': probe.get('success') is True,
               'latency_ms': round(float(latency), 3) if latency is not None else None,
               'error_category': _error_category(probe)}
        with self._lock:
            self._rows.append(row)

    @staticmethod
    def _summarize(rows):
        latencies = [row['latency_ms'] for row in rows if row['latency_ms'] is not None]
        return {'sample_count': len(rows), 'success_count': sum(row['success'] for row in rows),
                'error_count': sum(not row['success'] for row in rows),
                'latency_sample_count': len(latencies), 'p50_ms': _percentile(latencies, .5),
                'p95_ms': _percentile(latencies, .95), 'p99_ms': _percentile(latencies, .99),
                'error_categories': dict(Counter(row['error_category'] for row in rows if not row['success']))}

    def summary(self):
        with self._lock:
            rows = list(self._rows)
        ports = sorted({row['port'] for row in rows if row['port'] is not None})
        domains = sorted({row['domain'] for row in rows})
        return {**self._summarize(rows), 'scope': 'speedtest_only', 'window_size': len(rows),
                'max_samples': self.max_samples, 'storage': 'memory_only',
                'percentile_method': 'nearest_rank', 'latency_scope': 'all_timed_probes',
                'by_port': [dict(self._summarize([row for row in rows if row['port'] == port]), port=port)
                            for port in ports],
                'by_domain': [dict(self._summarize([row for row in rows if row['domain'] == domain]), domain=domain)
                              for domain in domains]}
