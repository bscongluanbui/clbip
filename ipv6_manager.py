"""Validated IPv6 operations; callers own locking, persistence, and activation.

Aliases default to /128 + noprefixroute. ISP allocations, LAN on-link routes,
and address prefix lengths are separate. No sysctls or inferred ownership.
"""
import bisect
import ipaddress
import json
import logging
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import time
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)
DATA_DIR = os.environ.get('DATA_DIR', '/app/data')
DEFAULT_PROBE_URL = 'https://api64.ipify.org'
_INTERFACE = re.compile(r'[A-Za-z0-9_.:-]{1,15}\Z')
_BAD_FLAGS = {'tentative', 'dadfailed', 'deprecated'}
_ADDRESS_FLAGS = _BAD_FLAGS | {'dynamic', 'temporary', 'mngtmpaddr', 'noprefixroute', 'optimistic'}


def _integer(value, name, minimum, maximum):
    if isinstance(value, (bool, float)):
        raise ValueError(f'{name} must be an integer')
    try:
        number = int(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f'{name} must be an integer') from exc
    if str(number) != str(value).strip() or not minimum <= number <= maximum:
        raise ValueError(f'{name} must be between {minimum} and {maximum}')
    return number


def validate_interface(interface):
    if not isinstance(interface, str) or not _INTERFACE.fullmatch(interface) or interface.startswith('-'):
        raise ValueError('Invalid network interface name')
    return interface


def normalize_ipv6(address):
    if not isinstance(address, str) or '%' in address or '/' in address:
        raise ValueError('An IPv6 address without zone or prefix is required')
    return str(ipaddress.IPv6Address(address))


def validate_subnet(subnet_str):
    try:
        if not isinstance(subnet_str, str) or '%' in subnet_str:
            raise ValueError('Zone indices are not accepted in a subnet')
        return ipaddress.IPv6Network(subnet_str, strict=False)
    except (ValueError, TypeError) as exc:
        raise ValueError(f'Invalid IPv6 subnet: {subnet_str}') from exc


def _record(record, interface=None, prefix_len=128):
    if isinstance(record, str):
        address = record
    elif isinstance(record, (tuple, list)) and len(record) == 3:
        address, interface, prefix_len = record
    elif isinstance(record, dict):
        address = record.get('address', record.get('ipv6'))
        interface = record.get('interface', interface)
        prefix_len = record.get('address_prefix_len', record.get('prefix_len', prefix_len))
    else:
        raise ValueError('Invalid managed-address record')
    return normalize_ipv6(address), validate_interface(interface), _integer(prefix_len, 'prefix_len', 0, 128)


def generate_random_ipv6(prefix, prefix_len, count=1, *, exclude_addresses=None, interface=None):
    """Sample exactly count distinct addresses, or fail before any mutation.

    Reserve host zero except for an explicit /128 pool. Interface additionally
    excludes every current kernel address. Bounded Floyd sampling also works
    when the pool is almost full, unlike collision/retry loops.
    """
    prefix_len = _integer(prefix_len, 'prefix_len', 0, 128)
    count = _integer(count, 'count', 0, 10000)
    network = validate_subnet(f'{prefix}/{prefix_len}')
    excluded = list(exclude_addresses or [])
    if interface is not None:
        excluded.extend(get_ipv6_addresses(interface, strict=True))
    first = 0 if prefix_len == 128 else 1
    base, last = int(network.network_address), network.num_addresses - 1
    excluded_offsets = set()
    for value in excluded:
        address = value.get('address', value.get('ipv6')) if isinstance(value, dict) else value
        number = int(ipaddress.IPv6Address(normalize_ipv6(address)))
        if base + first <= number <= base + last:
            excluded_offsets.add(number - base)
    excluded_offsets = sorted(excluded_offsets)
    capacity = last - first + 1 - len(excluded_offsets)
    if count > capacity:
        raise ValueError(f'Pool has only {capacity} available IPv6 addresses; requested {count}')
    ranks, selected = [], set()
    for upper in range(capacity - count, capacity):
        rank = secrets.randbelow(upper + 1)
        if rank in selected:
            rank = upper
        selected.add(rank)
        ranks.append(rank)
    addresses = []
    for rank in ranks:
        low, high = first, last
        while low < high:
            mid = (low + high) // 2
            available = mid - first + 1 - bisect.bisect_right(excluded_offsets, mid)
            if available > rank:
                high = mid
            else:
                low = mid + 1
        addresses.append(str(ipaddress.IPv6Address(base + low)))
    return addresses


def _run(argv, timeout=10):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)


def _json_snapshot(argv):
    result = _run(argv)
    if result.returncode != 0:
        raise RuntimeError(f'Network snapshot failed: {result.stderr.strip()}')
    data = json.loads(result.stdout)
    if not isinstance(data, list):
        raise ValueError('Invalid iproute2 JSON snapshot')
    return data


def _lifetime(value):
    if value is None or value == 'forever':
        return None
    value = int(value)
    return None if value >= 4294967295 else max(0, value)


def get_interfaces():
    try:
        return [validate_interface(item['ifname'].split('@')[0]) for item in
                _json_snapshot(['ip', '-j', 'link', 'show']) if item.get('ifname') != 'lo']
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        logger.error('Reading interfaces failed: %s', exc)
        return []


def get_interface_inventory():
    """One passive address/link snapshot; this never adds aliases or probes egress."""
    result = []
    for item in _json_snapshot(['ip', '-j', '-d', 'address', 'show']):
        name = validate_interface(item['ifname'].split('@')[0])
        if name == 'lo':
            continue
        link_kind = (item.get('linkinfo') or {}).get('info_kind', '')
        if name.startswith('tailscale'):
            kind = 'Tailscale'
        elif Path('/sys/class/net', name, 'wireless').is_dir():
            kind = 'Wi-Fi'
        elif link_kind in {'tun', 'wireguard', 'gre', 'ip6gre', 'sit', 'ipip'} or name.startswith(('tun', 'wg')):
            kind = 'VPN'
        elif link_kind:
            kind = 'Virtual (' + link_kind + ')'
        else:
            kind = 'Ethernet'
        flags = item.get('flags', [])
        active = ('UP' in flags and item.get('operstate') != 'DOWN' and
                  ('LOWER_UP' in flags or item.get('operstate') == 'UNKNOWN'))
        row = {'device': name, 'name': name, 'kind': kind, 'active': active,
               'ipv4': [], 'ipv6': [], 'pool_capable': False, 'reason': ''}
        for info in item.get('addr_info', []):
            family = info.get('family')
            if family == 'inet':
                address = ipaddress.IPv4Address(info['local'])
                if not (address.is_unspecified or address.is_loopback or address.is_multicast):
                    row['ipv4'].append(str(address))
            elif family == 'inet6':
                address_flags = set(info.get('flags', []))
                address_flags.update(flag for flag in _ADDRESS_FLAGS if info.get(flag) is True)
                valid = _lifetime(info.get('valid_life_time', info.get('valid_lft')))
                preferred = _lifetime(info.get('preferred_life_time', info.get('preferred_lft')))
                row['ipv6'].append({'address': normalize_ipv6(info['local']), 'interface': name,
                    'prefix_len': _integer(info['prefixlen'], 'prefixlen', 0, 128),
                    'scope': info.get('scope', ''), 'flags': sorted(address_flags),
                    'valid_lft': valid, 'preferred_lft': preferred,
                    'ready': not bool(address_flags & _BAD_FLAGS) and valid != 0 and preferred != 0})
        result.append(row)
    return result


def get_ipv6_addresses(interface=None, *, strict=False):
    """Return canonical addresses, prefix, DAD flags, lifetimes, readiness.

    strict=True is required for mutations: a failed read is not an empty
    interface. Lifetime None means unlimited; expired/deprecated is not ready.
    """
    argv = ['ip', '-j', '-6', 'addr', 'show']
    if interface is not None:
        argv.extend(['dev', validate_interface(interface)])
    try:
        addresses = []
        for item in _json_snapshot(argv):
            name = item.get('ifname', interface)
            if not isinstance(name, str):
                raise ValueError('Missing interface in IPv6 snapshot')
            iface = validate_interface(name.split('@')[0])
            for info in item.get('addr_info', []):
                if info.get('family') != 'inet6':
                    continue
                flags = set(info.get('flags', []))
                flags.update(name for name in _ADDRESS_FLAGS if info.get(name) is True)
                valid = _lifetime(info.get('valid_life_time', info.get('valid_lft')))
                preferred = _lifetime(info.get('preferred_life_time', info.get('preferred_lft')))
                addresses.append({
                    'address': normalize_ipv6(info['local']), 'interface': iface,
                    'prefix_len': _integer(info['prefixlen'], 'prefixlen', 0, 128),
                    'scope': info.get('scope', ''), 'flags': sorted(flags),
                    'valid_lft': valid, 'preferred_lft': preferred,
                    'ready': not bool(flags & _BAD_FLAGS) and valid != 0 and preferred != 0,
                })
        return addresses
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
        if strict:
            raise RuntimeError(f'Cannot read IPv6 state: {exc}') from exc
        logger.error('Reading IPv6 addresses failed: %s', exc)
        return []


def get_ipv6_routes(interface=None, *, strict=False):
    argv = ['ip', '-j', '-6', 'route', 'show']
    if interface is not None:
        argv.extend(['dev', validate_interface(interface)])
    try:
        return _json_snapshot(argv)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        if strict:
            raise RuntimeError(f'Cannot read IPv6 routes: {exc}') from exc
        logger.error('Reading IPv6 routes failed: %s', exc)
        return []


def observe_ndp(interface=None):
    """Read NDP counts without modifying neighbor state or exposing MAC addresses."""
    argv = ['ip', '-j', '-6', 'neigh', 'show']
    if interface is not None:
        argv.extend(['dev', validate_interface(interface)])
    try:
        rows = _json_snapshot(argv)
        states = {}
        count = 0
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError('Invalid NDP record')
            normalize_ipv6(row['dst'])
            validate_interface(row.get('dev', interface))
            values = row.get('state', ['UNKNOWN'])
            if isinstance(values, str):
                values = [values]
            if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
                raise ValueError('Invalid NDP state')
            for value in set(values or ['UNKNOWN']):
                name = value.upper()
                states[name] = states.get(name, 0) + 1
            count += 1
        return {'interface': interface, 'neighbor_count': count, 'states': states}
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError) as exc:
        raise RuntimeError('Cannot read IPv6 NDP metrics') from exc


def wait_for_ipv6_ready(address, interface, *, timeout=5, poll_interval=0.1):
    address, interface = normalize_ipv6(address), validate_interface(interface)
    if not 0 <= float(timeout) <= 120 or not 0 < float(poll_interval) <= 10:
        raise ValueError('Invalid DAD wait timeout')
    deadline = time.monotonic() + float(timeout)
    while True:
        try:
            current = next((a for a in get_ipv6_addresses(interface, strict=True)
                            if a['address'] == address), None)
        except RuntimeError:
            return False
        if current:
            if 'dadfailed' in current['flags'] or current['valid_lft'] == 0 or current['preferred_lft'] == 0:
                return False
            if current['ready']:
                return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(float(poll_interval), remaining))


def add_ipv6_to_interface(ipv6_address, interface, prefix_len=128, *, wait_ready=True, ready_timeout=5):
    address, interface, prefix_len = _record(ipv6_address, interface, prefix_len)
    if not isinstance(wait_ready, bool) or not 0 <= float(ready_timeout) <= 120:
        raise ValueError('Invalid DAD wait options')
    try:
        result = _run(['ip', '-6', 'addr', 'add', f'{address}/{prefix_len}', 'dev', interface, 'noprefixroute'])
        if result.returncode != 0:
            existing = get_ipv6_addresses(interface, strict=True)
            if not any(a['address'] == address and a['prefix_len'] == prefix_len for a in existing):
                logger.error('Adding IPv6 failed: %s', result.stderr.strip())
                return False
        return not wait_ready or wait_for_ipv6_ready(address, interface, timeout=ready_timeout)
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        logger.error('Adding IPv6 failed: %s', exc)
        return False


def remove_ipv6_from_interface(ipv6_address, interface, prefix_len=128):
    address, interface, prefix_len = _record(ipv6_address, interface, prefix_len)
    try:
        result = _run(['ip', '-6', 'addr', 'del', f'{address}/{prefix_len}', 'dev', interface])
        if result.returncode == 0:
            return True
        return not any(a['address'] == address and a['prefix_len'] == prefix_len
                       for a in get_ipv6_addresses(interface, strict=True))
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        logger.error('Removing IPv6 failed: %s', exc)
        return False


def create_ipv6_alias(ipv6_address, interface, prefix_len=128, *, wait_ready=False, ready_timeout=5,
                      on_created=None):
    """Exclusively create a new alias and report evidence, never adopt EEXIST.

    created=True means the kernel acknowledged our add; False means a rejected
    add. None means execution ended without an acknowledgement (e.g. timeout),
    so callers retain a non-destructive uncertainty record. The durable owner
    callback runs immediately after kernel success, before DAD/egress checks.
    A process crash between kernel success and that callback remains uncertain.
    Known-owned restoration intentionally uses add_ipv6_to_interface instead.
    """
    address, interface, prefix_len = _record(ipv6_address, interface, prefix_len)
    if not isinstance(wait_ready, bool) or not 0 <= float(ready_timeout) <= 120:
        raise ValueError('Invalid DAD wait options')
    if on_created is not None and not callable(on_created):
        raise ValueError('on_created must be callable')
    row = {'address': address, 'interface': interface, 'prefix_len': prefix_len,
           'success': False, 'created': None, 'existing': False, 'error': ''}
    try:
        result = _run(['ip', '-6', 'addr', 'add', f'{address}/{prefix_len}', 'dev', interface, 'noprefixroute'])
    except (OSError, RuntimeError, subprocess.SubprocessError):
        row['error'] = 'IPv6 add acknowledgement unknown; retained for manual review'
        return row
    if result.returncode != 0:
        row['created'] = False
        try:
            row['existing'] = any(a['address'] == address and a['prefix_len'] == prefix_len
                                  for a in get_ipv6_addresses(interface, strict=True))
        except RuntimeError:
            pass
        row['error'] = 'IPv6 alias already exists; ownership not acquired' if row['existing'] else 'IPv6 add command rejected'
        return row
    row.update(created=True, success=True)
    if on_created is not None:
        on_created(dict(row))
    if wait_ready and not wait_for_ipv6_ready(address, interface, timeout=ready_timeout):
        row.update(success=False, error='Created IPv6 failed DAD/readiness')
    return row


def bulk_add_ipv6(addresses, interface, prefix_len=128, *, wait_ready=False, ready_timeout=5,
                  on_created=None):
    return [create_ipv6_alias(addr, interface, prefix_len, wait_ready=wait_ready,
                             ready_timeout=ready_timeout, on_created=on_created)
            for addr in addresses]


def bulk_remove_ipv6(addresses, interface, prefix_len=128):
    return [{'address': normalize_ipv6(addr), 'success': remove_ipv6_from_interface(addr, interface, prefix_len)}
            for addr in addresses]


def _public_ip(address):
    if not address.is_global or address.is_multicast or address.is_reserved or address.is_link_local:
        return False
    if address.version == 6:
        if address.ipv4_mapped or address.is_site_local:
            return False
        if address.sixtofour and not address.sixtofour.is_global:
            return False
        if address.teredo and not all(a.is_global for a in address.teredo):
            return False
    return True


def validate_probe_target(target_url):
    """Validate public HTTPS; pin a public IPv6 DNS answer against rebinding."""
    if not isinstance(target_url, str) or any(c.isspace() or ord(c) < 32 for c in target_url):
        raise ValueError('Invalid HTTPS probe URL')
    parsed = urlsplit(target_url)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError('Probe target must be a credential-free HTTPS URL')
    port = parsed.port or 443
    hostname = parsed.hostname.encode('idna').decode('ascii')
    if hostname.lower() in {'localhost', 'localhost.localdomain'} or hostname.lower().endswith(('.local', '.localhost')):
        raise ValueError('Probe target must resolve only to public addresses')
    try:
        literal = ipaddress.ip_address(hostname)
    except ValueError:
        literal = None
    if literal is not None:
        if literal.version != 6 or not _public_ip(literal):
            raise ValueError('Probe target must be public IPv6')
        return {'url': target_url, 'hostname': hostname, 'port': port, 'resolve': None}
    answers = socket.getaddrinfo(hostname, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
    if not answers:
        raise ValueError('Probe hostname did not resolve')
    ipv6 = []
    for answer in answers:
        address = ipaddress.ip_address(answer[4][0].split('%')[0])
        if not _public_ip(address):
            raise ValueError('Probe target must resolve only to public addresses')
        if address.version == 6:
            ipv6.append(str(address))
    if not ipv6:
        raise ValueError('Probe hostname has no public IPv6 address')
    return {'url': target_url, 'hostname': hostname, 'port': port,
            'resolve': f'{hostname}:{port}:[{ipv6[0]}]'}


def probe_ipv6_egress(address, interface, *, target_url=DEFAULT_PROBE_URL, timeout=10, expected_address=None):
    address, interface = normalize_ipv6(address), validate_interface(interface)
    expected = normalize_ipv6(expected_address) if expected_address is not None else address
    result = {'success': False, 'address': address, 'observed_address': None, 'error': None}
    try:
        timeout = _integer(timeout, 'timeout', 1, 120)
        if not any(a['address'] == address and a['ready'] for a in get_ipv6_addresses(interface, strict=True)):
            raise ValueError('Source IPv6 is absent, tentative, deprecated, or expired')
        target = validate_probe_target(target_url)
        argv = ['curl', '--disable', '--silent', '--show-error', '--fail', '--noproxy', '*',
                '--proto', '=https', '--max-redirs', '0', '--connect-timeout', str(min(timeout, 5)),
                '--max-time', str(timeout), '--max-filesize', '4096', '--ipv6', '--interface', address]
        if target['resolve']:
            argv.extend(['--resolve', target['resolve']])
        argv.extend(['--url', target['url']])
        response = _run(argv, timeout=timeout + 2)
        if response.returncode != 0:
            raise RuntimeError(f'IPv6 egress probe failed (curl exit {response.returncode})')
        if len(response.stdout) > 128:
            raise RuntimeError('IPv6 probe response exceeded the address-size limit')
        observed = normalize_ipv6(response.stdout.strip())
        result['observed_address'] = observed
        if observed != expected:
            raise RuntimeError('Egress source address did not match assigned IPv6')
        result['success'] = True
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        result['error'] = str(exc)
    return result


def select_current_lan_prefix(interface, *, managed_addresses=None, target_url=DEFAULT_PROBE_URL,
                              timeout=5, checkpoint=None, prefer_networks=None):
    """Select a source-verified LAN prefix during boot or router renumbering.

    A host can legitimately retain several SLAAC/privacy/DHCPv6 addresses.
    Their presence alone is not ambiguous: ignore unusable and owned aliases,
    then test each plausible source against its exact expected public address.
    The selection is read-only, including failed/stale original host addresses.
    A second snapshot must still contain the selected source and usable routes
    after the probe, because Router Advertisements can change during startup.
    ``prefix_len`` describes the alias pool, not necessarily a DHCPv6 /128
    source's own ``address_prefix_len``. ``subnet`` is the bare network address,
    and ``full`` includes the prefix. Prefer a still-working configured prefix
    during live reconciliation without preventing failover to a new prefix.
    """
    interface = validate_interface(interface)
    timeout = _integer(timeout, 'timeout', 1, 120)
    if checkpoint is not None and not callable(checkpoint):
        raise ValueError('checkpoint must be callable')
    owned = {(address, iface) for address, iface, _ in
             (_record(record, interface) for record in (managed_addresses or []))}
    if isinstance(prefer_networks, str):
        prefer_networks = [prefer_networks]
    preferred_networks = {validate_subnet(value) for value in (prefer_networks or [])}

    def check():
        if checkpoint is not None:
            checkpoint()

    def snapshot_candidates():
        check()
        addresses = get_ipv6_addresses(interface, strict=True)
        check()
        routes = get_ipv6_routes(interface, strict=True)
        usable = [route for route in routes if isinstance(route, dict)
                  and route.get('dev', interface) == interface
                  and route.get('type', 'unicast') == 'unicast'
                  and route.get('expires') != 0
                  and 'linkdown' not in route.get('flags', [])]
        defaults = [route for route in usable if route.get('dst') in {'default', '::/0'}]
        if not defaults:
            raise RuntimeError('Waiting for a usable IPv6 default route on selected interface')
        onlink = []
        for route in usable:
            if route.get('gateway') or route.get('dst') in {None, 'default', '::/0'}:
                continue
            try:
                network = validate_subnet(route['dst'])
                if 64 <= network.prefixlen < 128 and _public_ip(network.network_address):
                    onlink.append(network)
            except ValueError:
                continue
        preferred_sources = {route.get('prefsrc') for route in defaults}
        candidates = {}
        for item in addresses:
            address = normalize_ipv6(item['address'])
            if item.get('interface', interface) != interface or (address, interface) in owned:
                continue
            flags = set(item.get('flags', []))
            if (item.get('scope') != 'global' or not item.get('ready') or flags & _BAD_FLAGS
                    or item.get('valid_lft') == 0 or item.get('preferred_lft') == 0
                    or not _public_ip(ipaddress.IPv6Address(address))):
                continue
            address_prefix = _integer(item['prefix_len'], 'prefix_len', 0, 128)
            network = validate_subnet(f'{address}/{address_prefix}')
            covering = [pool for pool in onlink if ipaddress.IPv6Address(address) in pool]
            if not covering:
                continue
            if 64 <= address_prefix < 128 and any(network.subnet_of(pool) for pool in covering):
                pool = network
            else:
                # DHCPv6 /128 is a host address, not an alias allocation. An
                # explicit current on-link route supplies its LAN pool.
                pool = max(covering, key=lambda value: value.prefixlen)
            candidate = dict(item, address=address, subnet=str(pool), prefix_len=pool.prefixlen,
                             address_prefix_len=address_prefix,
                             router_preferred=address in preferred_sources,
                             configured_preferred=any(network.subnet_of(pool)
                                                      for network in preferred_networks))
            candidates[(str(pool), address)] = candidate

        def score(candidate):
            # Unlimited lifetimes sort above finite lifetimes. A fresh RA's
            # preferred lifetime usually distinguishes new and stale prefixes;
            # reachability, not this hint, remains the selection criterion.
            lifetime = lambda value: float('inf') if value is None else int(value)
            return (not candidate['router_preferred'],
                    not candidate['configured_preferred'],
                    -lifetime(candidate.get('preferred_lft')),
                    -lifetime(candidate.get('valid_lft')),
                    'temporary' in candidate.get('flags', []), candidate['address'])

        # Keep prefixes together so a failed old source does not produce the
        # former arbitrary "multiple prefixes" error. Privacy sources in that
        # prefix remain fallbacks when its stable source fails.
        groups = {}
        for candidate in sorted(candidates.values(), key=score):
            groups.setdefault(candidate['subnet'], []).append(candidate)
        return [candidate for values in groups.values() for candidate in values]

    candidates = snapshot_candidates()
    if not candidates:
        raise RuntimeError('Waiting for a preferred non-managed global IPv6 source and on-link LAN prefix')
    for candidate in candidates:
        check()
        probe = probe_ipv6_egress(candidate['address'], interface, target_url=target_url,
                                 timeout=timeout, expected_address=candidate['address'])
        check()
        if not probe.get('success') or probe.get('observed_address') != candidate['address']:
            continue
        current = snapshot_candidates()
        if not any(item['address'] == candidate['address'] and item['subnet'] == candidate['subnet']
                   for item in current):
            continue
        return {'address': candidate['address'], 'interface': interface,
                'subnet': str(validate_subnet(candidate['subnet']).network_address),
                'full': candidate['subnet'], 'prefix_len': candidate['prefix_len'],
                'address_prefix_len': candidate['address_prefix_len'], 'verified': True}
    raise RuntimeError('Waiting for a current LAN IPv6 source with verified Internet egress')


def observe_prefix_state(interface, *, previous=None, managed_addresses=None):
    """Observe system prefix/lifetime changes without changing any address."""
    interface = validate_interface(interface)
    addresses = get_ipv6_addresses(interface, strict=True)
    routes = get_ipv6_routes(interface, strict=True)
    owned = {_record(r, interface) for r in (managed_addresses or [])}
    prefixes = {}
    for addr in addresses:
        key = (addr['address'], interface, addr['prefix_len'])
        if key in owned or addr['scope'] != 'global' or addr['prefix_len'] == 128:
            continue
        network = str(validate_subnet(f"{addr['address']}/{addr['prefix_len']}"))
        state = prefixes.setdefault(network, {'network': network, 'interface': interface,
                                               'valid_lft': addr['valid_lft'], 'preferred_lft': addr['preferred_lft']})
        for field in ('valid_lft', 'preferred_lft'):
            # A deprecated privacy address must not expire a still-valid
            # stable address for the same prefix. None means unlimited.
            values = (state[field], addr[field])
            state[field] = None if None in values else max(values)
    prior = previous.get('prefixes', []) if isinstance(previous, dict) else (previous or [])
    old = {p['network'] if isinstance(p, dict) else str(p) for p in prior}
    current = set(prefixes)
    present = {(a['address'], interface, a['prefix_len']) for a in addresses}
    return {'interface': interface, 'prefixes': sorted(prefixes.values(), key=lambda p: p['network']),
            'changed': previous is not None and old != current,
            'added_prefixes': sorted(current - old), 'removed_prefixes': sorted(old - current),
            'expired': [p for p in prefixes.values() if p['valid_lft'] == 0 or p['preferred_lft'] == 0],
            'missing_managed': [dict(address=a, interface=i, prefix_len=p) for a, i, p in sorted(owned - present) if i == interface],
            'addresses': addresses, 'routes': routes}


def topology_preflight(prefix, prefix_len, interface, *, topology_mode='lan', routed_prefix=None):
    """LAN needs a covering on-link route; routed mode needs explicit allocation."""
    result = {'success': False, 'errors': [], 'warnings': [], 'addresses': [], 'routes': [], 'prefix_state': None}
    try:
        interface = validate_interface(interface)
        network = validate_subnet(f"{prefix}/{_integer(prefix_len, 'prefix_len', 0, 128)}")
        if not _public_ip(network.network_address):
            raise ValueError('An Internet-routable IPv6 pool is required')
        mode = str(topology_mode).lower().replace('_', '-').replace('on-link', 'lan')
        if mode not in {'lan', 'routed'}:
            raise ValueError('topology_mode must be lan or routed')
        state = observe_prefix_state(interface)
        result.update(addresses=state['addresses'], routes=state['routes'], prefix_state=state)
        usable_routes = [r for r in state['routes'] if r.get('type', 'unicast') == 'unicast'
                         and r.get('expires') != 0 and 'linkdown' not in r.get('flags', [])]
        if not any(r.get('dst') in {'default', '::/0'} for r in usable_routes):
            result['errors'].append('No usable IPv6 default route on selected interface')
        if mode == 'lan':
            if network.prefixlen < 64:
                result['errors'].append('LAN mode requires a /64 or narrower on-link pool, not an ISP delegated aggregate')
            onlink = []
            for route in usable_routes:
                if not route.get('gateway') and route.get('dst') not in {None, 'default', '::/0'}:
                    try:
                        onlink.append(validate_subnet(route['dst']))
                    except ValueError:
                        pass
            if not any(network.subnet_of(n) for n in onlink):
                result['errors'].append('Selected pool is not covered by a current on-link IPv6 route')
            matching = [a for a in state['addresses'] if ipaddress.IPv6Address(a['address']) in network]
            if matching and not any(a['ready'] for a in matching):
                result['errors'].append('LAN prefix has only tentative, deprecated, or expired source addresses')
        else:
            if not routed_prefix or not network.subnet_of(validate_subnet(routed_prefix)):
                result['errors'].append('Routed mode requires a configured upstream allocation covering the pool')
            result['warnings'].append('Upstream router must route this allocation to the host; each alias requires a source-bound egress probe')
        result['success'] = not result['errors']
    except (OSError, ValueError, RuntimeError) as exc:
        result['errors'].append(str(exc))
    return result


def cleanup_orphan_ipv6(interface, keep_addresses=None, *, managed_addresses=None):
    """Delete only explicit ledger entries; missing ownership means no deletion."""
    interface = validate_interface(interface)
    keep = {normalize_ipv6(a.get('address', a.get('ipv6')) if isinstance(a, dict) else a)
            for a in (keep_addresses or [])}
    result = {'removed': 0, 'kept': 0, 'failed': [], 'removed_addresses': [], 'unmanaged': 0}
    try:
        current = get_ipv6_addresses(interface, strict=True)
        owned = {_record(r, interface) for r in (managed_addresses or [])}
        for addr in current:
            key = (addr['address'], interface, addr['prefix_len'])
            if key not in owned or addr['address'] in keep or ipaddress.IPv6Address(addr['address']).is_link_local:
                result['kept'] += 1
                result['unmanaged'] += key not in owned
            elif remove_ipv6_from_interface(*key):
                result['removed'] += 1
                result['removed_addresses'].append(addr['address'])
            else:
                result['failed'].append(addr['address'])
    except (ValueError, RuntimeError) as exc:
        result['error'] = str(exc)
    return result


def restore_proxy_addresses(proxies, settings=None, *, probe=False, probe_existing=True, checkpoint=None):
    """Restore missing aliases; optionally probe aliases that are already present.

    The default retains full source verification for explicit Start/legacy calls.
    A reconciler can skip existing aliases while still verifying every newly
    restored source before it is counted as successful.
    """
    settings = settings or {}
    result = {'restored': 0, 'failed': 0, 'already_present': 0, 'results': []}
    snapshots = {}
    for proxy in proxies:
        if checkpoint:
            checkpoint()
        item = {'address': proxy.get('ipv6', proxy.get('address')), 'success': False, 'restored': False}
        try:
            address, interface, prefix = _record(proxy, settings.get('interface', 'eth0'), 128)
            item.update(address=address, interface=interface, prefix_len=prefix)
            if interface not in snapshots:
                snapshots[interface] = get_ipv6_addresses(interface, strict=True)
            present = next((a for a in snapshots[interface] if a['address'] == address and a['prefix_len'] == prefix), None)
            if present:
                if not present['ready'] and not wait_for_ipv6_ready(address, interface):
                    raise RuntimeError('Existing IPv6 is not usable')
                result['already_present'] += 1
            else:
                if not add_ipv6_to_interface(address, interface, prefix):
                    raise RuntimeError('IPv6 restoration failed')
                item['restored'] = True
                snapshots[interface].append({'address': address, 'prefix_len': prefix, 'ready': True})
            if probe and (item['restored'] or probe_existing):
                if checkpoint:
                    checkpoint()
                checked = probe_ipv6_egress(address, interface, target_url=settings.get('probe_url', DEFAULT_PROBE_URL),
                                            timeout=settings.get('probe_timeout', 10))
                if not checked['success']:
                    raise RuntimeError(checked['error'])
            item['success'] = True
            if item['restored']:
                result['restored'] += 1
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            item['error'] = str(exc)
            result['failed'] += 1
        result['results'].append(item)
    return result


def auto_restore_ips(restart_proxy_func=None, *, proxies=None, settings=None, return_details=False):
    """Legacy adapter; the application reconciler passes its locked state."""
    try:
        if proxies is None:
            with open(os.path.join(DATA_DIR, 'proxies.json'), encoding='utf-8') as source:
                proxies = json.load(source)
        if settings is None:
            with open(os.path.join(DATA_DIR, 'settings.json'), encoding='utf-8') as source:
                settings = json.load(source)
        result = restore_proxy_addresses(proxies, settings, probe=True)
        if result['restored'] and restart_proxy_func:
            try:
                restarted = restart_proxy_func()
                if restarted is False or (isinstance(restarted, tuple) and not restarted[0]):
                    raise RuntimeError('Proxy restart failed')
            except Exception as exc:
                result['restart_error'] = str(exc)
        return result if return_details else result['restored']
    except (OSError, ValueError, RuntimeError, TypeError) as exc:
        logger.error('Auto-restore failed: %s', exc)
        result = {'restored': 0, 'failed': 0, 'already_present': 0, 'results': [], 'error': str(exc)}
        return result if return_details else 0


def rotate_ipv6_addresses(prefix, prefix_len, count, interface, old_addresses=None, *,
                          managed_addresses=None, activate_func=None, rollback_func=None,
                          probe=True, target_url=DEFAULT_PROBE_URL):
    """Stage /128s, activate/verify via callback, then retire only owned aliases.

    activate_func(new_addresses) returns truthy or (True, message).
    rollback_func() restores the prior proxy configuration. Old-address
    rotation requires both callbacks and explicit ownership before any changes.
    Application service adds persistent transactions around these helpers.
    """
    interface = validate_interface(interface)
    old = [normalize_ipv6(a) for a in (old_addresses or [])]
    owned = {_record(r, interface) for r in (managed_addresses or [])}
    if old and (activate_func is None or rollback_func is None):
        raise ValueError('Rotation requires activation and rollback callbacks before retiring old IPv6')
    old_records = [key for key in owned if key[0] in old and key[1] == interface]
    if len({key[0] for key in old_records}) != len(set(old)):
        raise ValueError('Rotation requires explicit ownership records for every old IPv6')
    current = get_ipv6_addresses(interface, strict=True)
    new = generate_random_ipv6(prefix, prefix_len, count, exclude_addresses=current + old)
    added, retired, uncertain = [], [], []
    activation_attempted = False
    try:
        for address in new:
            rows = bulk_add_ipv6([address], interface, 128, wait_ready=True)
            if rows and rows[0].get('created') is True:
                added.append(address)
            elif rows and rows[0].get('created') is None:
                uncertain.append(address)
            if not rows or not rows[0].get('success'):
                raise RuntimeError(f'New IPv6 failed DAD/add: {address}')
            if probe:
                checked = probe_ipv6_egress(address, interface, target_url=target_url)
                if not checked['success']:
                    raise RuntimeError(checked['error'])
        if activate_func:
            activation_attempted = True
            active = activate_func(new)
            if not active or (isinstance(active, tuple) and not active[0]):
                raise RuntimeError('New proxy configuration activation failed')
        for key in old_records:
            if not remove_ipv6_from_interface(*key):
                raise RuntimeError(f'Old IPv6 retirement failed: {key[0]}')
            retired.append(key)
        return new
    except Exception as exc:
        failures = []
        if uncertain:
            failures.append(f'creation acknowledgement unknown; aliases retained for manual review: {", ".join(uncertain)}')
        configuration_restored = not activation_attempted
        # A failed delete may have timed out after the kernel accepted it;
        # restore every old record once retirement was attempted.
        for key in old_records if activation_attempted else retired:
            if not add_ipv6_to_interface(*key):
                failures.append(f'restore old {key[0]}')
        if activation_attempted and rollback_func:
            try:
                rolled = rollback_func()
                if rolled is False or (isinstance(rolled, tuple) and not rolled[0]):
                    failures.append('proxy configuration rollback')
                else:
                    configuration_restored = True
            except Exception as rollback_exc:
                failures.append(f'proxy configuration rollback: {rollback_exc}')
        elif activation_attempted:
            failures.append('proxy configuration rollback not available')
        # If the old config did not reload, new aliases may still be in use.
        # Keep them for the caller's ledger recovery instead of breaking both.
        if configuration_restored:
            for address in added:
                if not remove_ipv6_from_interface(address, interface, 128):
                    failures.append(f'remove staged {address}')
        else:
            failures.append(f'staged aliases retained: {", ".join(added)}')
        if failures:
            raise RuntimeError(f'{exc}; rollback incomplete: {", ".join(failures)}') from exc
        raise RuntimeError(f'{exc}; previous addresses/configuration restored') from exc
