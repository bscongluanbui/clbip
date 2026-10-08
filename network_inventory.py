"""Passive presentation helpers. Observing a source is not an egress proof."""
import copy
import ipaddress


def usable_ipv4(value):
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        return None
    if address.is_unspecified or address.is_loopback or address.is_multicast or address.is_reserved:
        return None
    return str(address)


def collect(net, managed=()):
    if hasattr(net, 'get_interface_inventory'):
        rows = net.get_interface_inventory()
    else:  # Retain compatibility with injected/older read-only backends.
        addresses = net.get_ipv6_addresses(strict=True)
        rows = [{'device': name, 'name': name, 'kind': 'Interface', 'active': None,
                 'ipv4': [], 'ipv6': [r for r in addresses if r['interface'] == name]}
                for name in net.get_interfaces()]
    owned = {(str(ipaddress.IPv6Address(r['address'])), r['interface']) for r in managed}
    inventory = copy.deepcopy(rows)
    for row in inventory:
        for record in row.get('ipv6', []):
            # Pool annotations are evidence from this observation only.
            record.pop('pool_prefix_len', None)
    # A DHCPv6 /128 is a host address, not the pool allocation. Infer its
    # possible LAN pool from a current covering on-link route, just as the
    # mutation backend does. Tool-owned /128 aliases never trigger this read.
    host_sources = [(row['device'], record) for row in inventory if row.get('active') is not False
                    for record in row.get('ipv6', [])
                    if _eligible_address(record, row['device'], owned) and int(record['prefix_len']) == 128]
    if host_sources and hasattr(net, 'get_ipv6_routes'):
        try:
            routes = net.get_ipv6_routes(strict=True)
            if not isinstance(routes, list):
                routes = []
        except (OSError, RuntimeError, ValueError, TypeError):
            routes = []  # Missing route evidence is never a pool allocation.
        for device, record in host_sources:
            pools = []
            for route in routes:
                if (not isinstance(route, dict) or route.get('dev') != device or route.get('gateway') or
                        route.get('type', 'unicast') != 'unicast' or route.get('expires') == 0 or
                        'linkdown' in route.get('flags', [])):
                    continue
                try:
                    pool = ipaddress.IPv6Network(route['dst'], strict=False)
                    if (64 <= pool.prefixlen < 128 and pool.network_address.is_global and
                            not pool.network_address.is_multicast and ipaddress.IPv6Address(record['address']) in pool):
                        pools.append(pool)
                except (ValueError, TypeError, KeyError):
                    continue
            if pools:
                record['pool_prefix_len'] = max(pools, key=lambda pool: pool.prefixlen).prefixlen
    for row in inventory:
        candidates = [r for r in row.get('ipv6', []) if eligible(r, row['device'], owned)]
        capable = bool(candidates) and row.get('active') is not False
        row.update(pool_capable=capable, reason=(
            'Có IPv6 global/prefix để thử pool; DAD và egress sẽ được xác minh khi tạo.' if capable else
            'Interface chưa hoạt động.' if row.get('active') is False else
            'Chưa có IPv6 global còn hiệu lực với prefix pool/on-link usable ngoài alias của tool.'))
    return inventory


def _eligible_address(record, interface, owned):
    try:
        address = ipaddress.IPv6Address(record['address'])
        length = int(record['prefix_len'])
        return (address.is_global and not address.is_multicast and 1 <= length <= 128 and
                record.get('interface', interface) == interface and
                record.get('ready') is True and record.get('valid_lft') != 0 and
                record.get('preferred_lft') != 0 and
                not set(record.get('flags', [])) & {'tentative', 'dadfailed', 'deprecated'} and
                (str(address), interface) not in owned)
    except (ValueError, KeyError, TypeError):
        return False


def eligible(record, interface, owned):
    if not _eligible_address(record, interface, owned):
        return False
    try:
        length = int(record['prefix_len'])
        pool_length = int(record.get('pool_prefix_len', length))
        return 1 <= pool_length < 128 and (length != 128 or 64 <= pool_length < 128)
    except (ValueError, TypeError, KeyError):
        return False


def observed_source(inventory, interface, managed=(), *, preferred=None):
    owned = {(str(ipaddress.IPv6Address(r['address'])), r['interface']) for r in managed}
    for row in inventory:
        if row['device'] != interface or row.get('active') is False:
            continue
        candidates = [r for r in row.get('ipv6', []) if eligible(r, interface, owned)]
        preferred_address = None
        if (isinstance(preferred, dict) and preferred.get('verified') is True and
                preferred.get('interface', interface) == interface):
            try:
                preferred_address = str(ipaddress.IPv6Address(preferred['address']))
            except (ValueError, TypeError, KeyError):
                pass
        candidates.sort(key=lambda r: (str(ipaddress.IPv6Address(r['address'])) != preferred_address,
                                       'temporary' in r.get('flags', []), r['address']))
        if candidates:
            record = candidates[0]
            length = record.get('pool_prefix_len', record['prefix_len'])
            network = ipaddress.IPv6Network(f"{record['address']}/{length}", strict=False)
            return {'address': str(ipaddress.IPv6Address(record['address'])), 'interface': interface,
                    'subnet': str(network.network_address), 'prefix_len': network.prefixlen,
                    'address_prefix_len': int(record['prefix_len'])}
    return None


def hosts(inventory):
    return list(dict.fromkeys(host for row in inventory if row.get('active') is not False
                for value in row.get('ipv4', []) if (host := usable_ipv4(value))))


def export_host(bind, inventory, source_interface):
    if bind != '0.0.0.0':
        return bind
    for row in inventory:
        if row['device'] == source_interface and row.get('active') is not False:
            for value in row.get('ipv4', []):
                if host := usable_ipv4(value):
                    return host
    # Never manufacture a remotely usable host when the observation is missing.
    raise ValueError('Chưa nhận diện IPv4 của interface nguồn; chọn listener_ipv4 cụ thể rồi export lại.')
