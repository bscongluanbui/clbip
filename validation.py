"""Typed, fail-closed input validation shared by the API and network worker."""
import ipaddress
import re
import socket
from urllib.parse import urlsplit


class ValidationError(ValueError):
    pass


DEFAULT_SETTINGS = {
    'subnet': '', 'prefix_len': 64, 'interface': 'eth0', 'start_port': 10000,
    'protocol': 'http', 'auth_type': 'userpass', 'allowed_ips': [],
    'listener_ipv4': '127.0.0.1', 'public_proxy': False,
    'dns1': '1.1.1.1', 'dns2': '8.8.8.8', 'dns3': '2606:4700:4700::1111',
    'max_connections': 64, 'log_enabled': True, 'timeout_connect': 10,
    'timeout_idle': 300, 'rotation_enabled': False, 'rotation_interval': 10,
    'auto_start': False, 'startup_rebuild_enabled': False, 'startup_proxy_count': 25,
    'topology_mode': 'lan', 'routed_prefix': '',
    'probe_url': 'https://api64.ipify.org', 'probe_timeout': 10,
    'source_change_confirmations': 2, 'source_poll_interval': 5,
    'telegram_bot_token': '', 'telegram_chat_id': '', 'telegram_allowed_user_ids': [],
    'allow_private_destinations': False,
}


def integer(value, name, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValidationError(f'{name} phải là số nguyên')
    if not minimum <= value <= maximum:
        raise ValidationError(f'{name} phải trong {minimum}..{maximum}')
    return value


def boolean(value, name):
    if not isinstance(value, bool):
        raise ValidationError(f'{name} phải là boolean')
    return value


def text(value, name, max_length=256, empty=True):
    if not isinstance(value, str) or len(value) > max_length:
        raise ValidationError(f'{name} phải là chuỗi tối đa {max_length} ký tự')
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValidationError(f'{name} chứa ký tự điều khiển')
    if not empty and not value:
        raise ValidationError(f'{name} không được rỗng')
    return value


def credential(username, password):
    username = text(username, 'username', 64, False)
    password = text(password, 'password', 256, False)
    if not re.fullmatch(r'[A-Za-z0-9_.@-]+', username):
        raise ValidationError('username chỉ gồm chữ ASCII, số, _, ., @, -')
    if any(ord(c) < 33 or ord(c) > 126 or c in ':$"\\#' for c in password):
        raise ValidationError('password chứa ký tự không hợp lệ cho token 3proxy')
    return username, password


def interface(value):
    value = text(value, 'interface', 15, False)
    if not re.fullmatch(r'[A-Za-z0-9_.:-]+', value) or value.startswith('-'):
        raise ValidationError('interface không hợp lệ')
    return value


def target_url(value, *, resolve=True):
    value = text(value, 'target_url', 2048, False)
    parsed = urlsplit(value)
    if parsed.scheme != 'https' or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValidationError('Chỉ hỗ trợ HTTPS URL không có credentials/fragment')
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise ValidationError('URL port không hợp lệ') from exc
    if port != 443:
        raise ValidationError('URL chỉ dùng HTTPS port 443')
    try:
        literal = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        literal = None
    def public(addr):
        return addr.is_global and not (addr.is_multicast or addr.is_reserved or getattr(addr, 'is_site_local', False))
    if literal and not public(literal):
        raise ValidationError('URL phải trỏ đến địa chỉ Internet public')
    if resolve:
        try:
            addresses = {row[4][0] for row in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)}
        except OSError as exc:
            raise ValidationError('DNS của target_url chưa phân giải được') from exc
        if not addresses or any(not public(ipaddress.ip_address(addr)) for addr in addresses):
            raise ValidationError('DNS target_url có địa chỉ không public')
    return value


def settings_patch(data, previous=None):
    if not isinstance(data, dict):
        raise ValidationError('JSON body phải là object')
    unknown = set(data) - set(DEFAULT_SETTINGS)
    if unknown:
        raise ValidationError('Trường settings không hỗ trợ: ' + ', '.join(sorted(unknown)))
    result = {**DEFAULT_SETTINGS, **(previous or {}), **data}
    for name in ('public_proxy', 'log_enabled', 'rotation_enabled', 'auto_start',
                 'startup_rebuild_enabled', 'allow_private_destinations'):
        boolean(result[name], name)
    for name, lo, hi in [('prefix_len', 1, 128), ('start_port', 1024, 65535), ('max_connections', 1, 10000),
                         ('timeout_connect', 1, 120), ('timeout_idle', 1, 86400), ('rotation_interval', 1, 10080),
                         ('probe_timeout', 1, 60), ('startup_proxy_count', 1, 1024),
                         ('source_change_confirmations', 1, 10), ('source_poll_interval', 2, 300)]:
        integer(result[name], name, lo, hi)
    interface(result['interface'])
    for name, options in [('protocol', ('http', 'socks5', 'dual')), ('auth_type', ('userpass', 'ip', 'none')),
                          ('topology_mode', ('lan', 'routed'))]:
        if result[name] not in options:
            raise ValidationError(f'{name} không hợp lệ')
    try:
        bind = ipaddress.ip_address(result['listener_ipv4'])
        if bind.version != 4 or bind.is_multicast:
            raise ValueError('IPv4 required')
    except (TypeError, ValueError) as exc:
        raise ValidationError('listener_ipv4 phải là IPv4 unicast') from exc
    if result['subnet']:
        try:
            net = ipaddress.IPv6Network(f"{result['subnet']}/{result['prefix_len']}", strict=False)
        except ValueError as exc:
            raise ValidationError('Subnet IPv6 không hợp lệ') from exc
        if net.network_address.is_link_local or net.network_address.is_multicast or net.network_address.is_loopback or net.network_address.is_unspecified:
            raise ValidationError('Subnet không phải IPv6 unicast có thể dùng')
        result['subnet'] = str(net.network_address)
    if result['routed_prefix']:
        try:
            result['routed_prefix'] = str(ipaddress.IPv6Network(result['routed_prefix'], strict=False))
        except ValueError as exc:
            raise ValidationError('routed_prefix không hợp lệ') from exc
    if not isinstance(result['allowed_ips'], list) or len(result['allowed_ips']) > 128:
        raise ValidationError('allowed_ips phải là danh sách tối đa 128 CIDR')
    try:
        result['allowed_ips'] = [str(ipaddress.ip_network(text(x, 'CIDR', 128, False), strict=False)) for x in result['allowed_ips']]
    except ValueError as exc:
        raise ValidationError('allowed_ips chứa CIDR không hợp lệ') from exc
    target_url(result['probe_url'], resolve=False)
    for name in ('dns1', 'dns2', 'dns3'):
        value = text(result[name], name, 128, False)
        # Allow ip:port for the unprivileged local DNS cache, and IPv6 literals.
        host, port = value, None
        if value.count(':') == 1:
            host, port = value.rsplit(':', 1)
        try:
            ipaddress.ip_address(host)
            if port is not None and not 1 <= int(port) <= 65535:
                raise ValueError('port')
        except ValueError as exc:
            raise ValidationError(f'{name} phải là địa chỉ IP[:port]') from exc
    text(result['telegram_bot_token'], 'telegram_bot_token', 256)
    text(result['telegram_chat_id'], 'telegram_chat_id', 32)
    if result['telegram_chat_id'] and not re.fullmatch(r'-?\d+', result['telegram_chat_id']):
        raise ValidationError('telegram_chat_id phải là số')
    if not isinstance(result['telegram_allowed_user_ids'], list) or len(result['telegram_allowed_user_ids']) > 128:
        raise ValidationError('telegram_allowed_user_ids phải là danh sách')
    result['telegram_allowed_user_ids'] = [integer(x, 'Telegram user ID', 1, 2**63-1) for x in result['telegram_allowed_user_ids']]
    return result


def public_settings(settings):
    result = dict(settings)
    result['telegram_bot_token_configured'] = bool(result.pop('telegram_bot_token', ''))
    return result
