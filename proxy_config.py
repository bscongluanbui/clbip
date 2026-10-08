"""Validated transactional configs and owned foreground 3proxy lifecycle."""
import hashlib
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import re
import signal
import shutil
import socket
import subprocess
import tempfile
import time
import uuid

logger = logging.getLogger(__name__)
PROXY_BINARY = os.environ.get('PROXY_BINARY', '/usr/local/bin/3proxy')
DATA_DIR = os.environ.get('DATA_DIR', '/app/data')
CONFIG_PATH = os.path.join(DATA_DIR, '3proxy.cfg')
PROXIES_PER_INSTANCE = int(os.environ.get('PROXIES_PER_INSTANCE', '32'))
START_TIMEOUT, STOP_TIMEOUT = 10.0, 5.0
_CHILDREN = {}
PRIVATE_DESTINATIONS = '0.0.0.0/8,10.0.0.0/8,100.64.0.0/10,127.0.0.0/8,169.254.0.0/16,172.16.0.0/12,192.168.0.0/16,224.0.0.0/4,240.0.0.0/4,::/128,::1/128,fc00::/7,fe80::/10,ff00::/8,::ffff:0:0/96'


def _integer(value, name, low, high):
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        raise ValueError(f'{name} must be an integer')
    if isinstance(value, str) and not re.fullmatch(r'[0-9]+', value):
        raise ValueError(f'{name} must be an integer')
    number = int(value)
    if not low <= number <= high:
        raise ValueError(f'{name} must be between {low} and {high}')
    return number


def _bool(value, name):
    if not isinstance(value, bool):
        raise ValueError(f'{name} must be a boolean')
    return value


def _token(value, name, username=False):
    valid = isinstance(value, str)
    if username:
        valid = valid and bool(re.fullmatch(r'[A-Za-z0-9_.@-]{1,64}', value))
    else:
        valid = valid and 1 <= len(value) <= 256 and not any(ord(c) < 33 or ord(c) > 126 or c in ':$"\\#' for c in value)
    if not valid:
        raise ValueError(f'{name} contains unsupported config characters')
    return value


def _path_token(value):
    value = str(value)
    if not value or any(c.isspace() or c in '\x00$"' for c in value):
        raise ValueError('Config paths must not contain whitespace, quotes or $')
    return value


def validate_config_inputs(proxies, users, settings):
    """Pure preflight. Return canonical copies; never write configs or start IPs."""
    if not isinstance(proxies, list) or not isinstance(users, list) or not isinstance(settings, dict):
        raise ValueError('Proxies/users must be lists and settings must be an object')
    if len(users) > 256 or len(proxies) > 10000:
        raise ValueError('Proxy/user list exceeds the configured input limits')
    _path_token(DATA_DIR)
    s = dict(settings)
    auth = s.get('auth_type', 'userpass')
    if auth not in ('userpass', 'ip', 'none'):
        raise ValueError('Unknown authentication mode')
    s['auth_type'] = auth
    s['public_proxy'] = _bool(s.get('public_proxy', s.get('allow_public', False)), 'public_proxy')
    s['log_enabled'] = _bool(s.get('log_enabled', True), 'log_enabled')
    s['allow_private_destinations'] = _bool(s.get('allow_private_destinations', False), 'allow_private_destinations')
    s['listener_ipv4'] = str(ipaddress.IPv4Address(s.get('listener_ipv4', s.get('bind_address', '127.0.0.1'))))
    s['max_connections'] = _integer(s.get('max_connections', 64), 'max_connections', 1, 10000)
    s['timeout_connect'] = _integer(s.get('timeout_connect', 10), 'timeout_connect', 1, 300)
    s['timeout_idle'] = _integer(s.get('timeout_idle', 300), 'timeout_idle', 1, 86400)
    for key, default in (('dns1', '127.0.0.1'), ('dns2', '8.8.8.8'), ('dns3', '1.1.1.1')):
        value = s.get(key, default)
        if not isinstance(value, str) or '%' in value:
            raise ValueError(f'{key} must be a numeric IP address')
        host, port = value, None
        if value.count(':') == 1:
            host, port = value.rsplit(':', 1)
        s[key] = str(ipaddress.ip_address(host))
        if port is not None:
            s[key] += ':' + str(_integer(port, key + ' port', 1, 65535))
    allowlist = s.get('allowed_ips', s.get('ip_whitelist', []))
    if not isinstance(allowlist, list) or len(allowlist) > 256:
        raise ValueError('allowed_ips must be a list of at most 256 IPs/CIDRs')
    s['allowed_ips'] = []
    for cidr in allowlist:
        if not isinstance(cidr, str) or '%' in cidr:
            raise ValueError('Invalid allowed IP/CIDR')
        net = ipaddress.ip_network(cidr, strict=False)
        if net.prefixlen == 0:
            raise ValueError('Whitelist must not allow the entire Internet; use explicit public mode')
        s['allowed_ips'].append(str(net))
    clean_users, names = [], set()
    for user in users:
        if not isinstance(user, dict):
            raise ValueError('Invalid user')
        name = _token(user.get('username'), 'Username', username=True)
        password = _token(user.get('password'), 'Password')
        if name in names:
            raise ValueError('Duplicate username')
        names.add(name)
        clean_users.append({'username': name, 'password': password})
    if proxies and auth == 'userpass' and not clean_users:
        raise ValueError('userpass requires at least one valid user')
    if proxies and auth == 'ip' and not s['allowed_ips']:
        raise ValueError('IP mode requires an explicit IP/CIDR allowlist')
    if proxies and auth == 'none' and not s['public_proxy']:
        raise ValueError('Public proxy mode requires explicit public_proxy=true')
    batch = _integer(PROXIES_PER_INSTANCE, 'PROXIES_PER_INSTANCE', 1, 256)
    clean_proxies, ports = [], set()
    for proxy in proxies:
        if not isinstance(proxy, dict):
            raise ValueError('Invalid proxy')
        p = dict(proxy)
        if not isinstance(p.get('ipv6'), str) or '%' in p['ipv6']:
            raise ValueError('Invalid source IPv6')
        address = ipaddress.IPv6Address(p['ipv6'])
        if address.is_unspecified or address.is_loopback or address.is_link_local or address.is_multicast or address.ipv4_mapped:
            raise ValueError('Source IPv6 must be a unicast address on the provider prefix')
        p['ipv6'] = str(address)
        p['protocol'] = p.get('protocol', 'http')
        if p['protocol'] not in ('http', 'socks5', 'dual'):
            raise ValueError('Protocol must be http, socks5 or dual')
        p['port'] = _integer(p.get('port'), 'Proxy port', 1024, 65535)
        candidates = [p['port']]
        if p['protocol'] == 'dual':
            p['socks_port'] = _integer(p.get('socks_port', p['port'] + 10000), 'SOCKS port', 1024, 65535)
            candidates.append(p['socks_port'])
        for port in candidates:
            if port in ports:
                raise ValueError('Proxy listen ports must be unique')
            ports.add(port)
        clean_proxies.append(p)
    service_budget = _integer(os.environ.get('MAX_PROXY_SERVICES', '1024'), 'MAX_PROXY_SERVICES', 1, 10000)
    connection_budget = _integer(os.environ.get('MAX_TOTAL_CONNECTIONS', '65536'), 'MAX_TOTAL_CONNECTIONS', 1, 10000000)
    if len(ports) > service_budget or len(ports) * s['max_connections'] > connection_budget:
        raise ValueError('Requested proxy services exceed the configured connection/resource budget')
    fd_limit = _integer(os.environ.get('PROXY_NOFILE_LIMIT', '65535'), 'PROXY_NOFILE_LIMIT', 256, 10000000)
    if os.name == 'posix':
        import resource
        soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft_limit != resource.RLIM_INFINITY:
            fd_limit = min(fd_limit, soft_limit)
    for offset in range(0, len(clean_proxies), batch):
        services = sum(2 if proxy['protocol'] == 'dual' else 1 for proxy in clean_proxies[offset:offset + batch])
        # Each active TCP connection needs client+upstream descriptors. Reserve
        # listeners plus DNS/log/control overhead per foreground process.
        if services * s['max_connections'] * 2 + services + 128 > fd_limit:
            raise ValueError('Per-instance connection budget exceeds RLIMIT_NOFILE; lower max_connections or instance grouping')
    s['_proxies_per_instance'] = batch
    return clean_proxies, clean_users, s


def _calc_instance_count(total_proxies):
    return math.ceil(total_proxies / _integer(PROXIES_PER_INSTANCE, 'PROXIES_PER_INSTANCE', 1, 256)) if total_proxies else 0


def _generate_single_config(proxies, users, settings, instance_index=0, total_instances=1):
    proxies, users, settings = validate_config_inputs(proxies, users, settings)
    root = _path_token(DATA_DIR)
    lines = ['# Managed 3proxy config; foreground process', f'# Instance {instance_index + 1}/{total_instances}']
    lines += [f'nserver {settings[key]}' for key in ('dns1', 'dns2', 'dns3')]
    lines += ['nscache 65536', 'nscache6 65536']
    # BYTE_SHORT BYTE_LONG STRING_SHORT STRING_LONG CONNECTION_SHORT
    # CONNECTION_LONG DNS CHAIN CONNECT CONNECTBACK (3proxy manual).
    lines += [f"timeouts 1 5 30 60 {settings['timeout_idle']} {settings['timeout_idle']} 15 60 {settings['timeout_connect']} 5"]
    if settings['log_enabled']:
        lines += [f'log {root}/logs/3proxy_{instance_index}.log D', 'logformat "L%t.%. %N.%p %E %U %C:%c %R:%r %O %I"', 'rotate 7']
    else:
        lines += ['log /dev/null']
    lines += [f"maxconn {settings['max_connections']}"]
    # Destination filtering must use an ACL-aware auth type; 'auth none' skips ACLs.
    if settings['auth_type'] == 'userpass':
        lines += [f'users {user["username"]}:CL:{user["password"]}' for user in users]
        lines += ['auth strong']
    else:
        lines += ['auth iponly']
    if not settings['allow_private_destinations']:
        lines += ['deny * * ' + PRIVATE_DESTINATIONS]
    if settings['auth_type'] == 'userpass':
        lines += ['allow ' + user['username'] for user in users] + ['deny *']
    elif settings['auth_type'] == 'ip':
        lines += ['allow * ' + ','.join(settings['allowed_ips']), 'deny *']
    else:
        lines += ['# Explicit public mode: no credentials, destination ACL retained', 'allow *', 'deny *']
    for proxy in proxies:
        lines += [f"external {proxy['ipv6']}", f"internal {settings['listener_ipv4']}"]
        if proxy['protocol'] in ('http', 'dual'):
            lines += [f"proxy -6 -p{proxy['port']}"]
        if proxy['protocol'] == 'socks5':
            lines += [f"socks -6 -p{proxy['port']}"]
        elif proxy['protocol'] == 'dual':
            lines += [f"external {proxy['ipv6']}", f"internal {settings['listener_ipv4']}", f"socks -6 -p{proxy['socks_port']}"]
    return '\n'.join(lines) + '\n'


def _manifest_path():
    return Path(DATA_DIR) / 'config-manifest.json'


def _process_path():
    return Path(DATA_DIR) / 'owned-processes.json'


def _atomic_write(path, content):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700 if os.name == 'posix' else 0o777)
    fd, name = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(content if isinstance(content, bytes) else content.encode('utf-8'))
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, 0o600)
        os.replace(name, path)
        if os.name == 'posix':
            directory = os.open(str(path.parent), os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _json_write(path, value):
    _atomic_write(path, json.dumps(value, sort_keys=True, indent=2) + '\n')


def _config_location(instance):
    location = (Path(DATA_DIR) / instance['path']).resolve()
    root = (Path(DATA_DIR) / 'configs').resolve()
    if not location.is_relative_to(root) or location.suffix != '.cfg':
        raise ValueError('Manifest config path escapes the managed configs directory')
    return location


def _validate_manifest(manifest):
    if not isinstance(manifest, dict) or manifest.get('version') != 1 or not isinstance(manifest.get('instances'), list):
        raise ValueError('Invalid config manifest')
    if len(manifest['instances']) > 10000:
        raise ValueError('Invalid config manifest instance count')
    generation = manifest.get('generation')
    if not (isinstance(generation, str) and re.fullmatch(r'[0-9a-f]{32}', generation)):
        if generation is not None or manifest['instances']:
            raise ValueError('Invalid config manifest generation')
    listeners = set()
    for index, instance in enumerate(manifest['instances']):
        if not isinstance(instance, dict) or type(instance.get('index')) is not int or instance['index'] != index:
            raise ValueError('Invalid manifest instance index')
        if not isinstance(instance.get('path'), str) or not isinstance(instance.get('sha256'), str) or not re.fullmatch(r'[0-9a-f]{64}', instance['sha256']):
            raise ValueError('Invalid manifest config metadata')
        location = _config_location(instance)
        if location.parent.name != generation:
            raise ValueError('Manifest config generation mismatch')
        if not isinstance(instance.get('listeners'), list) or not 1 <= len(instance['listeners']) <= 512:
            raise ValueError('Invalid manifest listeners')
        for listener in instance['listeners']:
            if not isinstance(listener, dict) or not isinstance(listener.get('address'), str):
                raise ValueError('Invalid manifest listener address')
            address = str(ipaddress.IPv4Address(listener['address']))
            port = _integer(listener.get('port'), 'Manifest listener port', 1024, 65535)
            if listener.get('protocol') not in ('http', 'socks5') or (address, port) in listeners:
                raise ValueError('Invalid or duplicate manifest listener')
            listeners.add((address, port))
        if hashlib.sha256(location.read_bytes()).hexdigest() != instance['sha256']:
            raise ValueError('Managed config checksum mismatch')
    return manifest


def _load_manifest():
    path = _manifest_path()
    if not path.exists():
        return {'version': 1, 'generation': None, 'instances': []}
    return _validate_manifest(json.loads(path.read_text(encoding='utf-8')))


def generate_config(proxies, users, settings):
    """Stage immutable configs; the active manifest switches only on success."""
    proxies, users, settings = validate_config_inputs(proxies, users, settings)
    generation, batch = uuid.uuid4().hex, settings['_proxies_per_instance']
    chunks = [proxies[i:i + batch] for i in range(0, len(proxies), batch)]
    configs = [_generate_single_config(chunk, users, settings, i, len(chunks)) for i, chunk in enumerate(chunks)]
    manifest = {'version': 1, 'generation': generation, 'instances': []}
    for index, (chunk, config) in enumerate(zip(chunks, configs)):
        listeners = []
        for proxy in chunk:
            listeners.append({'address': settings['listener_ipv4'], 'port': proxy['port'], 'protocol': 'http' if proxy['protocol'] == 'dual' else proxy['protocol']})
            if proxy['protocol'] == 'dual':
                listeners.append({'address': settings['listener_ipv4'], 'port': proxy['socks_port'], 'protocol': 'socks5'})
        manifest['instances'].append({'index': index, 'path': f'configs/{generation}/3proxy_{index}.cfg',
                                     'sha256': hashlib.sha256(config.encode('utf-8')).hexdigest(), 'listeners': listeners})
    for config, instance in zip(configs, manifest['instances']):
        _atomic_write(Path(DATA_DIR) / instance['path'], config)
    if settings['log_enabled'] and proxies:
        (Path(DATA_DIR) / 'logs').mkdir(parents=True, exist_ok=True, mode=0o700 if os.name == 'posix' else 0o777)
    _json_write(_manifest_path(), manifest)
    return configs[0] if configs else ''


def save_config(config_content):
    """Compatibility copy only: the active manifest is the startup authority."""
    if not isinstance(config_content, str):
        raise ValueError('Config content must be text')
    path = Path(DATA_DIR) / '3proxy.cfg'
    _atomic_write(path, config_content)
    return str(path)


def snapshot_configs():
    _load_manifest()
    return {'manifest': _manifest_path().read_text(encoding='utf-8') if _manifest_path().exists() else None,
            'legacy': (Path(DATA_DIR) / '3proxy.cfg').read_text(encoding='utf-8') if (Path(DATA_DIR) / '3proxy.cfg').exists() else None}


def restore_configs(snapshot):
    if not isinstance(snapshot, dict) or set(snapshot) != {'manifest', 'legacy'}:
        raise ValueError('Invalid config snapshot')
    if snapshot['manifest'] is not None:
        _validate_manifest(json.loads(snapshot['manifest']))
    for path, content in ((Path(DATA_DIR) / '3proxy.cfg', snapshot['legacy']), (_manifest_path(), snapshot['manifest'])):
        if content is None:
            path.unlink(missing_ok=True)
        else:
            _atomic_write(path, content)


def prune_configs(retain=8, protected_generations=()):
    """Bound config history after a committed transaction; preserve active/PIDs.

    The caller may protect additional generations for a pending rollback/backup.
    Snapshots for durable backups must include the corresponding config files.
    """
    retain = _integer(retain, 'Config history retention', 2, 1000)
    root = (Path(DATA_DIR) / 'configs').resolve()
    if not root.exists():
        return 0
    protected = set(protected_generations)
    protected.add(_load_manifest().get('generation'))
    protected.update(r.get('generation') for r in _load_processes() if _owns_process(r))
    directories = sorted((p for p in root.iterdir() if p.is_dir() and re.fullmatch(r'[0-9a-f]{32}', p.name)),
                         key=lambda p: p.stat().st_mtime_ns, reverse=True)
    protected.update(p.name for p in directories[:retain])
    removed = 0
    for path in directories:
        if path.name not in protected:
            # Verify final recursive-delete target in this same Python process.
            resolved = path.resolve()
            if path.is_symlink() or not resolved.is_relative_to(root) or resolved == root:
                raise ValueError('Config cleanup target escapes managed directory')
            shutil.rmtree(resolved)
            removed += 1
    return removed


def _get_instance_count():
    return len(_load_manifest()['instances'])


def _instance_config_path(index):
    return str(_config_location(_load_manifest()['instances'][index]))


def _instance_pid_path(index):
    return str(Path(DATA_DIR) / f'3proxy_{index}.pid')


def _read_pid_file(path):
    try:
        return int(Path(path).read_text(encoding='ascii').strip())
    except (OSError, ValueError):
        return None


def _read_identity(pid):
    try:
        root = Path('/proc') / str(int(pid))
        stat = (root / 'stat').read_text().rsplit(')', 1)[1].split()
        if stat[0] in ('Z', 'X'):
            return None
        return {'pid': int(pid), 'start_time': stat[19], 'exe': os.path.realpath(root / 'exe'),
                'cmdline': [os.fsdecode(arg) for arg in (root / 'cmdline').read_bytes().split(b'\0') if arg],
                'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()}
    except (OSError, ValueError, IndexError, TypeError):
        return None


def _check_pid(pid):
    return _read_identity(pid) is not None


def _load_processes():
    path = _process_path()
    if not path.exists():
        return []
    records = json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(records, list) or len(records) > 10000:
        raise ValueError('Invalid owned-process ledger')
    seen = set()
    root = (Path(DATA_DIR) / 'configs').resolve()
    for record in records:
        if not isinstance(record, dict) or type(record.get('pid')) is not int or record['pid'] <= 0 or record['pid'] in seen:
            raise ValueError('Invalid owned-process PID')
        if not isinstance(record.get('start_time'), str) or not re.fullmatch(r'[0-9]+', record['start_time']):
            raise ValueError('Invalid owned-process start time')
        if not all(isinstance(record.get(key), str) and record[key] and '\x00' not in record[key] for key in ('exe', 'boot_id', 'config', 'generation')):
            raise ValueError('Invalid owned-process identity')
        if not isinstance(record.get('cmdline'), list) or not 1 <= len(record['cmdline']) <= 64 or not all(isinstance(arg, str) and arg and '\x00' not in arg for arg in record['cmdline']):
            raise ValueError('Invalid owned-process command identity')
        if type(record.get('index')) is not int or not 0 <= record['index'] < 10000 or not re.fullmatch(r'[0-9a-f]{32}', record['generation']):
            raise ValueError('Invalid owned-process generation')
        location = Path(record['config']).resolve()
        if not location.is_relative_to(root) or location.suffix != '.cfg' or location.parent.name != record['generation'] or str(location) != record['config']:
            raise ValueError('Owned-process config path escapes its generation')
        seen.add(record['pid'])
    return records


def _owns_process(record):
    if not isinstance(record, dict) or type(record.get('pid')) is not int or record['pid'] <= 0:
        return False
    current = _read_identity(record.get('pid'))
    return bool(current and all(current.get(key) == record.get(key) for key in ('pid', 'start_time', 'exe', 'cmdline', 'boot_id'))
                and current['exe'] == os.path.realpath(PROXY_BINARY)
                and str(record.get('config')) in current['cmdline'])


def _signal_owned(record, sig):
    """Pin the PID before re-checking identity to prevent PID-reuse races."""
    if not hasattr(os, 'pidfd_open') or not hasattr(signal, 'pidfd_send_signal'):
        raise OSError('Owned-process signalling requires Linux pidfd support')
    try:
        pidfd = os.pidfd_open(record['pid'])
    except ProcessLookupError:
        return
    try:
        if _owns_process(record):
            signal.pidfd_send_signal(pidfd, sig)
    except ProcessLookupError:
        pass
    finally:
        os.close(pidfd)


def _listener_set(pid):
    """Read listening socket inodes owned by the PID, not arbitrary host ports."""
    root, inodes = Path('/proc') / str(pid), set()
    for fd in (root / 'fd').iterdir():
        try:
            link = os.readlink(fd)
            if link.startswith('socket:['):
                inodes.add(link[8:-1])
        except OSError:
            continue
    listeners = set()
    for filename, family in (('tcp', socket.AF_INET), ('tcp6', socket.AF_INET6)):
        for line in (root / 'net' / filename).read_text().splitlines()[1:]:
            columns = line.split()
            if len(columns) < 10 or columns[3] != '0A' or columns[9] not in inodes:
                continue
            address_hex, port_hex = columns[1].split(':')
            raw = bytes.fromhex(address_hex)
            raw = raw[::-1] if family == socket.AF_INET else b''.join(raw[i:i + 4][::-1] for i in range(0, 16, 4))
            listeners.add((socket.inet_ntop(family, raw), int(port_hex, 16)))
    return listeners


def running_instances():
    result = {'ready': False, 'expected': 0, 'running': 0, 'active_running': 0,
              'instances': [], 'orphaned_instances': [], 'errors': []}
    try:
        # The ledger, not the current manifest, defines which processes we own.
        # Count it first so a replaced/empty/corrupt manifest cannot hide them.
        records = _load_processes()
        owned_records = [record for record in records if _owns_process(record)]
        result['running'] = len({record['pid'] for record in owned_records})
        manifest = _load_manifest()
        result['expected'] = len(manifest['instances'])
        active = {(instance['index'], str(_config_location(instance))) for instance in manifest['instances']}
        result['orphaned_instances'] = [{'index': record.get('index'), 'pid': record['pid'], 'config': record['config']}
                                        for record in owned_records if (record.get('index'), record.get('config')) not in active]
        if result['orphaned_instances']:
            result['errors'].append('Owned processes remain outside the active generation')
        for instance in manifest['instances']:
            config = str(_config_location(instance))
            matching = [r for r in owned_records if r.get('config') == config and r.get('index') == instance['index']]
            record = matching[0] if matching else None
            owned = bool(record)
            if len(matching) > 1:
                result['errors'].append(f"Instance {instance['index']}: multiple owned children use the active config")
            entry = {'index': instance['index'], 'pid': record.get('pid') if record else None, 'owned': owned,
                     'ready': False, 'listeners': instance['listeners'], 'missing_listeners': []}
            if owned:
                result['active_running'] += len(matching)
                try:
                    observed = _listener_set(record['pid'])
                    entry['missing_listeners'] = [item for item in instance['listeners'] if (item['address'], item['port']) not in observed]
                    if not _owns_process(record):
                        entry['owned'] = False
                        result['errors'].append(f"Instance {instance['index']}: ownership changed during listener inspection")
                    else:
                        entry['ready'] = not entry['missing_listeners']
                except OSError:
                    result['errors'].append(f"Instance {instance['index']}: listener inspection failed")
            result['instances'].append(entry)
        result['ready'] = bool(result['expected']) and all(entry['ready'] for entry in result['instances']) and not result['errors']
    except (OSError, ValueError, KeyError, TypeError) as exc:
        result['errors'].append(type(exc).__name__ + ': configuration/process metadata invalid')
    return result


def _read_process_metrics(pid):
    """Linux observation only; return no command line, config, or credential data."""
    root = Path('/proc') / str(pid)
    status = (root / 'status').read_text(encoding='ascii')
    match = re.search(r'^VmRSS:\s*([0-9]+)\s+kB\s*$', status, re.MULTILINE)
    if not match:
        raise ValueError('RSS observation unavailable')
    return {'rss_bytes': int(match.group(1)) * 1024, 'fd_count': sum(1 for _ in (root / 'fd').iterdir())}


def process_metrics():
    """Aggregate verified owned children, including old-generation children.

    Recheck the full PID/start-time/executable/config identity after /proc reads.
    A failed observation is null rather than a misleading zero/partial total.
    """
    result = {'rss_bytes': 0, 'fd_count': 0, 'process_count': 0, 'errors': []}
    try:
        records = _load_processes()
        seen = set()
        for record in records:
            if record['pid'] in seen or not _owns_process(record):
                continue
            seen.add(record['pid'])
            sample = None
            try:
                sample = _read_process_metrics(record['pid'])
            except (OSError, ValueError, UnicodeError):
                result['errors'].append('Owned-process resource observation unavailable')
            if not _owns_process(record):
                result['errors'].append('Owned-process identity changed during resource observation')
                result['process_count'] = None
                continue
            if result['process_count'] is not None:
                result['process_count'] += 1
            if sample is not None:
                result['rss_bytes'] += sample['rss_bytes']
                result['fd_count'] += sample['fd_count']
    except (OSError, ValueError, KeyError, TypeError):
        result['errors'].append('Owned-process resource metadata invalid')
        result['process_count'] = None
    if result['errors']:
        result['rss_bytes'] = result['fd_count'] = None
    return result


def _get_running_instances():
    return [(entry['index'], entry['pid']) for entry in running_instances()['instances'] if entry['owned']]


def is_3proxy_running():
    health = running_instances()
    return health['ready'], next((entry['pid'] for entry in health['instances'] if entry['owned']), None)


def start_3proxy():
    started_here = []
    try:
        manifest = _load_manifest()
        if not manifest['instances']:
            return False, 'No managed proxy configuration; generate proxies first'
        records = _load_processes()
        for instance in manifest['instances']:
            config = str(_config_location(instance))
            if any(r.get('config') == config and _owns_process(r) for r in records):
                continue
            process = subprocess.Popen([PROXY_BINARY, config], stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)
            _CHILDREN[process.pid] = process
            started_here.append(process.pid)
            deadline, identity = time.monotonic() + 2.0, None
            while time.monotonic() < deadline:
                identity = _read_identity(process.pid)
                if identity and identity['exe'] == os.path.realpath(PROXY_BINARY) and config in identity['cmdline']:
                    break
                if process.poll() is not None:
                    break
                time.sleep(0.05)
            if not identity or identity['exe'] != os.path.realpath(PROXY_BINARY) or config not in identity['cmdline']:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
                raise RuntimeError('Started child failed executable/config identity validation')
            record = dict(identity, index=instance['index'], config=config, generation=manifest['generation'])
            records = [r for r in records if _owns_process(r)] + [record]
            _json_write(_process_path(), records)
        deadline = time.monotonic() + START_TIMEOUT
        while time.monotonic() < deadline:
            health = running_instances()
            if health['ready']:
                return True, f"3proxy ready: {health['running']}/{health['expected']} owned instances and all listeners"
            time.sleep(0.1)
        raise RuntimeError('Not all expected instances/listeners became ready')
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as exc:
        if started_here:
            # Ledger persistence may itself have failed. Our unreaped Popen
            # children still identify the exact spawned child; clean them too.
            for pid in started_here:
                child = _CHILDREN.get(pid)
                if child is not None and child.poll() is None:
                    try:
                        child.terminate()
                        child.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        child.kill()
                        child.wait(timeout=2)
                    except OSError:
                        pass
            stop_3proxy()
        logger.error('3proxy startup failed: %s', type(exc).__name__)
        return False, '3proxy startup failed; no partial success: ' + str(exc)


def stop_3proxy():
    try:
        records = _load_processes()
        for sig, duration in ((signal.SIGTERM, STOP_TIMEOUT), (getattr(signal, 'SIGKILL', 9), 2.0)):
            for record in records:
                if _owns_process(record):
                    _signal_owned(record, sig)
            deadline = time.monotonic() + duration
            while time.monotonic() < deadline and any(_owns_process(record) for record in records):
                for pid, child in list(_CHILDREN.items()):
                    if child.poll() is not None:
                        _CHILDREN.pop(pid, None)
                time.sleep(0.05)
            if not any(_owns_process(record) for record in records):
                _json_write(_process_path(), [])
                return True, 'All owned 3proxy processes observed stopped; unrelated PIDs untouched'
        return False, 'Owned 3proxy processes remain running after TERM/KILL'
    except (OSError, ValueError, KeyError, TypeError) as exc:
        logger.error('3proxy stop failed: %s', type(exc).__name__)
        return False, '3proxy stop could not be verified'


def restart_3proxy():
    stopped, message = stop_3proxy()
    if not stopped:
        return False, message
    return start_3proxy()
