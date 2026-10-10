#!/usr/bin/env python3
"""Create one private, inactive VPS watchdog instance for a separate server/bot.

No existing configuration is overwritten. This command performs no HTTP
requests and never installs, enables, or starts a systemd service. The generated
environment file is a systemd EnvironmentFile, not a shell script.
"""
import argparse
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import re
import secrets
import shlex
import sys


TAILSCALE_V4 = ipaddress.ip_network('100.64.0.0/10')
TAILSCALE_V6 = ipaddress.ip_network('fd7a:115c:a1e0::/48')
SLUG = re.compile(r'[a-z][a-z0-9-]{0,31}\Z', re.ASCII)


@dataclass(frozen=True)
class NodePaths:
    directory: Path
    environment: Path
    data: Path
    unit: Path
    service_name: str


def _plain_path(value):
    text = os.fspath(value)
    if not isinstance(text, str) or any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ValueError('Root path contains invalid characters')
    # These systemd fields do not share a shell-like quoted-string parser:
    # WorkingDirectory retains quotes literally. Use portable unquoted paths,
    # and reject metacharacters rather than emitting ambiguous unit directives.
    pattern = r'[A-Za-z0-9_./:\\-]+' if os.name == 'nt' else r'/[A-Za-z0-9_./-]*'
    if not re.fullmatch(pattern, text, re.ASCII):
        raise ValueError('Root path supports only ASCII letters, digits, slash, dot, underscore and hyphen')
    path = Path(text)
    if not path.is_absolute():
        raise ValueError('Root path must be absolute')
    # Do not let an apparently scoped root traverse a symlinked ancestor.
    for ancestor in (path, *path.parents):
        if ancestor.is_symlink():
            raise ValueError('Root path and ancestors must not be symlinks')
    if not path.is_dir():
        raise ValueError('Root directory must already exist')
    return path.resolve()


def _tailscale_address(value):
    try:
        # Scoped IPv6 is not accepted: it is unnecessary for a Tailscale ULA.
        if not isinstance(value, str) or '%' in value:
            raise ValueError
        address = ipaddress.ip_address(value)
        allowed = TAILSCALE_V4 if address.version == 4 else TAILSCALE_V6
        if address not in allowed:
            raise ValueError
        return address.compressed
    except ValueError:
        raise ValueError('Bind must be a literal Tailscale IPv4 or IPv6 address') from None


def _environment_quote(value):
    # EnvironmentFile does not expand dollars or specifiers in its values.
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'


def _write_private(path, text):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
        descriptor = None
        path.chmod(0o600)
    finally:
        if descriptor is not None:
            # fdopen can fail before taking ownership of the descriptor.
            try:
                os.close(descriptor)
            except OSError:
                pass


def _configured_port(path):
    if path.is_symlink():
        raise ValueError('Existing configuration must not be a symlink')
    if not path.exists():
        return None
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    with os.fdopen(os.open(path, flags), 'r', encoding='utf-8') as stream:
        content = stream.read(65537)
    if len(content) > 65536:
        raise ValueError('Existing configuration is too large to validate')
    found = None
    for line in content.splitlines():
        key, separator, value = line.partition('=')
        if separator and key.strip() == 'WATCHDOG_PORT':
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            if not value.isascii() or not value.isdigit() or found is not None:
                raise ValueError('Existing watchdog port configuration is invalid')
            found = int(value)
    return found


def _check_configured_ports(root, parent, port):
    candidates = [root / 'watchdog.env']
    if parent.exists():
        candidates.extend(entry / 'watchdog.env' for entry in parent.iterdir()
                          if not entry.is_symlink() and entry.is_dir())
    for candidate in candidates:
        if _configured_port(candidate) == port:
            raise ValueError('Port is already assigned to another configured watchdog')


def create_node(root, name, bind, port=8089, timeout=180):
    """Return paths only; the newly generated shared token stays in its file."""
    if not isinstance(name, str) or not SLUG.fullmatch(name):
        raise ValueError('Name must be a lowercase slug of 1 to 32 characters')
    if isinstance(port, bool) or not isinstance(port, int) or not 8089 <= port <= 65535:
        raise ValueError('Port must be an integer from 8089 to 65535')
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 30 <= timeout <= 86400:
        raise ValueError('Timeout must be an integer from 30 to 86400 seconds')
    bind = _tailscale_address(bind)
    root = _plain_path(root)
    parent = root / 'nodes'
    if parent.is_symlink() or (parent.exists() and not parent.is_dir()):
        raise ValueError('Nodes path must be a regular directory')
    directory = parent / name
    if directory.is_symlink() or directory.exists():
        raise FileExistsError('Node already exists; its configuration was preserved')
    _check_configured_ports(root, parent, port)
    if not parent.exists():
        parent.mkdir(mode=0o700)
    parent.chmod(0o700)
    if parent.resolve().parent != root:
        raise ValueError('Nodes path must remain inside root')
    # is_symlink also catches broken links; mkdir(exist_ok=False) is the atomic
    # no-overwrite check for an existing file, directory, or symlink.
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    data = directory / 'data'
    data.mkdir(mode=0o700)
    data.chmod(0o700)
    environment = directory / 'watchdog.env'
    unit = directory / 'node.service'
    service_name = f'clbip-watchdog-{name}.service'
    token = secrets.token_urlsafe(48)
    _write_private(environment, '\n'.join([
        '# Private systemd EnvironmentFile; do not source as a shell script.',
        '# Fill only the two Telegram fields. Keep the unique heartbeat token.',
        'TELEGRAM_BOT_TOKEN=',
        'TELEGRAM_CHAT_ID=',
        f'WATCHDOG_SHARED_TOKEN={token}',
        f'WATCHDOG_NODE_NAME={name}',
        f'WATCHDOG_BIND={bind}',
        f'WATCHDOG_PORT={port}',
        f'WATCHDOG_TIMEOUT={timeout}',
        'WATCHDOG_CHECK_INTERVAL=5',
        f'DATA_DIR={_environment_quote(data)}',
        '',
    ]))
    script = root / 'external_watchdog.py'
    command = '/usr/bin/python3 ' + str(script)
    _write_private(unit, '\n'.join([
        '[Unit]',
        f'Description=CLBIP watchdog for {name}',
        'Wants=network-online.target tailscaled.service',
        'After=network-online.target tailscaled.service',
        # tailscaled being active does not guarantee its bind IP is assigned
        # already. Keep retrying after warm-up instead of exhausting a burst.
        'StartLimitIntervalSec=0',
        '',
        '[Service]',
        'Type=simple',
        'User=ubuntu',
        'Group=ubuntu',
        f'WorkingDirectory={root}',
        f'EnvironmentFile={environment}',
        'Environment=PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1',
        f'ExecStartPre={command} --check',
        f'ExecStart={command}',
        'Restart=on-failure',
        'RestartSec=10',
        'UMask=0077',
        'NoNewPrivileges=yes',
        'PrivateTmp=yes',
        'ProtectSystem=strict',
        'ProtectHome=read-only',
        f'ReadWritePaths={data}',
        'RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX',
        'CapabilityBoundingSet=',
        '',
        '[Install]',
        'WantedBy=multi-user.target',
        '',
    ]))
    return NodePaths(directory, environment, data, unit, service_name)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default='/home/ubuntu/clbip-watchdog',
                        help='Existing watchdog application directory')
    parser.add_argument('--name', required=True, help='Unique lowercase node slug')
    parser.add_argument('--bind', required=True, help='Literal Tailscale IP on this VPS')
    parser.add_argument('--port', type=int, default=8089, help='Unique port, 8089..65535')
    parser.add_argument('--timeout', type=int, default=180, help='Missing-heartbeat deadline in seconds')
    args = parser.parse_args(argv)
    try:
        paths = create_node(args.root, args.name, args.bind, args.port, args.timeout)
    except ValueError as error:
        print(f'Error: {error}', file=sys.stderr)
        return 2
    except OSError as error:
        print(f'Error: node creation failed ({type(error).__name__}); existing files were not overwritten',
              file=sys.stderr)
        return 1
    print(f'Created private configuration: {paths.environment}')
    print(f'Created isolated data directory: {paths.data}')
    print('Fill TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID without changing WATCHDOG_SHARED_TOKEN:')
    print('  nano -- ' + shlex.quote(str(paths.environment)))
    print('Service is not installed or started. After filling the Telegram fields:')
    destination = '/etc/systemd/system/' + paths.service_name
    print('  sudo install -o root -g root -m 0644 ' + shlex.quote(str(paths.unit)) + ' ' + shlex.quote(destination))
    print('  sudo systemctl daemon-reload')
    print('  sudo systemctl enable --now ' + shlex.quote(paths.service_name))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
