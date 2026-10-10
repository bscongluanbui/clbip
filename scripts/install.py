#!/usr/bin/env python3
"""Install a Linux Compose deployment without replacing secrets or volumes."""
from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import shlex
import stat
import sys
import time
from types import SimpleNamespace

try:
    from .doctor import ComposeProject, Redactor, RPC_CHECK, dashboard_address, http_probe, run_command
    from .change_dashboard_port import atomic_write, probe_port, update_lock, valid_port
except ImportError:
    from doctor import ComposeProject, Redactor, RPC_CHECK, dashboard_address, http_probe, run_command
    from change_dashboard_port import atomic_write, probe_port, update_lock, valid_port

BASE_COMPOSE = 'docker-compose.yml'
BUILD_COMPOSE = 'docker-compose.build.yml'
BUILD_FILES = BASE_COMPOSE + ':' + BUILD_COMPOSE
LOCAL_IMAGE = 'ipv6-proxy-manager:local'
LISTENER_CHECK = "import json,os; print(json.dumps({'bind':os.getenv('GUI_BIND','127.0.0.1'),'port':os.getenv('GUI_PORT','7070')}))"


def read_env(path):
    """Read only deployment selectors; Compose itself resolves the full env file."""
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError('.env must be a regular file, not a symlink')
    raw = path.read_bytes() if path.exists() else b''
    values = {}
    for line in raw.decode('utf-8').splitlines():
        match = re.match(r'^\s*(?:export\s+)?(COMPOSE_FILE|GUI_BIND|GUI_PORT|IPV6_MANAGER_IMAGE)\s*=\s*(.*)$', line)
        if match:
            pieces = shlex.split(match[2], comments=True, posix=True)
            if len(pieces) > 1:
                raise ValueError('Invalid .env deployment selector: ' + match[1])
            values[match[1]] = pieces[0] if pieces else ''
    return raw, values


def update_env(original, changes):
    """Keep comments, unknown settings and line endings; collapse edited duplicates."""
    text = original.decode('utf-8')
    newline = '\r\n' if '\r\n' in text else '\n'
    lines, found = [], set()
    for line in text.splitlines(keepends=True):
        match = re.match(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=', line)
        name = match[1] if match else None
        if name in changes:
            if name not in found:
                lines.append(name + '=' + changes[name] + newline)
                found.add(name)
        else:
            lines.append(line)
    for name, value in changes.items():
        if name not in found:
            if lines and not lines[-1].endswith(('\n', '\r')):
                lines.append(newline)
            lines.append(name + '=' + value + newline)
    return ''.join(lines).encode('utf-8')


def validate_bind(value):
    address = ipaddress.ip_address(value)
    if address.is_multicast:
        raise ValueError('GUI_BIND must be a unicast or wildcard IP address')
    return str(address)


class Installer:
    def __init__(self, root=None, *, runner=run_command, probe=http_probe,
                 port_probe=probe_port, sleep=time.sleep, monotonic=time.monotonic,
                 system=platform.system, out=None):
        self.root = Path(root or Path(__file__).resolve().parents[1]).resolve()
        self.runner, self.probe, self.port_probe = runner, probe, port_probe
        self.sleep, self.monotonic, self.system = sleep, monotonic, system
        self.out = sys.stdout if out is None else out
        self.redact = Redactor()
        self.project = None
        self.child_env = dict(os.environ)

    def say(self, message):
        print(self.redact(message), file=self.out, flush=True)

    def execute(self, command, *, timeout=20):
        result = self.runner(command, timeout=timeout, cwd=str(self.root), env=self.child_env)
        if result['exit'] != 0 or result.get('timeout'):
            raise RuntimeError(shlex.join(command) + '\nexit=' + str(result['exit']) + '\n' + result['output'])
        return result['output']

    def compose(self, *arguments, timeout=20):
        result = self.project.command(*arguments, timeout=timeout, env=self.child_env)
        if result.get('output'):
            self.say(result['output'].rstrip())
        if result['exit'] != 0 or result.get('timeout'):
            raise RuntimeError('Compose ' + shlex.join(arguments) + ' failed; exit=' + str(result['exit']))
        return result

    def validate_secrets(self):
        directory = self.root / 'secrets'
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise ValueError('secrets must be a regular directory, not a symlink')
        for name in ('admin_password', 'secret_key', 'service_token'):
            path = directory / name
            self.redact.add_file(path)
            if path.is_symlink() or (path.exists() and not path.is_file()):
                raise ValueError('Secret must be a regular file: ' + name)
            if not path.exists():
                self.say('Missing deployment file secrets/' + name + '; installer will create it')
                continue
            raw = path.read_bytes()
            if len(raw) > 4096:
                raise ValueError('Deployment secret is too large: ' + name)
            value = raw.decode('utf-8').strip()
            if name != 'admin_password' and len(value) < 32:
                raise ValueError('Existing deployment secret is shorter than 32 characters: ' + name)

    def initialize_secrets(self):
        directory = self.root / 'secrets'
        output = self.execute([sys.executable, str(self.root / 'scripts' / 'init_secrets.py'),
                               '--directory', str(directory), '--no-dashboard-password'])
        self.say(output.rstrip())
        for name in ('admin_password', 'secret_key', 'service_token'):
            path = directory / name
            # File-backed Compose secrets keep host modes; the non-root dashboard
            # needs readable files, while their parent stays host-owner-only.
            if os.name == 'posix':
                path.chmod(0o444)
            self.redact.add_file(path)

    def prepare(self, args):
        if not self.root.is_dir():
            raise ValueError('Repository directory does not exist')
        if self.system() != 'Linux':
            raise ValueError('Installer requires Linux Docker Engine with host networking')
        if not 1 <= args.wait_timeout <= 3600:
            raise ValueError('--wait-timeout must be in 1..3600 seconds')
        self.original_env, values = read_env(self.root / '.env')
        self.redact.learn_env_file(self.root / '.env')
        self.changes = {}
        if args.bind is not None:
            self.changes['GUI_BIND'] = validate_bind(args.bind)
        if args.port is not None:
            self.changes['GUI_PORT'] = str(valid_port(args.port))
        if args.build:
            self.changes.update(COMPOSE_FILE=BUILD_FILES, IPV6_MANAGER_IMAGE=LOCAL_IMAGE)
        values.update(self.changes)
        selectors = values.get('COMPOSE_FILE') or BASE_COMPOSE
        files = selectors.split(':')
        if not all(files):
            raise ValueError('COMPOSE_FILE contains an empty file entry')
        self.project = ComposeProject(self.root, compose_files=files, runner=self.runner)
        self.local_build = (self.root / BUILD_COMPOSE).resolve() in self.project.files
        # Explicit files prevent shell COMPOSE_FILE from changing the selected mode.
        self.child_env.pop('COMPOSE_FILE', None)
        for key in ('GUI_BIND', 'GUI_PORT', 'IPV6_MANAGER_IMAGE'):
            if key in values:
                self.child_env[key] = values[key]
        version = self.execute(['docker', 'compose', 'version', '--short']).strip()
        if not re.match(r'^v?2\.', version):
            raise ValueError('Docker Compose v2 is required; detected: ' + version)
        engine = self.execute(['docker', 'info', '--format', '{{.OSType}}/{{.Architecture}}']).strip()
        if engine not in {'linux/amd64', 'linux/x86_64', 'linux/arm64', 'linux/aarch64', 'linux/arm', 'linux/armv7l'}:
            raise ValueError('Expected a Linux amd64/arm64/armv7 Docker Engine; detected: ' + engine)
        self.say('PREFLIGHT_DOCKER=OK COMPOSE=' + version + ' ENGINE=' + engine)
        self.validate_secrets()
        config = self.project.config(env=self.child_env)
        self.redact.learn(config)
        self.bind, self.port, self.url = dashboard_address(config)
        validate_bind(self.bind)
        for role in ('worker', 'dashboard'):
            if config['services'].get(role, {}).get('network_mode') != 'host':
                raise ValueError('Expected host networking for ' + role)
        try:
            self.port_probe(self.bind, self.port)
        except OSError as exc:
            if exc.errno not in (errno.EADDRINUSE, 10048) or not self.existing_dashboard_owns_listener():
                raise ValueError(f'Dashboard listener {self.bind}:{self.port} is unavailable: {exc}') from exc
            self.say('PREFLIGHT_PORT=OWNED_BY_EXISTING_DASHBOARD')
        else:
            self.say('PREFLIGHT_PORT=AVAILABLE')
        self.say('PREFLIGHT_CONFIG=OK MODE=' + ('build' if self.local_build else 'image'))

    def existing_dashboard_owns_listener(self):
        result = self.project.command('exec', '-T', 'dashboard', 'python', '-B', '-c', LISTENER_CHECK,
                                      timeout=8, env=self.child_env)
        if result['exit'] != 0:
            return False
        try:
            state = json.loads(result['output'])
            existing = ipaddress.ip_address(validate_bind(state['bind']))
            requested = ipaddress.ip_address(self.bind)
            # A wildcard and a specific address in the same address family overlap.
            # Allow this deployment to rebind its own port, but do not accept a
            # container configured for an unrelated interface or port.
            overlaps = existing == requested or (existing.version == requested.version and
                                                  (existing.is_unspecified or requested.is_unspecified))
            return overlaps and valid_port(state['port']) == self.port
        except (KeyError, TypeError, ValueError):
            return False

    def wait_healthy(self, timeout):
        deadline = self.monotonic() + timeout
        last = {'dashboard_live': False, 'worker_rpc': False, 'worker_ready': False}
        while True:
            last = {'dashboard_live': False, 'worker_rpc': False, 'worker_ready': False}
            try:
                response = self.probe(self.url + '/livez', timeout=2)
                last['dashboard_live'] = response.get('http') == 200 and response.get('body', {}).get('alive') is True
            except (OSError, ValueError):
                pass
            result = self.project.command('exec', '-T', 'dashboard', 'python', '-B', '-c', RPC_CHECK,
                                          timeout=8, env=self.child_env)
            try:
                health = json.loads(result['output']) if result['exit'] == 0 else {}
                last['worker_rpc'] = health.get('authenticated') is True
                last['worker_ready'] = health.get('ready') is True
                last['worker_errors'] = health.get('errors', [])
            except (ValueError, TypeError):
                pass
            if all(last.get(key) is True for key in ('dashboard_live', 'worker_rpc', 'worker_ready')):
                self.say('DASHBOARD_LIVE=OK WORKER_RPC=OK WORKER_READY=OK')
                return
            if self.monotonic() >= deadline:
                self.say('HEALTH_STATE=' + json.dumps(last, ensure_ascii=False))
                raise RuntimeError('Services did not become ready before --wait-timeout; network recovery may still be pending')
            self.sleep(1)

    def diagnostics(self):
        if self.project is None:
            return
        flags = ''.join(' --compose-file ' + shlex.quote(str(path)) for path in self.project.files)
        self.say('DIAGNOSTIC: python3 ' + shlex.quote(str(self.root / 'scripts' / 'doctor.py')) + flags)
        command = ['docker', 'compose', '--project-directory', str(self.root)]
        for path in self.project.files:
            command += ['-f', str(path)]
        self.say('LOGS: ' + shlex.join(command + ['logs', '--tail=100', 'worker', 'dashboard']))

    def run(self, args):
        try:
            if args.check:
                self.prepare(args)
                self.say('CHECK=OK (no files, secrets or services changed)')
                return 0
            with update_lock(self.root):
                self.prepare(args)
                self.initialize_secrets()
                updated = update_env(self.original_env, self.changes)
                path = self.root / '.env'
                if updated != self.original_env:
                    if path.exists():
                        metadata = path.stat()
                    else:
                        owner = self.root.stat()
                        # A sudo install must not leave a user-owned checkout's
                        # private env file owned by root. Existing files retain
                        # their own owner and mode, while new files stay 0600.
                        metadata = SimpleNamespace(st_mode=stat.S_IFREG | 0o600,
                                                   st_uid=owner.st_uid, st_gid=owner.st_gid)
                    atomic_write(path, updated, metadata=metadata)
                    self.say('ENV_UPDATED=' + ','.join(self.changes))
                self.project.config(env=self.child_env)
                self.compose('build' if self.local_build else 'pull', 'worker', 'dashboard', timeout=3600)
                self.compose('up', '-d', '--no-build', '--pull', 'never', 'worker', 'dashboard', timeout=120)
                self.wait_healthy(args.wait_timeout)
                if args.host_controller:
                    command = ['bash', str(self.root / 'scripts' / 'install_host_controller.sh'),
                               str(self.root / BASE_COMPOSE)]
                    if hasattr(os, 'geteuid') and os.geteuid() != 0:
                        command.insert(0, 'sudo')
                    self.say(self.execute(command, timeout=60).rstrip())
                self.say('INSTALL=OK URL=' + self.url + ' MODE=' + ('build' if self.local_build else 'image'))
                return 0
        except (OSError, ValueError, RuntimeError) as exc:
            self.say('INSTALL=FAILED ' + str(exc))
            self.diagnostics()
            return 1


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build', action='store_true', help='Build checkout and persist local Compose mode in .env')
    parser.add_argument('--bind', help='Persist dashboard GUI_BIND as an IP address')
    parser.add_argument('--port', help='Persist dashboard GUI_PORT (1024..65535)')
    parser.add_argument('--check', action='store_true', help='Read-only preflight; do not create secrets or start services')
    parser.add_argument('--wait-timeout', type=int, default=120, help='Health/readiness wait in seconds, default 120')
    parser.add_argument('--host-controller', action='store_true', help='Also install the optional host thread-limit controller')
    return parser.parse_args(argv)


def main(argv=None):
    return Installer().run(parse_args(argv))


if __name__ == '__main__':
    raise SystemExit(main())
