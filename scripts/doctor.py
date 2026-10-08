#!/usr/bin/env python3
"""Read-only Linux/Docker diagnostics; never starts a service or changes IPv6."""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import threading
import urllib.error
import urllib.request

LIMIT = 16384


def run_command(args, *, timeout=10, cwd=None, env=None):
    """Bound both command runtime and captured output (including Docker logs)."""
    try:
        process = subprocess.Popen(args, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
    except OSError as exc:
        return {'exit': 127, 'output': str(exc), 'timeout': False}
    chunks, count, truncated = [], [0], [False]

    def drain():
        while True:
            block = process.stdout.read(4096)
            if not block:
                break
            take = max(0, LIMIT-count[0])
            if take:
                chunks.append(block[:take])
                count[0] += min(take, len(block))
            truncated[0] |= len(block) > take

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        process.kill()  # Diagnostic child only, never a container/service.
        process.wait(timeout=2)
    reader.join(timeout=2)
    if not reader.is_alive():
        process.stdout.close()
    output = b''.join(chunks).decode('utf-8', errors='replace')
    if truncated[0]:
        output += '\n[output truncated]'
    return {'exit': 124 if timed_out else process.returncode, 'output': output, 'timeout': timed_out}


class Redactor:
    """Redact known secrets, JSON/YAML/env credentials and proxy/Bearer strings."""
    sensitive = re.compile(r'(?i)(?:password|passwd|token|secret|credential|api[_-]?key)')

    def __init__(self):
        self.values = set()
        for key, value in os.environ.items():
            if self.sensitive.search(key) and value:
                self.values.add(value)

    def add_file(self, path):
        try:
            with Path(path).open('rb') as stream:
                raw = stream.read(4097)
            if len(raw) <= 4096:
                value = raw.decode('utf-8').strip()
                if value:
                    self.values.add(value)
        except (OSError, UnicodeError):
            pass

    def learn(self, value):
        if isinstance(value, dict):
            for key, item in value.items():
                if self.sensitive.search(str(key)) and isinstance(item, str) and item:
                    self.values.add(item)
                self.learn(item)
        elif isinstance(value, list):
            for item in value:
                self.learn(item)

    def learn_env_file(self, path):
        try:
            with Path(path).open(encoding='utf-8') as stream:
                text = stream.read(65536)
            for line in text.splitlines():
                match = re.match(r'^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$', line)
                if match and self.sensitive.search(match[1]):
                    value = match[2].strip().strip('"\'')
                    if value:
                        self.values.add(value)
        except (OSError, UnicodeError):
            pass

    def __call__(self, value):
        value = str(value)
        for secret in sorted(self.values, key=len, reverse=True):
            value = value.replace(secret, '[REDACTED]')
        # Keep field names but never echo values, even if config validation fails.
        names = r'[A-Za-z0-9_.-]*(?:password|passwd|token|secret|credential|api[_-]?key)[A-Za-z0-9_.-]*'
        value = re.sub(r'(?i)(["\']' + names + r'["\']\s*:\s*)["\'][^"\'\r\n]*["\']',
                       r'\1"[REDACTED]"', value)
        value = re.sub(r'(?im)(\b' + names + r'\b\s*(?:=|:)\s*)[^\r\n]+', r'\1[REDACTED]', value)
        value = re.sub(r'(?i)(Bearer\s+)[A-Za-z0-9_.~+/-]+', r'\1[REDACTED]', value)
        value = re.sub(r'(?i)(https?|socks5h?)://[^\s/@:]+:[^\s/@]+@', r'\1://[REDACTED]@', value)
        value = re.sub(r'\b[^\s:]+:CL:[^\s]+', '[REDACTED_PROXY_CREDENTIAL]', value)
        return value


class ComposeProject:
    def __init__(self, project_dir, *, compose_files=None, env_file=None, runner=run_command):
        self.root = Path(project_dir).resolve()
        if not self.root.is_dir():
            raise ValueError('Project directory does not exist')
        if compose_files:
            self.files = [(self.root / file).resolve() for file in compose_files]
        else:
            base = next((self.root / name for name in
                         ('compose.yaml', 'compose.yml', 'docker-compose.yaml', 'docker-compose.yml')
                         if (self.root / name).is_file()), None)
            if base is None:
                raise ValueError('No Compose file in project directory')
            override = next((self.root / name for name in
                             ('compose.override.yaml', 'compose.override.yml',
                              'docker-compose.override.yaml', 'docker-compose.override.yml')
                             if (self.root / name).is_file()), None)
            self.files = [base] + ([override] if override else [])
        for path in self.files:
            if not path.is_file() or path.is_symlink():
                raise ValueError('Compose files must be regular files')
        self.env_file = (self.root / (env_file or '.env')).absolute()
        if self.env_file.is_symlink():
            raise ValueError('Env file must not be a symlink')
        self.runner = runner

    def command(self, *args, timeout=10, env=None):
        cmd = ['docker', 'compose', '--project-directory', str(self.root)]
        if self.env_file.exists():
            cmd += ['--env-file', str(self.env_file)]
        for file in self.files:
            cmd += ['-f', str(file)]
        return self.runner(cmd + list(args), timeout=timeout, cwd=str(self.root), env=env)

    def config(self, *, env=None):
        result = self.command('config', '--format', 'json', env=env)
        if result['exit'] != 0 or result.get('timeout'):
            raise RuntimeError('Compose config failed: ' + result['output'])
        try:
            config = json.loads(result['output'])
            if not isinstance(config, dict) or not isinstance(config.get('services'), dict):
                raise ValueError('Malformed Compose config')
            return config
        except (ValueError, TypeError) as exc:
            raise RuntimeError('Compose config did not return valid JSON') from exc


def environment(service):
    value = service.get('environment', {})
    if isinstance(value, list):
        return dict(item.split('=', 1) for item in value if isinstance(item, str) and '=' in item)
    return value if isinstance(value, dict) else {}


def dashboard_address(config):
    try:
        env = environment(config['services']['dashboard'])
        host = str(ipaddress.ip_address(env.get('GUI_BIND') or '127.0.0.1'))
        port = int(env.get('GUI_PORT') or '7070')
    except (KeyError, TypeError, ValueError):
        raise ValueError('Compose dashboard requires a valid IP GUI_BIND and integer GUI_PORT') from None
    if not 1024 <= port <= 65535:
        raise ValueError('GUI_PORT must be in 1024..65535')
    connect = '127.0.0.1' if host == '0.0.0.0' else '::1' if host == '::' else host
    return host, port, f'http://[{connect}]:{port}' if ':' in connect else f'http://{connect}:{port}'


def http_probe(url, *, timeout=3):
    # Local diagnostics must not route through a system HTTP proxy or redirect.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(url, timeout=timeout)
    except urllib.error.HTTPError as exc:
        response = exc
    with response:
        raw = response.read(65537)
        if len(raw) > 65536:
            raise ValueError('Health response too large')
        body = json.loads(raw)
        return {'http': response.status, 'body': body}


RUNTIME_CHECK = """import importlib.metadata,json,os,shutil; print(json.dumps({
'python':__import__('sys').version.split()[0], 'uid':os.getuid(), 'gid':os.getgid(),
'role':os.getenv('APP_ROLE'), 'flask':importlib.metadata.version('flask'),
'gunicorn':importlib.metadata.version('gunicorn'), 'curl':bool(shutil.which('curl')),
'ip':bool(shutil.which('ip')), '3proxy':bool(shutil.which('3proxy'))}))"""
RPC_CHECK = """import json,os; os.environ['WORKER_RPC_TIMEOUT']='3'; from rpc import WorkerClient; r=WorkerClient().call('health');
print(json.dumps({'authenticated':True,'ready':r.get('ready') is True,
'desired_state':r.get('desired_state'),'errors':r.get('errors',[])}))"""
DASHBOARD_CHECK = """import json,os,stat; import app
r=app.app.test_client().get('/login',follow_redirects=True); files=[]
for name in ('ADMIN_PASSWORD_FILE','SECRET_KEY_FILE','SERVICE_TOKEN_FILE','DASHBOARD_PASSWORD_PATH','WORKER_SOCKET'):
 path=os.getenv(name)
 if not path: continue
 try:
  item=os.stat(path); files.append({'name':name,'mode':stat.filemode(item.st_mode),'uid':item.st_uid,'gid':item.st_gid,'readable':os.access(path,os.R_OK)})
 except OSError as exc: files.append({'name':name,'error':type(exc).__name__})
print(json.dumps({'login_http':r.status_code,'files':files}))"""


class Doctor:
    def __init__(self, project_dir=None, *, runner=run_command, probe=http_probe,
                 compose_files=None, env_file=None):
        self.project = ComposeProject(project_dir or Path(__file__).resolve().parents[1],
                                      runner=runner, compose_files=compose_files, env_file=env_file)
        self.probe = probe
        self.redact, self.sections, self.failures = Redactor(), [], []
        for name in ('admin_password', 'secret_key', 'service_token', 'dashboard_password'):
            self.redact.add_file(self.project.root / 'secrets' / name)
        self.redact.learn_env_file(self.project.env_file)
        self.classification = 'unclassified'

    def record(self, title, good, detail, *, required=True):
        self.sections.append(f'[{"OK" if good else "FAIL" if required else "INFO"}] {title}\n{self.redact(detail)}')
        if required and not good:
            self.failures.append(title)

    def command(self, title, *args, timeout=10, required=True):
        try:
            result = self.project.command(*args, timeout=timeout)
        except Exception as exc:
            result = {'exit': 127, 'output': f'{type(exc).__name__}: {exc}'}
        self.record(title, result['exit'] == 0 and not result.get('timeout'),
                    f'compose {shlex.join(args)}\nexit={result["exit"]}\n{result["output"]}', required=required)
        return result

    def collect(self):
        self.record('read-only', True, f'project={self.project.root}\nNo service start/stop, state/password writes, or NIC changes.')
        config = None
        try:
            config = self.project.config()
            self.redact.learn(config)
            for spec in config.get('secrets', {}).values():
                if isinstance(spec, dict) and spec.get('file'):
                    self.redact.add_file(self.project.root / spec['file'])
            for role in ('worker', 'dashboard'):
                service = config['services'][role]
                actual_role = environment(service).get('APP_ROLE')
                user = str(service.get('user', ''))
                identity = user.split(':', 1)[0]
                good = actual_role == role and ((identity == '0') if role == 'worker' else (bool(identity) and identity not in ('0', 'root')))
                self.record('Compose role ' + role, good,
                            json.dumps({'image': service.get('image'), 'user': user,
                                        'role': actual_role, 'network_mode': service.get('network_mode')}))
            self.record('Compose config', True, 'Resolved config validated; credential values omitted.')
        except Exception as exc:
            self.record('Compose config', False, f'{type(exc).__name__}: {exc}')
        ps = self.command('Compose services/health', 'ps', '--all', '--format', 'json')
        dashboard_running = False
        try:
            try:
                rows = json.loads(ps['output'])
                rows = rows if isinstance(rows, list) else [rows]
            except ValueError:
                rows = [json.loads(line) for line in ps['output'].splitlines() if line.strip()]
            for role in ('worker', 'dashboard'):
                row = next(item for item in rows if item.get('Service') == role)
                good = row.get('State') == 'running' and row.get('Health', '') in ('', 'healthy')
                self.record('container ' + role, good,
                            json.dumps({k: row.get(k) for k in ('Service', 'State', 'Health', 'ExitCode')}))
                if role == 'dashboard':
                    dashboard_running = good
        except (ValueError, KeyError, TypeError, StopIteration):
            self.record('container inventory', False, 'Expected worker and dashboard services were not found.')
        for role in ('worker', 'dashboard'):
            result = self.command('runtime/dependencies ' + role, 'exec', '-T', role, 'python', '-B', '-c', RUNTIME_CHECK)
            try:
                info = json.loads(result['output'])
                good = info['role'] == role and (info['uid'] == 0 if role == 'worker' else info['uid'] != 0)
                if role == 'worker':
                    good = good and all(info.get(binary) is True for binary in ('curl', 'ip', '3proxy'))
                self.record('runtime identity ' + role, good, json.dumps(info))
            except (ValueError, KeyError, TypeError):
                self.record('runtime identity ' + role, False, 'Runtime diagnostic did not return JSON.')
        imported = self.command('dashboard import/login + mount permissions', 'exec', '-T', 'dashboard',
                                'python', '-B', '-c', DASHBOARD_CHECK)
        try:
            info = json.loads(imported['output'])
            self.record('dashboard login preflight', info.get('login_http') == 200,
                        json.dumps(info))
        except (ValueError, TypeError):
            self.record('dashboard login preflight', False, 'Dashboard import diagnostic did not return JSON.')
        rpc = self.command('authenticated worker RPC', 'exec', '-T', 'dashboard', 'python', '-B', '-c', RPC_CHECK, timeout=8)
        try:
            info = json.loads(rpc['output'])
            self.record('worker readiness', info.get('authenticated') is True and info.get('ready') is True,
                        json.dumps(info))
        except (ValueError, TypeError):
            self.record('worker readiness', False, 'Authenticated health RPC did not return JSON.')
        live = False
        if config is not None:
            try:
                host, port, url = dashboard_address(config)
                owner = self.project.runner(['ss', '-ltnp', f'sport = :{port}'], timeout=3,
                                            cwd=str(self.project.root), env=None)
                self.record('dashboard listener owner', owner['exit'] == 0, owner['output'], required=False)
                for path, field in (('/livez', 'alive'), ('/readyz', 'ready')):
                    try:
                        response = self.probe(url + path, timeout=3)
                        good = response.get('http') == 200 and response.get('body', {}).get(field) is True
                        self.record('dashboard ' + path, good, f'GET {url}{path}\n{json.dumps(response)}')
                        if path == '/livez':
                            live = good
                    except Exception as exc:
                        self.record('dashboard ' + path, False, f'{type(exc).__name__}: {exc}')
            except Exception as exc:
                self.record('dashboard bind/port', False, f'{type(exc).__name__}: {exc}')
        logs = self.command('recent logs (redacted)', 'logs', '--no-color', '--tail', '60', 'worker', 'dashboard', required=False)
        conflict = re.search(r'(?i)address already in use|\[Errno (?:48|98)\]', logs['output'])
        if conflict and not (dashboard_running and live):
            self.classification = 'dashboard_port_conflict'
            self.record('dashboard port conflict', False,
                        'Check listener owner above. To propose a different port:\n'
                        'python3 scripts/change_dashboard_port.py 7071 --project-dir ' + shlex.quote(str(self.project.root)) +
                        '\nThe helper preflights the proposed port and recreates dashboard only; doctor performed no repair.', required=False)
        elif not self.failures:
            self.classification = 'healthy'
        self.sections += ['CLASSIFICATION: ' + self.classification,
                          f'DOCTOR: result={"FAILED" if self.failures else "OK"} failed_checks={len(self.failures)}']
        # Redact again after all config/secret discoveries, including earlier errors.
        return self.redact('\n\n'.join(self.sections) + '\n'), 1 if self.failures else 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--project-dir', default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument('--compose-file', action='append', dest='compose_files')
    parser.add_argument('--env-file')
    args = parser.parse_args(argv)
    try:
        report, status = Doctor(**vars(args)).collect()
        print(report, end='')
        return status
    except (OSError, ValueError) as exc:
        print('DOCTOR ERROR: ' + Redactor()(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
