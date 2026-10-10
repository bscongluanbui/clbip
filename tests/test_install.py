"""Offline installer regression tests; Docker commands never reach a daemon."""
import errno
import io
import json
import os
from pathlib import Path
import shutil
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from scripts import install

ROOT = Path(__file__).resolve().parents[1]


class FakeRuntime:
    def __init__(self, root):
        self.root = Path(root)
        self.calls = []
        self.fail = None
        self.engine = 'linux/aarch64'
        self.version = '2.39.4'
        self.ready = True
        self.authenticated = True
        self.running_listener = None
        self.ticks = 0

    def __call__(self, args, *, timeout=10, cwd=None, env=None):
        self.calls.append({'args': args[:], 'cwd': cwd, 'env': dict(env or {}), 'timeout': timeout})
        output, code = '', 0
        if args[0] == sys.executable:
            result = subprocess.run(args, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
            return {'exit': result.returncode, 'output': result.stdout + result.stderr, 'timeout': False}
        if self.fail and self.fail in args:
            return {'exit': 1, 'output': 'fixture command failure password=DO_NOT_LOG_ME', 'timeout': False}
        if args[:4] == ['docker', 'compose', 'version', '--short']:
            output = self.version
        elif args[:2] == ['docker', 'info']:
            output = self.engine
        elif 'config' in args:
            _, values = install.read_env(self.root / '.env')
            values.update(env or {})
            output = json.dumps({'services': {
                'worker': {'network_mode': 'host', 'environment': {'APP_ROLE': 'worker'}},
                'dashboard': {'network_mode': 'host', 'environment': {
                    'GUI_BIND': values.get('GUI_BIND') or '127.0.0.1',
                    'GUI_PORT': values.get('GUI_PORT') or '7070'}}}})
        elif 'exec' in args:
            if args[-1] == install.LISTENER_CHECK:
                if self.running_listener:
                    output = json.dumps(self.running_listener)
                else:
                    code, output = 1, 'dashboard is not running'
            elif args[-1] == install.RPC_CHECK:
                output = json.dumps({'authenticated': self.authenticated, 'ready': self.ready,
                                     'errors': [] if self.ready else ['IPv6 router pending']})
            else:
                raise AssertionError(args)
        elif 'build' in args or 'pull' in args or 'up' in args:
            output = 'fixture compose success'
        elif 'bash' in args:
            output = 'HOST_PID_CONTROLLER_INSTALLED'
        else:
            raise AssertionError('Unexpected fixture command: ' + str(args))
        return {'exit': code, 'output': output, 'timeout': False}

    def clock(self):
        self.ticks += 1
        return self.ticks


class InstallerTests(unittest.TestCase):
    def setUp(self):
        scratch = ROOT / '.test-tmp'
        scratch.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='install-test-', dir=scratch)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'scripts').mkdir()
        shutil.copyfile(ROOT / 'scripts' / 'init_secrets.py', self.root / 'scripts' / 'init_secrets.py')
        (self.root / install.BASE_COMPOSE).write_text('services: {}\n', encoding='utf-8')
        (self.root / install.BUILD_COMPOSE).write_text('services: {}\n', encoding='utf-8')
        self.runtime = FakeRuntime(self.root)
        self.out = io.StringIO()
        self.live = True
        self.port_calls = []
        self.installer = install.Installer(self.root, runner=self.runtime, out=self.out,
                                          system=lambda: 'Linux', sleep=lambda _: None,
                                          monotonic=self.runtime.clock,
                                          port_probe=lambda host, port: self.port_calls.append((host, port)),
                                          probe=lambda url, timeout: {'http': 200, 'body': {'alive': self.live}})

    def run_install(self, *argv):
        return self.installer.run(install.parse_args(list(argv)))

    def docker_actions(self, action):
        return [call for call in self.runtime.calls if call['args'][0] == 'docker' and action in call['args']]

    def test_fresh_install_creates_empty_admin_and_independent_persistent_keys(self):
        self.assertEqual(self.run_install(), 0, self.out.getvalue())
        directory = self.root / 'secrets'
        self.assertEqual((directory / 'admin_password').read_bytes().strip(), b'')
        keys = [(directory / name).read_bytes() for name in ('secret_key', 'service_token')]
        self.assertNotEqual(keys[0], keys[1])
        self.assertTrue(all(len(value.strip()) >= 32 for value in keys))
        self.assertEqual(len(self.docker_actions('pull')), 1)
        self.assertFalse(self.docker_actions('build'))
        self.assertIn('INSTALL=OK', self.out.getvalue())
        self.assertFalse((self.root / '.env').exists())
        creation = next(call for call in self.runtime.calls if call['args'][0] == sys.executable)
        self.assertIn('--no-dashboard-password', creation['args'])
        self.assertEqual(creation['args'][0], sys.executable)

    def test_repeated_install_preserves_secret_bytes_and_unrelated_env(self):
        original = b'# operator settings\r\nOTHER=keep\r\nGUI_BIND=192.168.1.3\r\n'
        path = self.root / '.env'
        path.write_bytes(original)
        self.assertEqual(self.run_install(), 0, self.out.getvalue())
        secrets_before = {p.name: p.read_bytes() for p in (self.root / 'secrets').iterdir()}
        self.assertEqual(self.run_install(), 0, self.out.getvalue())
        self.assertEqual(secrets_before, {p.name: p.read_bytes() for p in (self.root / 'secrets').iterdir()})
        self.assertEqual(path.read_bytes(), original)
        self.assertNotIn('down', [arg for call in self.runtime.calls for arg in call['args']])

    def test_build_mode_is_persisted_and_reused_on_later_default_run(self):
        self.assertEqual(self.run_install('--build'), 0, self.out.getvalue())
        contents = (self.root / '.env').read_text()
        self.assertIn('COMPOSE_FILE=' + install.BUILD_FILES, contents)
        self.assertIn('IPV6_MANAGER_IMAGE=' + install.LOCAL_IMAGE, contents)
        self.assertEqual(len(self.docker_actions('build')), 1)
        self.assertFalse(self.docker_actions('pull'))
        self.assertEqual(self.run_install(), 0, self.out.getvalue())
        self.assertEqual(len(self.docker_actions('build')), 2)
        self.assertFalse(self.docker_actions('pull'))
        for call in self.docker_actions('up'):
            self.assertIn(str(self.root / install.BUILD_COMPOSE), call['args'])
            self.assertIn('--no-build', call['args'])
            self.assertIn('never', call['args'])

    def test_persisted_dot_relative_build_override_selects_build(self):
        original = 'COMPOSE_FILE=' + install.BASE_COMPOSE + ':./' + install.BUILD_COMPOSE + '\n'
        (self.root / '.env').write_text(original, encoding='utf-8')
        self.assertEqual(self.run_install(), 0, self.out.getvalue())
        self.assertEqual(len(self.docker_actions('build')), 1)
        self.assertFalse(self.docker_actions('pull'))
        self.assertEqual((self.root / '.env').read_text(encoding='utf-8'), original)
        self.assertIn((self.root / install.BUILD_COMPOSE).resolve(), self.installer.project.files)

    def test_persisted_absolute_build_override_selects_build(self):
        absolute = (self.root / install.BUILD_COMPOSE).as_posix()
        if os.name == 'nt':
            # COMPOSE_FILE uses Linux ':' separators; emulate its absolute path
            # using the current-drive rooted path, without a Windows drive ':'.
            absolute = absolute[len(self.root.drive):]
        original = 'COMPOSE_FILE=' + install.BASE_COMPOSE + ':' + absolute + '\n'
        (self.root / '.env').write_text(original, encoding='utf-8')
        self.assertEqual(self.run_install(), 0, self.out.getvalue())
        self.assertEqual(len(self.docker_actions('build')), 1)
        self.assertFalse(self.docker_actions('pull'))
        self.assertEqual((self.root / '.env').read_text(encoding='utf-8'), original)
        self.assertIn((self.root / install.BUILD_COMPOSE).resolve(), self.installer.project.files)

    def test_check_on_fresh_checkout_is_read_only_and_allows_missing_secrets(self):
        before = set(self.root.rglob('*'))
        self.assertEqual(self.run_install('--check', '--build', '--bind', '192.168.1.3', '--port', '7071'), 0,
                         self.out.getvalue())
        self.assertEqual(before, set(self.root.rglob('*')))
        self.assertFalse(any(self.docker_actions(action) for action in ('up', 'pull', 'build', 'restart', 'down')))
        self.assertFalse(any(call['args'][0] == sys.executable for call in self.runtime.calls))
        self.assertIn('Missing deployment file secrets/service_token', self.out.getvalue())
        self.assertIn('CHECK=OK', self.out.getvalue())

    def test_check_keeps_existing_env_bytes_and_secret_values(self):
        self.assertEqual(self.run_install(), 0)
        original = b'# unchanged\nGUI_PORT=7070\nOTHER=keep\n'
        (self.root / '.env').write_bytes(original)
        before = {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        self.assertEqual(self.run_install('--check', '--port', '7071'), 0)
        self.assertEqual(before, {p: p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_bind_port_edits_preserve_crlf_comments_and_remove_duplicates(self):
        path = self.root / '.env'
        path.write_bytes(b'# retained\r\nOTHER=keep\r\nexport GUI_PORT=7070\r\nGUI_PORT=7072\r\n')
        self.assertEqual(self.run_install('--bind', '192.168.1.3', '--port', '7071'), 0, self.out.getvalue())
        self.assertEqual(path.read_bytes(), b'# retained\r\nOTHER=keep\r\nGUI_PORT=7071\r\nGUI_BIND=192.168.1.3\r\n')
        self.assertIn(('192.168.1.3', 7071), self.port_calls)

    def test_new_env_retains_checkout_owner_and_private_mode_under_sudo(self):
        original_stat = Path.stat
        writes = []

        def user_owned_checkout(path, *args, **kwargs):
            actual = original_stat(path, *args, **kwargs)
            if path == self.root:
                return SimpleNamespace(st_mode=actual.st_mode, st_uid=1000, st_gid=1000)
            return actual

        def write_fixture(path, content, *, metadata=None):
            # Verify the privileged-write metadata without a real chown on any
            # platform; the real helper performs chown only on POSIX hosts.
            writes.append(metadata)
            path.write_bytes(content)
            path.chmod(stat.S_IMODE(metadata.st_mode))

        with patch.object(Path, 'stat', user_owned_checkout), \
                patch('scripts.install.atomic_write', side_effect=write_fixture):
            self.assertEqual(self.run_install('--bind', '192.168.1.3'), 0, self.out.getvalue())
        self.assertEqual(len(writes), 1)
        self.assertEqual((writes[0].st_uid, writes[0].st_gid), (1000, 1000))
        self.assertEqual(stat.S_IMODE(writes[0].st_mode), 0o600)
        self.assertIn('GUI_BIND=192.168.1.3', (self.root / '.env').read_text())

    def test_child_commands_resolve_repo_root_from_any_cwd(self):
        self.assertEqual(self.run_install('--check'), 0)
        for call in self.runtime.calls:
            self.assertEqual(call['cwd'], str(self.root))
            if '--project-directory' in call['args']:
                self.assertEqual(call['args'][call['args'].index('--project-directory') + 1], str(self.root))

    def test_persisted_build_and_gui_settings_win_over_ambient_selectors(self):
        (self.root / '.env').write_text('COMPOSE_FILE=' + install.BUILD_FILES + '\nGUI_BIND=192.168.1.3\nGUI_PORT=7071\n')
        with patch.dict(os.environ, {'COMPOSE_FILE': '/other/compose.yml', 'GUI_BIND': '0.0.0.0', 'GUI_PORT': '9999'}):
            self.installer.child_env = dict(os.environ)
            self.assertEqual(self.run_install('--check'), 0, self.out.getvalue())
        self.assertEqual(self.port_calls[-1], ('192.168.1.3', 7071))
        for call in self.runtime.calls:
            self.assertNotIn('COMPOSE_FILE', call['env'])

    def test_bad_bind_and_ports_fail_before_docker(self):
        for flags in [('--bind', 'hostname'), ('--bind', '224.0.0.1'), ('--port', '7070;touch'),
                      ('--port', '80'), ('--port', '65536'), ('--wait-timeout', '0')]:
            with self.subTest(flags=flags):
                self.runtime.calls.clear()
                self.assertEqual(self.run_install('--check', *flags), 1)
                self.assertFalse(self.runtime.calls)

    def test_docker_access_failure_does_not_create_secrets_or_start_services(self):
        self.runtime.fail = 'info'
        self.assertEqual(self.run_install(), 1)
        self.assertFalse((self.root / 'secrets').exists())
        self.assertFalse(self.docker_actions('up'))
        self.assertNotIn('DO_NOT_LOG_ME', self.out.getvalue())

    def test_compose_v1_and_non_linux_daemon_are_rejected(self):
        self.runtime.version = '1.29.2'
        self.assertEqual(self.run_install('--check'), 1)
        self.runtime.version = '2.39.4'
        self.runtime.engine = 'windows/amd64'
        self.assertEqual(self.run_install('--check'), 1)
        self.assertFalse((self.root / 'secrets').exists())

    def test_short_existing_secret_is_not_rotated(self):
        directory = self.root / 'secrets'
        directory.mkdir()
        token = directory / 'service_token'
        token.write_bytes(b'short\n')
        self.assertEqual(self.run_install(), 1)
        self.assertEqual(token.read_bytes(), b'short\n')
        self.assertFalse(self.docker_actions('up'))

    def test_occupied_unrelated_listener_is_rejected(self):
        def occupied(*_):
            raise OSError(errno.EADDRINUSE, 'Address already in use')
        self.installer.port_probe = occupied
        self.assertEqual(self.run_install('--check'), 1)
        self.assertFalse((self.root / 'secrets').exists())
        self.assertFalse(self.docker_actions('up'))

    def test_occupied_listener_owned_by_same_project_is_allowed(self):
        def occupied(*_):
            raise OSError(errno.EADDRINUSE, 'Address already in use')
        self.installer.port_probe = occupied
        self.runtime.running_listener = {'bind': '127.0.0.1', 'port': '7070'}
        self.assertEqual(self.run_install('--check'), 0, self.out.getvalue())
        self.assertIn('OWNED_BY_EXISTING_DASHBOARD', self.out.getvalue())

    def test_non_local_bind_error_is_not_misidentified_as_existing_port(self):
        def unavailable(*_):
            raise OSError(errno.EADDRNOTAVAIL, 'Cannot assign requested address')
        self.installer.port_probe = unavailable
        self.runtime.running_listener = {'bind': '127.0.0.1', 'port': '7070'}
        self.assertEqual(self.run_install('--check'), 1)

    def test_same_project_can_change_its_existing_listener_to_wildcard(self):
        def occupied(*_):
            raise OSError(errno.EADDRINUSE, 'Address already in use')
        self.installer.port_probe = occupied
        self.runtime.running_listener = {'bind': '127.0.0.1', 'port': '7070'}
        self.assertEqual(self.run_install('--check', '--bind', '0.0.0.0'), 0, self.out.getvalue())

    def test_same_project_wrong_port_does_not_override_unrelated_busy_listener(self):
        def occupied(*_):
            raise OSError(errno.EADDRINUSE, 'Address already in use')
        self.installer.port_probe = occupied
        self.runtime.running_listener = {'bind': '0.0.0.0', 'port': '7071'}
        self.assertEqual(self.run_install('--check'), 1)

    def test_pull_failure_returns_nonzero_with_diagnostic_guidance(self):
        self.runtime.fail = 'pull'
        self.assertEqual(self.run_install(), 1)
        self.assertFalse(self.docker_actions('up'))
        self.assertIn('DIAGNOSTIC:', self.out.getvalue())
        self.assertIn('LOGS:', self.out.getvalue())

    def test_worker_not_ready_is_distinct_from_liveness_and_fails_bounded_wait(self):
        self.runtime.ready = False
        self.assertEqual(self.run_install('--build', '--wait-timeout', '2'), 1)
        output = self.out.getvalue()
        self.assertIn('"dashboard_live": true', output)
        self.assertIn('"worker_rpc": true', output)
        self.assertIn('"worker_ready": false', output)
        self.assertIn('IPv6 router pending', output)
        self.assertIn('--compose-file ' + shlex.quote(str(self.root / install.BUILD_COMPOSE)), output)

    def test_worker_authentication_failure_or_dashboard_liveness_failure_returns_nonzero(self):
        self.runtime.authenticated = False
        self.assertEqual(self.run_install('--wait-timeout', '1'), 1)
        self.runtime.authenticated = True
        self.live = False
        self.assertEqual(self.run_install('--wait-timeout', '1'), 1)

    def test_host_controller_is_optional_and_runs_only_after_health(self):
        self.assertEqual(self.run_install('--host-controller'), 0, self.out.getvalue())
        commands = [call['args'] for call in self.runtime.calls]
        controller = next(index for index, command in enumerate(commands) if 'bash' in command)
        rpc = next(index for index, command in enumerate(commands) if command[-1] == install.RPC_CHECK)
        self.assertGreater(controller, rpc)
        self.runtime.calls.clear()
        self.runtime.ready = False
        self.assertEqual(self.run_install('--host-controller', '--wait-timeout', '1'), 1)
        self.assertFalse(any('bash' in call['args'] for call in self.runtime.calls))

    def test_wrapper_resolves_its_own_directory_and_forwards_all_args(self):
        script = (ROOT / 'scripts' / 'install.sh').read_text(encoding='utf-8')
        self.assertIn('${BASH_SOURCE[0]}', script)
        self.assertIn('exec python3 "$HERE/install.py" "$@"', script)
        self.assertNotIn(b'\r\n', (ROOT / 'scripts' / 'install.sh').read_bytes())


if __name__ == '__main__':
    unittest.main()
