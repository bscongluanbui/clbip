import contextlib
import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / 'scripts' / 'create_watchdog_node.py'
spec = importlib.util.spec_from_file_location('create_watchdog_node', SCRIPT)
nodes = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = nodes
spec.loader.exec_module(nodes)


class WatchdogNodeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.legacy = self.root / 'watchdog.env'
        self.legacy.write_text('EXISTING_PRIVATE_CONFIG=preserve\n', encoding='utf-8')

    def create(self, name='friend-one', **options):
        return nodes.create_node(self.root, name, options.pop('bind', '100.76.59.88'), **options)

    def env(self, path):
        return dict(line.split('=', 1) for line in path.read_text(encoding='utf-8').splitlines()
                    if line and not line.startswith('#'))

    def test_separate_tokens_config_and_data_preserve_legacy(self):
        one = self.create(port=8089)
        two = self.create('friend-two', port=8090)
        first, second = self.env(one.environment), self.env(two.environment)
        self.assertNotEqual(first['WATCHDOG_SHARED_TOKEN'], second['WATCHDOG_SHARED_TOKEN'])
        self.assertRegex(first['WATCHDOG_SHARED_TOKEN'], r'^[A-Za-z0-9_-]{64}$')
        self.assertEqual(first['TELEGRAM_BOT_TOKEN'], '')
        self.assertEqual(first['TELEGRAM_CHAT_ID'], '')
        self.assertEqual(first['WATCHDOG_NODE_NAME'], 'friend-one')
        self.assertEqual(first['WATCHDOG_PORT'], '8089')
        self.assertEqual(first['WATCHDOG_TIMEOUT'], '180')
        self.assertNotEqual(first['DATA_DIR'], second['DATA_DIR'])
        self.assertTrue(one.data.is_dir())
        self.assertTrue(two.data.is_dir())
        self.assertEqual(self.legacy.read_text(), 'EXISTING_PRIVATE_CONFIG=preserve\n')

    @unittest.skipIf(os.name == 'nt', 'POSIX permission bits')
    def test_private_modes(self):
        one = self.create()
        for path in (one.environment, one.unit):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        for path in (one.directory.parent, one.directory, one.data):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    def test_unit_runs_one_instance_as_ubuntu_with_only_own_data_writable(self):
        one = self.create()
        unit = one.unit.read_text(encoding='utf-8')
        self.assertEqual(one.service_name, 'clbip-watchdog-friend-one.service')
        for entry in ('User=ubuntu\n', 'Group=ubuntu\n', 'UMask=0077\n',
                      'ProtectSystem=strict\n', 'ProtectHome=read-only\n',
                      'NoNewPrivileges=yes\n', 'ExecStartPre=/usr/bin/python3 ',
                      ' --check\n', 'Restart=on-failure\n'):
            self.assertIn(entry, unit)
        self.assertIn('EnvironmentFile=' + str(one.environment), unit)
        self.assertIn('WorkingDirectory=' + str(self.root), unit)
        self.assertIn('ReadWritePaths=' + str(one.data), unit)
        self.assertEqual(unit.count('ReadWritePaths='), 1)
        self.assertNotIn(self.env(one.environment)['WATCHDOG_SHARED_TOKEN'], unit)

    def test_tailscale_bind_warmup_cannot_exhaust_restart_burst(self):
        # tailscaled.service can become active before the configured overlay
        # address is ready. A temporary bind failure must keep retrying.
        unit = self.create().unit.read_text(encoding='utf-8')
        self.assertIn('StartLimitIntervalSec=0\n', unit)
        self.assertNotIn('StartLimitBurst=', unit)
        self.assertIn('Restart=on-failure\n', unit)
        self.assertIn('RestartSec=10\n', unit)
        self.assertIn(' --check\n', unit)

    def test_existing_node_not_overwritten(self):
        one = self.create()
        originals = {path: path.read_bytes() for path in (one.environment, one.unit)}
        marker = one.data / 'do-not-replace'
        marker.write_bytes(b'existing-state')
        with self.assertRaises(FileExistsError):
            self.create(port=8099)
        self.assertEqual({path: path.read_bytes() for path in originals}, originals)
        self.assertEqual(marker.read_bytes(), b'existing-state')

    def test_duplicate_node_port_rejected_without_creating_node(self):
        one = self.create(port=8093)
        original = one.environment.read_bytes()
        with self.assertRaisesRegex(ValueError, 'already assigned'):
            self.create('friend-two', port=8093)
        self.assertFalse((one.directory.parent / 'friend-two').exists())
        self.assertEqual(one.environment.read_bytes(), original)

    def test_duplicate_legacy_port_rejected_and_legacy_preserved(self):
        self.legacy.write_text('WATCHDOG_PORT="8094"\nTELEGRAM_BOT_TOKEN=PRIVATE\n')
        original = self.legacy.read_bytes()
        with self.assertRaisesRegex(ValueError, 'already assigned'):
            self.create(port=8094)
        self.assertFalse((self.root / 'nodes').exists())
        self.assertEqual(self.legacy.read_bytes(), original)

    def test_invalid_existing_port_not_echoed(self):
        self.legacy.write_text('WATCHDOG_PORT=PRIVATE-TOKEN\n')
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            code = nodes.main(['--root', str(self.root), '--name', 'friend',
                               '--bind', '100.76.59.88'])
        self.assertEqual(code, 2)
        self.assertNotIn('PRIVATE-TOKEN', errors.getvalue())
        self.assertFalse((self.root / 'nodes').exists())

    def test_existing_file_instead_of_node_not_overwritten(self):
        parent = self.root / 'nodes'
        parent.mkdir()
        target = parent / 'friend-one'
        target.write_text('preserve')
        with self.assertRaises(FileExistsError):
            self.create()
        self.assertEqual(target.read_text(), 'preserve')

    def test_existing_file_instead_of_nodes_directory_not_overwritten(self):
        target = self.root / 'nodes'
        target.write_text('preserve')
        with self.assertRaises(ValueError):
            self.create()
        self.assertEqual(target.read_text(), 'preserve')

    def test_invalid_names_do_not_create_nodes_or_echo_input(self):
        for name in ('', '.', '..', '../secret', '/tmp/secret', 'UPPER', '-start',
                     'a/b', 'a\\b', 'a' * 33, 'a\nTOKEN=private', 'é', 'a.service',
                     'a;touch-secret', 'a%u', 'a$TOKEN'):
            with self.subTest(name=name):
                output = io.StringIO()
                with contextlib.redirect_stderr(output):
                    code = nodes.main(['--root', str(self.root), '--name=' + name,
                                       '--bind', '100.76.59.88'])
                self.assertEqual(code, 2)
                if len(name) > 2:
                    self.assertNotIn(name, output.getvalue())
                self.assertFalse((self.root / 'nodes').exists())

    def test_name_length_boundary(self):
        self.assertTrue(self.create('a').environment.exists())
        self.assertTrue(self.create('a' * 32, port=8090).environment.exists())

    def test_invalid_ports_do_not_create_files(self):
        for port in (0, 80, 8088, 65536, -1, True, '8089', 8089.0):
            with self.subTest(port=port), self.assertRaises(ValueError):
                self.create(port=port)
            self.assertFalse((self.root / 'nodes').exists())

    def test_port_boundary(self):
        self.assertEqual(self.env(self.create(port=65535).environment)['WATCHDOG_PORT'], '65535')

    def test_invalid_timeouts(self):
        for timeout in (0, 29, 86401, True, '180', 180.0):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                self.create(timeout=timeout)
            self.assertFalse((self.root / 'nodes').exists())

    def test_invalid_bind_does_not_create_files(self):
        for bind in ('', '0.0.0.0', '::', '127.0.0.1', '192.168.1.3', '140.245.107.68',
                     '100.63.255.255', '100.128.0.0', 'localhost', 'arm2.ts.net',
                     'fd7b::1', 'fd7a:115c:a1e1::1', 'fd7a:115c:a1e0::1%eth0',
                     '100.76.59.88\nTOKEN=private', None):
            with self.subTest(bind=bind), self.assertRaises(ValueError):
                self.create(bind=bind)
            self.assertFalse((self.root / 'nodes').exists())

    def test_tailscale_ipv6_bind(self):
        one = self.create(bind='fd7a:115c:a1e0:0:0:0:0:1234')
        self.assertEqual(self.env(one.environment)['WATCHDOG_BIND'], 'fd7a:115c:a1e0::1234')

    def test_relative_or_nonexistent_root_rejected(self):
        for root in ('relative', self.root / 'absent'):
            with self.subTest(root=root), self.assertRaises(ValueError):
                nodes.create_node(root, 'friend', '100.76.59.88')
        self.assertFalse((self.root / 'absent').exists())

    def _symlink(self, link, target, is_directory=True):
        try:
            link.symlink_to(target, target_is_directory=is_directory)
        except (OSError, NotImplementedError):
            self.skipTest('Symlink privilege not available')

    def test_symlink_root_rejected(self):
        actual = self.root / 'actual'
        actual.mkdir()
        alias = self.root / 'alias'
        self._symlink(alias, actual)
        with self.assertRaises(ValueError):
            nodes.create_node(alias, 'friend', '100.76.59.88')
        self.assertFalse((actual / 'nodes').exists())

    def test_symlink_ancestor_rejected(self):
        actual = self.root / 'actual'
        child = actual / 'child'
        child.mkdir(parents=True)
        alias = self.root / 'alias'
        self._symlink(alias, actual)
        with self.assertRaises(ValueError):
            nodes.create_node(alias / 'child', 'friend', '100.76.59.88')
        self.assertFalse((child / 'nodes').exists())

    def test_symlink_nodes_directory_rejected(self):
        outside = self.root / 'outside'
        outside.mkdir()
        self._symlink(self.root / 'nodes', outside)
        with self.assertRaises(ValueError):
            self.create()
        self.assertEqual(list(outside.iterdir()), [])

    def test_broken_symlink_destination_rejected(self):
        parent = self.root / 'nodes'
        parent.mkdir()
        link = parent / 'friend-one'
        self._symlink(link, self.root / 'nonexistent')
        with self.assertRaises(FileExistsError):
            self.create()
        self.assertTrue(link.is_symlink())
        self.assertFalse((self.root / 'nonexistent').exists())

    def test_path_control_characters_rejected(self):
        with self.assertRaises(ValueError):
            nodes.create_node(str(self.root) + '\nENV=secret', 'friend', '100.76.59.88')

    def test_unsupported_systemd_root_characters_rejected_before_writes(self):
        for suffix in ('root with spaces', 'root$HOME', 'root%u', 'root"quote',
                       "root'quote", 'root;command', 'root#comment', 'rooté'):
            with self.subTest(suffix=suffix), self.assertRaises(ValueError):
                nodes.create_node(self.root / suffix, 'friend', '100.76.59.88')
            self.assertFalse((self.root / suffix / 'nodes').exists())

    def test_systemd_path_directives_are_plain_absolute_not_quoted(self):
        one = self.create()
        unit = one.unit.read_text(encoding='utf-8')
        expected = {'WorkingDirectory': self.root, 'EnvironmentFile': one.environment,
                    'ReadWritePaths': one.data}
        for field, path in expected.items():
            line = next(line for line in unit.splitlines() if line.startswith(field + '='))
            self.assertEqual(line, field + '=' + str(path))
            self.assertNotIn('"', line)
            self.assertNotIn("'", line)
            self.assertTrue(path.is_absolute())

    @unittest.skipIf(os.name == 'nt', 'Linux systemd verifier')
    def test_generated_unit_accepted_by_real_systemd_verifier_when_available(self):
        import shutil
        import subprocess
        verifier = shutil.which('systemd-analyze')
        if verifier is None:
            self.skipTest('systemd-analyze not installed')
        one = self.create()
        result = subprocess.run([verifier, 'verify', str(one.unit)],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('WorkingDirectory= path is not absolute', result.stderr)

    def test_cli_outputs_instructions_not_tokens_or_file_values(self):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), \
                patch.object(nodes.secrets, 'token_urlsafe', return_value='TOP_SECRET_UNIQUE_TOKEN' * 3):
            code = nodes.main(['--root', str(self.root), '--name', 'friend-one',
                               '--bind', '100.76.59.88'])
        self.assertEqual(code, 0)
        self.assertEqual(errors.getvalue(), '')
        self.assertNotIn('TOP_SECRET_UNIQUE_TOKEN', output.getvalue())
        self.assertIn('not installed or started', output.getvalue())
        self.assertIn('sudo systemctl enable --now clbip-watchdog-friend-one.service', output.getvalue())
        self.assertIn('nano -- ', output.getvalue())
        self.assertEqual(self.legacy.read_text(), 'EXISTING_PRIVATE_CONFIG=preserve\n')

    def test_existing_node_cli_failure_does_not_print_tokens(self):
        one = self.create()
        token = self.env(one.environment)['WATCHDOG_SHARED_TOKEN']
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            code = nodes.main(['--root', str(self.root), '--name', 'friend-one',
                               '--bind', '100.76.59.88'])
        self.assertEqual(code, 1)
        self.assertNotIn(token, errors.getvalue())
        self.assertIn('existing files were not overwritten', errors.getvalue())


if __name__ == '__main__':
    unittest.main()
