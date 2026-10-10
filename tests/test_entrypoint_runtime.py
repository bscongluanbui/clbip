"""Offline contracts for the read-only dashboard container entrypoint."""
from pathlib import Path
import shlex
import unittest


ROOT = Path(__file__).resolve().parents[1]


def dashboard_arguments(source):
    """Read the continued Gunicorn command without running the entrypoint."""
    command = source.split('    gunicorn ', 1)[1].split(' &', 1)[0]
    return shlex.split('gunicorn ' + command.replace('\\\n', ' '))


class EntrypointRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (ROOT / 'start.sh').read_text(encoding='utf-8')
        cls.arguments = dashboard_arguments(cls.source)

    def test_optional_control_socket_is_disabled_for_read_only_home(self):
        # Gunicorn >=25.1 creates $HOME/.gunicorn by default. Containers have
        # a read-only root and no need for the optional gunicornc interface.
        self.assertIn('--no-control-socket', self.arguments)
        self.assertNotIn('--control-socket', self.arguments)

    def test_worker_temporary_files_stay_on_existing_tmpfs(self):
        index = self.arguments.index('--worker-tmp-dir')
        self.assertEqual(self.arguments[index + 1], '/tmp')
        self.assertNotIn('mkdir -p /home/manager', self.source)
        self.assertNotIn('chmod 777', self.source)

    def test_threaded_worker_and_timeout_settings_are_preserved(self):
        for option, value in (('--workers', '1'), ('--threads', '8'),
                              ('--worker-class', 'gthread'), ('--timeout', '300'),
                              ('--graceful-timeout', '30')):
            with self.subTest(option=option):
                self.assertEqual(self.arguments[self.arguments.index(option) + 1], value)
        self.assertEqual(self.arguments[-1], 'app:app')

    def test_bind_remains_configurable_with_loopback_default(self):
        self.assertIn('GUI_BIND=${GUI_BIND:-127.0.0.1}', self.source)
        self.assertEqual(self.arguments[self.arguments.index('--bind') + 1],
                         '${GUI_BIND}:${GUI_PORT}')

    def test_logs_keep_using_stdout_and_stderr(self):
        for option in ('--access-logfile', '--error-logfile'):
            with self.subTest(option=option):
                self.assertEqual(self.arguments[self.arguments.index(option) + 1], '-')

    def test_signal_and_child_exit_propagation_are_preserved(self):
        for contract in ('trap \'finish; exit 143\' TERM',
                         'trap \'finish; exit 130\' INT', 'trap finish EXIT',
                         'kill -TERM "$pid"', 'wait "$pid"',
                         'wait -n "${children[@]}"', 'status=$?',
                         'if (( status == 0 )); then status=1; fi', 'exit "$status"'):
            with self.subTest(contract=contract):
                self.assertIn(contract, self.source)

    def test_fix_is_dashboard_only_and_entrypoint_uses_lf(self):
        worker_branch = self.source.split('  worker)', 1)[1].split('  *)', 1)[0]
        self.assertNotIn('gunicorn', worker_branch)
        self.assertIn('python -u worker.py &', worker_branch)
        self.assertNotIn(b'\r\n', (ROOT / 'start.sh').read_bytes())


if __name__ == '__main__':
    unittest.main()
