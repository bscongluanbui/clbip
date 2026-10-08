"""Offline Linux/Docker doctor, transactional port helper and preview fixtures."""
import copy
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from scripts import change_dashboard_port as port_helper
from scripts import doctor
from scripts import preview_dashboard as preview


class FakeDocker:
    def __init__(self, root):
        self.root, self.calls = Path(root), []
        self.fail_up = 0
        self.override_port = None
        self.changed_bind = None
        self.config_failure = None
        self.logs = 'worker: demo ready\ndashboard: demo ready'
        self.stopped = set()
        self.bad_health = set()
        self.missing_binary = None
        self.rpc_ready = True
        self.login_http = 200
        self.secret = 'PRIVATE_FIXTURE_PASSWORD_123'

    def config(self):
        env = self.root / '.env'
        values = {}
        if env.exists():
            for line in env.read_text(encoding='utf-8').splitlines():
                if '=' in line and not line.startswith('#'):
                    key, value = line.removeprefix('export ').split('=', 1)
                    values[key.strip()] = value.strip()
        return {'services': {
            'worker': {'user': '0:10001', 'network_mode': 'host', 'image': 'test',
                       'environment': {'APP_ROLE': 'worker'}},
            'dashboard': {'user': '10001:10001', 'network_mode': 'host', 'image': 'test',
                          'environment': {'APP_ROLE': 'dashboard', 'ADMIN_PASSWORD': self.secret,
                                          'GUI_PORT': str(self.override_port or values.get('GUI_PORT', 7070)),
                                          'GUI_BIND': self.changed_bind or values.get('GUI_BIND', '127.0.0.1')}}}}

    def __call__(self, args, *, timeout=10, cwd=None, env=None):
        self.calls.append({'args': list(args), 'cwd': cwd, 'env': env, 'timeout': timeout})
        output, code = '', 0
        if args[0] == 'ss':
            output = 'LISTEN 127.0.0.1:7070 users:((gunicorn,pid=10,fd=4))'
        elif 'config' in args:
            if self.config_failure:
                output, code = self.config_failure, 1
            else:
                output = json.dumps(self.config())
        elif 'ps' in args:
            output = json.dumps([{'Service': role, 'State': 'exited' if role in self.stopped else 'running',
                                  'Health': 'unhealthy' if role in self.bad_health else 'healthy', 'ExitCode': 0}
                                 for role in ('worker', 'dashboard')])
        elif 'logs' in args:
            output = self.logs
        elif 'exec' in args:
            role = args[args.index('-T')+1]
            if args[-1] == doctor.RPC_CHECK:
                output = json.dumps({'authenticated': True, 'ready': self.rpc_ready, 'desired_state': 'running'})
            elif args[-1] == doctor.DASHBOARD_CHECK:
                output = json.dumps({'login_http': self.login_http, 'files': [{'name': 'WORKER_SOCKET', 'mode': 'srw-rw----', 'uid': 0, 'gid': 10001}]})
            else:
                info = {'python': '3.12.0', 'uid': 0 if role == 'worker' else 10001, 'gid': 10001,
                        'role': role, 'flask': 'fixture', 'gunicorn': 'fixture', 'curl': True, 'ip': True, '3proxy': True}
                if self.missing_binary:
                    info[self.missing_binary] = False
                output = json.dumps(info)
        elif 'up' in args:
            if self.fail_up:
                self.fail_up -= 1
                output, code = f'recreate failed with password={self.secret}', 1
        else:
            raise AssertionError('Unexpected fixture command: ' + str(args))
        return {'exit': code, 'output': output, 'timeout': False}


class OpsFixture(unittest.TestCase):
    def setUp(self):
        test_temp = Path(__file__).resolve().parents[1] / '.test-tmp'
        test_temp.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='ipv6-ops-test-', dir=test_temp)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'docker-compose.yml').write_text('services: {}\n', encoding='utf-8')
        self.env = self.root / '.env'
        self.original = b'# operator settings\nGUI_BIND=192.168.1.3\nGUI_PORT=7070\nOTHER=keep\n'
        self.env.write_bytes(self.original)
        self.runner = FakeDocker(self.root)
        self.probes, self.live = [], []

    def probe(self, host, port):
        self.probes.append((host, port))

    def live_check(self, url):
        self.live.append(url)

    def change(self, port=7071, **kwargs):
        return port_helper.change_port(port, project_dir=self.root, runner=self.runner,
                                       probe=kwargs.pop('probe', self.probe),
                                       live_check=kwargs.pop('live_check', self.live_check),
                                       out=kwargs.pop('out', io.StringIO()), **kwargs)

    def doctor(self, probe=None):
        if probe is None:
            probe = lambda url, timeout: {'http': 200, 'body': {'alive': True, 'ready': True}}
        return doctor.Doctor(self.root, runner=self.runner, probe=probe).collect()


class DoctorTests(OpsFixture):
    def test_healthy_offline_fixture(self):
        report, code = self.doctor()
        self.assertEqual(code, 0, report)
        self.assertIn('CLASSIFICATION: healthy', report)
        self.assertIn('authenticated worker RPC', report)

    def test_only_read_only_commands(self):
        self.doctor()
        for call in self.runner.calls:
            self.assertNotIn('up', call['args'])
            self.assertNotIn('restart', call['args'])
            self.assertNotIn('stop', call['args'])
        self.assertEqual(self.env.read_bytes(), self.original)

    def test_project_directory_absolute_for_every_docker_command(self):
        self.doctor()
        for call in self.runner.calls:
            self.assertEqual(call['cwd'], str(self.root))
            if call['args'][0] == 'docker':
                self.assertEqual(call['args'][call['args'].index('--project-directory')+1], str(self.root))

    def test_secrets_in_config_logs_and_rpc_are_redacted(self):
        self.runner.logs = 'password=' + self.runner.secret + '\nhttps://alice:hunter2@host\nBearer ABC123TOKEN'
        report, _ = self.doctor()
        for value in (self.runner.secret, 'hunter2', 'ABC123TOKEN'):
            self.assertNotIn(value, report)

    def test_file_secret_redacted_on_command_failure(self):
        secrets_dir = self.root / 'secrets'
        secrets_dir.mkdir()
        (secrets_dir / 'service_token').write_text('bare-token-private-fixture')
        self.runner.config_failure = 'Docker says bare-token-private-fixture is invalid'
        report, code = self.doctor()
        self.assertEqual(code, 1)
        self.assertNotIn('bare-token-private-fixture', report)

    def test_env_secret_redacted_on_failed_config(self):
        self.env.write_text('ADMIN_PASSWORD=env-private-fixture\n')
        self.runner.config_failure = 'invalid bare env-private-fixture'
        report, _ = self.doctor()
        self.assertNotIn('env-private-fixture', report)

    def test_dashboard_conflict_classification(self):
        self.runner.stopped.add('dashboard')
        self.runner.logs = 'dashboard: [Errno 98] Address already in use'
        report, code = self.doctor(lambda url, timeout: {'http': 503, 'body': {}})
        self.assertEqual(code, 1)
        self.assertIn('CLASSIFICATION: dashboard_port_conflict', report)
        self.assertIn('change_dashboard_port.py 7071', report)

    def test_old_conflict_log_does_not_override_current_health(self):
        self.runner.logs = 'old startup: Address already in use'
        report, code = self.doctor()
        self.assertEqual(code, 0)
        self.assertIn('CLASSIFICATION: healthy', report)

    def test_not_ready_rpc_marks_failure(self):
        self.runner.rpc_ready = False
        report, code = self.doctor()
        self.assertEqual(code, 1)
        self.assertIn('[FAIL] worker readiness', report)

    def test_health_endpoint_bad_field_marks_failure(self):
        report, code = self.doctor(lambda url, timeout: {'http': 200, 'body': {'alive': True, 'ready': False}})
        self.assertEqual(code, 1)
        self.assertIn('[FAIL] dashboard /readyz', report)

    def test_http_failure_does_not_skip_logs(self):
        def failed(*args, **kwargs):
            raise OSError('fixture timeout')
        report, code = self.doctor(failed)
        self.assertEqual(code, 1)
        self.assertIn('recent logs (redacted)', report)

    def test_missing_worker_binary_marks_failure(self):
        self.runner.missing_binary = '3proxy'
        report, code = self.doctor()
        self.assertEqual(code, 1)
        self.assertIn('[FAIL] runtime identity worker', report)

    def test_dashboard_import_preflight_uses_real_dashboard_identity(self):
        self.runner.login_http = 503
        report, code = self.doctor()
        self.assertEqual(code, 1)
        self.assertIn('[FAIL] dashboard login preflight', report)
        calls = [call for call in self.runner.calls if call['args'][-1] == doctor.DASHBOARD_CHECK]
        self.assertEqual(calls[0]['args'][calls[0]['args'].index('-T')+1], 'dashboard')
        self.assertIn('-B', calls[0]['args'])

    def test_config_error_without_services_collects_remaining_sections(self):
        self.runner.config_failure = 'services.worker malformed'
        report, code = self.doctor()
        self.assertEqual(code, 1)
        self.assertIn('[FAIL] Compose config', report)
        self.assertIn('recent logs', report)

    def test_redactor_json_yaml_url_cl_tokens(self):
        redact = doctor.Redactor()
        output = redact('"current_password":"private1"\nSERVICE_TOKEN: private2\n'
                        'https://demo:private3@host\nfoo:CL:private4\nBearer private5')
        for index in range(1, 6):
            self.assertNotIn('private'+str(index), output)


class DashboardPortTests(OpsFixture):
    def test_success_preserves_bind_and_unrelated_env(self):
        result = self.change()
        self.assertTrue(result['changed'])
        self.assertEqual(self.probes, [('192.168.1.3', 7071)])
        self.assertEqual(self.env.read_bytes(), self.original.replace(b'7070', b'7071'))
        self.assertEqual(self.live, ['http://192.168.1.3:7071'])

    def test_backups_include_original_env_compose_and_manifest(self):
        result = self.change()
        backup = Path(result['backup'])
        self.assertEqual((backup / 'env.before').read_bytes(), self.original)
        self.assertEqual((backup / 'compose-0.before').read_bytes(), (self.root / 'docker-compose.yml').read_bytes())
        self.assertEqual(json.loads((backup / 'manifest.json').read_text())['old_port'], 7070)

    def test_dashboard_only_no_worker_start_even_if_stopped(self):
        self.runner.stopped.add('worker')
        self.change()
        for call in self.runner.calls:
            args = call['args']
            if 'up' in args:
                self.assertIn('--no-deps', args)
                self.assertIn('--no-build', args)
                self.assertEqual(args[-1], 'dashboard')
                self.assertNotIn('worker', args)

    def test_busy_port_leaves_config_and_services_untouched(self):
        def busy(*args):
            raise OSError('Address already in use')
        with self.assertRaises(OSError):
            self.change(probe=busy)
        self.assertEqual(self.env.read_bytes(), self.original)
        self.assertFalse(any('up' in call['args'] for call in self.runner.calls))
        self.assertFalse((self.root / '.dashboard-port-backups').exists())

    def test_same_port_no_probe_files_or_service_changes(self):
        result = self.change(7070)
        self.assertFalse(result['changed'])
        self.assertFalse(self.probes)
        self.assertFalse(any('up' in call['args'] for call in self.runner.calls))
        self.assertEqual(self.env.read_bytes(), self.original)

    def test_failed_recreate_restores_original_env_and_old_dashboard(self):
        self.runner.fail_up = 1
        with self.assertRaisesRegex(RuntimeError, 'previous dashboard port verified live'):
            self.change()
        self.assertEqual(self.env.read_bytes(), self.original)
        self.assertEqual(self.live, ['http://192.168.1.3:7070'])
        self.assertEqual(sum('up' in call['args'] for call in self.runner.calls), 2)

    def test_failed_recreate_error_redacts_credentials(self):
        self.runner.fail_up = 1
        with self.assertRaises(RuntimeError) as exc:
            self.change()
        self.assertNotIn(self.runner.secret, str(exc.exception))

    def test_failed_health_rolls_back(self):
        def fail_first(url):
            self.live.append(url)
            if len(self.live) == 1:
                raise RuntimeError('fixture health failed')
        with self.assertRaisesRegex(RuntimeError, 'previous dashboard port verified live'):
            self.change(live_check=fail_first)
        self.assertEqual(self.env.read_bytes(), self.original)
        self.assertEqual(self.live, ['http://192.168.1.3:7071', 'http://192.168.1.3:7070'])

    def test_failed_rollback_still_restores_env_and_reports_failure(self):
        self.runner.fail_up = 2
        with self.assertRaisesRegex(RuntimeError, 'rollback recreate failed'):
            self.change()
        self.assertEqual(self.env.read_bytes(), self.original)

    def test_absent_env_removed_after_failed_recreate(self):
        self.env.unlink()
        self.runner.fail_up = 1
        with self.assertRaises(RuntimeError):
            self.change()
        self.assertFalse(self.env.exists())

    def test_hardcoded_compose_port_rejected_before_recreate(self):
        self.runner.override_port = 7070
        with self.assertRaisesRegex(RuntimeError, 'Compose override prevents'):
            self.change()
        self.assertEqual(self.env.read_bytes(), self.original)
        self.assertFalse(any('up' in call['args'] for call in self.runner.calls))

    def test_shell_gui_port_does_not_override_persisted_change(self):
        with patch.dict(os.environ, {'GUI_PORT': '9999', 'GUI_BIND': '192.168.1.3'}):
            self.change()
        for call in self.runner.calls:
            self.assertNotIn('GUI_PORT', call['env'])
            self.assertEqual(call['env']['GUI_BIND'], '192.168.1.3')

    def test_override_compose_backed_up_and_selected(self):
        override = self.root / 'docker-compose.override.yml'
        override.write_text('# fixture override\n')
        result = self.change()
        self.assertEqual((Path(result['backup']) / 'compose-1.before').read_bytes(), override.read_bytes())
        self.assertTrue(all(str(override) in call['args'] for call in self.runner.calls))

    def test_concurrent_updater_is_rejected(self):
        with port_helper.update_lock(self.root):
            with self.assertRaisesRegex(RuntimeError, 'Another dashboard port update'):
                self.change()
        self.assertEqual(self.env.read_bytes(), self.original)

    def test_invalid_port_values(self):
        for value in (True, None, -1, 1023, 65536, '7071;touch', '７０７１', 7071.0):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.change(value)

    def test_env_editor_preserves_crlf_comments_and_removes_duplicates(self):
        original = b'# comment\r\nexport GUI_PORT=7070\r\nOTHER=x\r\nGUI_PORT=7070\r\n'
        self.assertEqual(port_helper.update_env(original, 7071), b'# comment\r\nGUI_PORT=7071\r\nOTHER=x\r\n')

    def test_env_editor_appends_without_truncating_last_line(self):
        self.assertEqual(port_helper.update_env(b'OTHER=x', 7071), b'OTHER=x\nGUI_PORT=7071\n')

    def test_ipv6_bind_not_replaced_with_ipv4(self):
        self.env.write_text('GUI_BIND=::1\nGUI_PORT=7070\n')
        self.change()
        self.assertEqual(self.probes, [('::1', 7071)])
        self.assertEqual(self.live, ['http://[::1]:7071'])

    def test_preflight_real_busy_loopback(self):
        with socket.socket() as listener:
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            with self.assertRaises(OSError):
                port_helper.probe_port('127.0.0.1', listener.getsockname()[1])

    def test_config_failure_secrets_in_env_are_redacted(self):
        self.env.write_text('ADMIN_PASSWORD=private-env-secret\n')
        self.runner.config_failure = 'invalid private-env-secret'
        with self.assertRaises(RuntimeError) as exc:
            self.change()
        self.assertNotIn('private-env-secret', str(exc.exception))


class PreviewTests(unittest.TestCase):
    def test_preview_only_read_methods(self):
        client = preview.PreviewClient()
        for method in ('generate', 'stop', 'start', 'rotate', 'cleanup', 'save_settings', 'export', 'password'):
            with self.subTest(method=method), self.assertRaises(Exception) as exc:
                client.call(method, {})
            self.assertEqual(exc.exception.status, 403)

    def test_preview_payloads_are_detached_copies(self):
        client = preview.PreviewClient()
        response = client.call('settings')
        response['max_connections'] = 1
        self.assertEqual(client.call('settings')['max_connections'], 64)

    def test_preview_read_status_progress_inventory(self):
        client = preview.PreviewClient()
        self.assertEqual(client.call('status')['progress']['verified'], 100)
        self.assertEqual(len(client.call('proxies')['proxies']), 100)
        self.assertEqual(len(client.call('interfaces')['details']), 3)

    def test_preview_app_login_and_read_data(self):
        app = preview.create_preview_app()
        client = app.test_client()
        token = client.get('/api/csrf').get_json()['csrf_token']
        response = client.post('/login', data={'password': preview.DEMO_PASSWORD, 'csrf_token': token})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(client.get('/api/status').status_code, 200)
        self.assertEqual(client.get('/readyz').status_code, 200)

    def test_preview_mutation_guard_does_not_call_real_password_store(self):
        app = preview.create_preview_app()
        client = app.test_client()
        token = client.get('/api/csrf').get_json()['csrf_token']
        client.post('/login', data={'password': preview.DEMO_PASSWORD, 'csrf_token': token})
        token = client.get('/api/csrf').get_json()['csrf_token']
        for path in ('/api/proxy/start', '/api/proxies/generate', '/api/password'):
            with self.subTest(path=path):
                response = client.post(path, json={}, headers={'X-CSRF-Token': token})
                self.assertEqual(response.status_code, 403)


if __name__ == '__main__':
    unittest.main()
