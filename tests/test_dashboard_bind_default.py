"""Offline contracts for the dashboard's default bind, not a port change."""
import copy
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import app as dashboard


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('dashboard_bind_doctor', ROOT / 'scripts' / 'doctor.py')
doctor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(doctor)
TOKEN = 'bind-default-test-service-token-' + 't' * 40
CONFIG = {'TESTING': True, 'SECRET_KEY': 'bind-test-session-key-' + 's' * 40,
          'ADMIN_PASSWORD': '', 'SERVICE_TOKEN': TOKEN, 'DASHBOARD_PASSWORD_PATH': '',
          'SESSION_COOKIE_SECURE': False}


class DashboardBindDefaultTests(unittest.TestCase):
    def application(self, env, config=None):
        worker = Mock()
        worker.call.return_value = {'proxy_running': False, 'desired_state': 'stopped',
                                    'dashboard_hosts': ['192.168.1.3', '100.127.65.53']}
        with patch.dict(os.environ, env, clear=True):
            application = dashboard.create_app({**CONFIG, **(config or {})}, worker)
        return application, worker

    def test_unset_environment_defaults_to_all_interfaces_without_changing_port(self):
        application, worker = self.application({})
        self.assertEqual(application.config['GUI_BIND'], '0.0.0.0')
        self.assertEqual(application.config['GUI_PORT'], '7070')
        worker.call.assert_not_called()

    def test_empty_environment_uses_same_all_interfaces_default(self):
        application, worker = self.application({'GUI_BIND': ''})
        self.assertEqual(application.config['GUI_BIND'], '0.0.0.0')
        worker.call.assert_not_called()

    def test_explicit_environment_bind_and_port_are_retained(self):
        for bind in ('127.0.0.1', '192.168.1.3', '::1', '::'):
            with self.subTest(bind=bind):
                application, _ = self.application({'GUI_BIND': bind, 'GUI_PORT': '17070'})
                self.assertEqual(application.config['GUI_BIND'], bind)
                self.assertEqual(application.config['GUI_PORT'], '17070')

    def test_explicit_application_config_still_overrides_environment(self):
        application, _ = self.application({'GUI_BIND': '0.0.0.0'}, {'GUI_BIND': '127.0.0.1'})
        self.assertEqual(application.config['GUI_BIND'], '127.0.0.1')

    def test_status_defaults_to_all_interfaces_and_lists_observed_lan_hosts(self):
        for environment in ({}, {'GUI_BIND': ''}):
            with self.subTest(environment=environment):
                application, worker = self.application(environment)
                response = application.test_client().get('/api/status', headers={'Authorization': 'Bearer ' + TOKEN})
                self.assertEqual(response.status_code, 200)
                body = response.get_json()
                self.assertEqual(body['dashboard_bind'], '0.0.0.0')
                self.assertEqual(body['dashboard_port'], 7070)
                self.assertEqual(body['dashboard_hosts'], ['192.168.1.3', '100.127.65.53'])
                worker.call.assert_called_once_with('status', {})

    def test_status_preserves_explicit_loopback_and_lan_bind(self):
        for bind in ('127.0.0.1', '192.168.1.3'):
            with self.subTest(bind=bind):
                application, _ = self.application({'GUI_BIND': bind, 'GUI_PORT': '17070'})
                response = application.test_client().get('/api/status', headers={'Authorization': 'Bearer ' + TOKEN})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json()['dashboard_bind'], bind)
                self.assertEqual(response.get_json()['dashboard_hosts'], [bind])
                self.assertEqual(response.get_json()['dashboard_port'], 17070)

    def test_status_missing_or_empty_config_uses_default_but_invalid_stays_loopback(self):
        for value, expected in ((None, '0.0.0.0'), ('', '0.0.0.0'), ('not-an-ip', '127.0.0.1')):
            with self.subTest(value=value):
                application, _ = self.application({})
                if value is None:
                    application.config.pop('GUI_BIND')
                else:
                    application.config['GUI_BIND'] = value
                response = application.test_client().get('/api/status', headers={'Authorization': 'Bearer ' + TOKEN})
                self.assertEqual(response.status_code, 200)
                self.assertEqual(response.get_json()['dashboard_bind'], expected)

    def test_doctor_missing_or_empty_bind_connects_via_loopback(self):
        for environment in ({}, {'GUI_BIND': ''}):
            with self.subTest(environment=environment):
                config = {'services': {'dashboard': {'environment': environment}}}
                self.assertEqual(doctor.dashboard_address(config),
                                 ('0.0.0.0', 7070, 'http://127.0.0.1:7070'))

    def test_doctor_preserves_explicit_ipv4_and_ipv6_bind_overrides(self):
        for bind, url in (('127.0.0.1', 'http://127.0.0.1:17070'),
                          ('192.168.1.3', 'http://192.168.1.3:17070'),
                          ('::', 'http://[::1]:17070'), ('::1', 'http://[::1]:17070')):
            with self.subTest(bind=bind):
                config = {'services': {'dashboard': {'environment': {'GUI_BIND': bind, 'GUI_PORT': '17070'}}}}
                self.assertEqual(doctor.dashboard_address(config), (bind, 17070, url))

    def test_image_compose_and_entrypoint_agree_on_all_interfaces_default(self):
        dockerfile = (ROOT / 'Dockerfile').read_text(encoding='utf-8')
        compose = (ROOT / 'docker-compose.yml').read_text(encoding='utf-8')
        entrypoint = (ROOT / 'start.sh').read_text(encoding='utf-8')
        self.assertIn('DATA_DIR=/app/data GUI_PORT=7070 GUI_BIND=0.0.0.0', dockerfile)
        self.assertEqual(compose.count('GUI_BIND: "${GUI_BIND:-0.0.0.0}"'), 2)
        self.assertEqual(compose.count('GUI_PORT: "${GUI_PORT:-7070}"'), 2)
        self.assertIn('GUI_BIND=${GUI_BIND:-0.0.0.0}', entrypoint)
        self.assertIn('GUI_PORT=${GUI_PORT:-7070}', entrypoint)
        self.assertIn('--bind "${GUI_BIND}:${GUI_PORT}"', entrypoint)


if __name__ == '__main__':
    unittest.main()
