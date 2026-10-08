"""Offline typed settings tests for the opt-in startup rebuild controls."""
import unittest
from unittest.mock import patch

from validation import DEFAULT_SETTINGS, ValidationError, public_settings, settings_patch


class RebootSettingsTests(unittest.TestCase):
    def test_defaults_are_opt_in_and_count_25(self):
        settings = settings_patch({})
        self.assertIs(settings['startup_rebuild_enabled'], False)
        self.assertEqual(settings['startup_proxy_count'], 25)
        self.assertIs(DEFAULT_SETTINGS['startup_rebuild_enabled'], False)

    def test_enable_disable_and_boundaries(self):
        for enabled in (True, False):
            for count in (1, 25, 1024):
                with self.subTest(enabled=enabled, count=count):
                    settings = settings_patch({'startup_rebuild_enabled': enabled, 'startup_proxy_count': count})
                    self.assertIs(settings['startup_rebuild_enabled'], enabled)
                    self.assertEqual(settings['startup_proxy_count'], count)

    def test_enabled_requires_actual_boolean(self):
        for enabled in (0, 1, 'true', 'false', None, [], {}):
            with self.subTest(enabled=enabled):
                with self.assertRaisesRegex(ValidationError, 'startup_rebuild_enabled'):
                    settings_patch({'startup_rebuild_enabled': enabled})

    def test_count_requires_bounded_integer_even_when_disabled(self):
        for count in (True, False, 0, -1, 1025, 1.0, 1.5, '25', None, [], {}):
            with self.subTest(count=count):
                with self.assertRaisesRegex(ValidationError, 'startup_proxy_count'):
                    settings_patch({'startup_proxy_count': count})

    def test_patch_preserves_configuration_and_existing_recovery_values(self):
        previous = settings_patch({'startup_rebuild_enabled': True, 'startup_proxy_count': 100,
                                   'start_port': 11000, 'protocol': 'dual', 'interface': 'enp1s0',
                                   'auth_type': 'ip', 'allowed_ips': ['192.168.1.0/24']})
        settings = settings_patch({'timeout_connect': 8}, previous)
        for name in ('startup_rebuild_enabled', 'startup_proxy_count', 'start_port', 'protocol',
                     'interface', 'auth_type', 'allowed_ips'):
            self.assertEqual(settings[name], previous[name])
        self.assertEqual(settings['timeout_connect'], 8)

    def test_legacy_settings_migrate_without_starting_new_behavior(self):
        old = {name: value for name, value in DEFAULT_SETTINGS.items() if not name.startswith('startup_')}
        settings = settings_patch({}, old)
        self.assertIs(settings['startup_rebuild_enabled'], False)
        self.assertEqual(settings['startup_proxy_count'], 25)

    def test_public_settings_expose_controls_but_keep_secret_masked(self):
        settings = settings_patch({'startup_rebuild_enabled': True, 'startup_proxy_count': 80,
                                   'telegram_bot_token': 'fixture-token'})
        public = public_settings(settings)
        self.assertIs(public['startup_rebuild_enabled'], True)
        self.assertEqual(public['startup_proxy_count'], 80)
        self.assertNotIn('telegram_bot_token', public)

    def test_recovery_setting_validation_performs_no_network_calls(self):
        with patch('validation.socket.getaddrinfo', side_effect=AssertionError('No network in settings validation')):
            settings = settings_patch({'startup_rebuild_enabled': True, 'startup_proxy_count': 20})
        self.assertEqual(settings['startup_proxy_count'], 20)


if __name__ == '__main__':
    unittest.main()
