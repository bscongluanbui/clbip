"""Explicit empty generation fields select no-auth; omitted keys retain credentials.

These fixtures use an isolated SQLite store and fake NIC/engine only.
"""
import copy
import unittest

import test_service as fixtures
from service import OperationError
from validation import DEFAULT_SETTINGS, ValidationError, generation_auth


class GenerationAuthValidationTests(unittest.TestCase):
    def test_omitted_pair_keeps_mode_and_does_not_mutate_input(self):
        for mode in ('userpass', 'none', 'ip'):
            settings = {**DEFAULT_SETTINGS, 'auth_type': mode}
            before = copy.deepcopy(settings)
            normalized, pair = generation_auth({}, settings)
            self.assertEqual(normalized, before)
            self.assertIsNone(pair)
            self.assertIsNot(normalized, settings)
            self.assertEqual(settings, before)

    def test_explicit_blank_preserves_other_settings_and_input(self):
        settings = {**DEFAULT_SETTINGS, 'listener_ipv4': '192.168.1.3',
                    'allowed_ips': ['192.168.1.0/24'], 'allow_private_destinations': False}
        before = copy.deepcopy(settings)
        normalized, pair = generation_auth({'username': '', 'password': ''}, settings)
        self.assertEqual(normalized, {**before, 'auth_type': 'none', 'public_proxy': True})
        self.assertIsNone(pair)
        self.assertEqual(settings, before)

    def test_null_nonstring_or_injected_values_are_not_blank(self):
        for pair in [(None, None), (0, 0), ([], []), (' ', ' '), ('\nauth none', ''), ('tester', 'x#')]:
            with self.subTest(pair=pair), self.assertRaises(ValidationError):
                generation_auth({'username': pair[0], 'password': pair[1]}, DEFAULT_SETTINGS)

    def test_one_missing_field_does_not_imply_blank(self):
        for params in [{'username': ''}, {'password': ''}, {'username': 'tester'}, {'password': '1'}]:
            with self.subTest(params=params), self.assertRaisesRegex(ValidationError, 'cả username và password'):
                generation_auth(params, DEFAULT_SETTINGS)

    def test_user_credential_validation_remains_strict(self):
        normalized, pair = generation_auth({'username': 'tester', 'password': '1'}, DEFAULT_SETTINGS)
        self.assertEqual(pair, ('tester', '1'))
        self.assertEqual(normalized['auth_type'], 'userpass')
        self.assertFalse(normalized['public_proxy'])


class ProxyGenerationAuthTests(unittest.TestCase):
    setUp = fixtures.ServiceTests.setUp
    tearDown = fixtures.ServiceTests.tearDown
    names = fixtures.ServiceTests.names
    generate = fixtures.ServiceTests.generate

    def test_explicit_blank_pair_generates_no_auth_on_fresh_install(self):
        result = self.generate(username='', password='')
        state = self.store.read()
        self.assertTrue(result['success'])
        self.assertEqual(state['settings']['auth_type'], 'none')
        self.assertTrue(state['settings']['public_proxy'])
        self.assertEqual(state['users'], [])
        self.assertEqual(self.engine.config['settings']['auth_type'], 'none')

    def test_blank_pair_does_not_reuse_old_user_or_change_listener_acl(self):
        self.generate()
        before = self.store.read()
        before['settings'].update(listener_ipv4='192.168.1.3', allowed_ips=['192.168.1.0/24'])
        self.store.write(before)
        result = self.generate(username='', password='', recreate=True)
        state = self.store.read()
        self.assertTrue(result['success'])
        self.assertEqual(state['settings']['auth_type'], 'none')
        self.assertEqual(state['settings']['listener_ipv4'], '192.168.1.3')
        self.assertEqual(state['settings']['allowed_ips'], ['192.168.1.0/24'])
        self.assertEqual(state['users'], before['users'])
        self.assertEqual(len(state['proxies']), 1)
        exported = self.service.export({'format': 'full_url'})
        self.assertNotIn(fixtures.USER['username'], str(exported))
        self.assertNotIn(fixtures.USER['password'], str(exported))

    def test_omitted_credential_keys_keep_saved_auth_for_api_and_recovery(self):
        self.generate()
        before = self.store.read()
        result = self.service.dispatch('generate', {'count': 1, 'subnet': fixtures.POOL, 'recreate': True})
        state = self.store.read()
        self.assertTrue(result['success'])
        self.assertEqual(state['settings']['auth_type'], 'userpass')
        self.assertEqual(state['users'], before['users'])
        self.assertFalse(state['settings']['public_proxy'])

    def test_partial_or_missing_pair_errors_before_nic_and_preserves_state(self):
        for pair in [{'username': 'tester', 'password': ''}, {'username': '', 'password': 'fixture'},
                     {'username': ''}, {'password': ''}, {'username': 'tester'}, {'password': 'fixture'}]:
            self.events.clear()
            before = self.store.read()
            with self.subTest(pair=pair), self.assertRaisesRegex(ValidationError, 'cả username và password'):
                self.service.dispatch('generate', {'count': 1, 'subnet': fixtures.POOL, **pair})
            self.assertEqual(self.store.read(), before)
            self.assertFalse(set(self.names()) & {'preflight', 'snapshot', 'generate', 'add'})

    def test_blank_pair_keeps_explicit_ip_allowlist_mode(self):
        result = self.generate(username='', password='', auth_type='ip', allowed_ips=['192.168.1.0/24'])
        state = self.store.read()
        self.assertTrue(result['success'])
        self.assertEqual(state['settings']['auth_type'], 'ip')
        self.assertEqual(state['settings']['allowed_ips'], ['192.168.1.0/24'])
        self.assertFalse(state['settings']['public_proxy'])
        self.assertEqual(state['users'], [])

    def test_no_credentials_omitted_remains_an_error_on_fresh_userpass_install(self):
        before = self.store.read()
        with self.assertRaises(ValueError):
            self.service.dispatch('generate', {'count': 1, 'subnet': fixtures.POOL})
        self.assertEqual(self.store.read(), before)
        self.assertNotIn('add', self.names())

    def test_nonempty_pair_selects_userpass_when_previous_pool_was_no_auth(self):
        self.generate(username='', password='')
        result = self.generate(auth_type='userpass', username='new-user', password='1', recreate=True,
                               public_proxy=False)
        self.assertTrue(result['success'])
        state = self.store.read()
        self.assertEqual(state['settings']['auth_type'], 'userpass')
        self.assertEqual(state['users'][0]['username'], 'new-user')
        self.assertEqual(state['users'][0]['password'], '1')
        self.assertFalse(state['settings']['public_proxy'])

    def test_failed_blank_generation_rolls_back_saved_auth_and_pool(self):
        self.generate()
        before = copy.deepcopy(self.store.read())
        self.net.failure = 'probe'
        with self.assertRaises(OperationError):
            self.generate(username='', password='', recreate=True)
        self.assertIn('probe', self.names())
        after = self.store.read()
        for key in ('settings', 'users', 'proxies', 'managed_addresses'):
            self.assertEqual(after[key], before[key], key)


if __name__ == '__main__':
    unittest.main()
