"""Fresh pool generation replaces old rows; explicit append and rollback remain.

The NIC/3proxy are in-memory fixtures and the state store is workspace SQLite.
"""
import copy
from pathlib import Path
import re
import unittest

import test_service as fixtures
from service import OperationError, address_key


class PoolRecreateTests(unittest.TestCase):
    setUp = fixtures.ServiceTests.setUp
    tearDown = fixtures.ServiceTests.tearDown
    generate = fixtures.ServiceTests.generate
    names = fixtures.ServiceTests.names

    def test_dashboard_defaults_to_recreate_but_checkbox_is_optional(self):
        template = (Path(__file__).resolve().parents[1] / 'templates' / 'index.html').read_text(encoding='utf-8')
        checkbox = re.search(r'<input\b[^>]*\bid="opt-recreate"[^>]*>', template)
        self.assertIsNotNone(checkbox)
        self.assertRegex(checkbox.group(0), r'\bchecked(?:\s|>|=)')
        self.assertNotRegex(checkbox.group(0), r'\bdisabled(?:\s|>|=)')

    def test_successful_recreate_commits_exact_count_and_removes_old_pool(self):
        self.generate(count=3)
        original = copy.deepcopy(self.store.read())
        old_ids = {row['id'] for row in original['proxies']}
        old_keys = {address_key(row) for row in original['managed_addresses']}
        self.events.clear()
        result = self.generate(count=2, recreate=True)
        current = self.store.read()
        self.assertEqual((result['generated'], result['total'], len(current['proxies'])), (2, 2, 2))
        self.assertFalse(old_ids & {row['id'] for row in current['proxies']})
        self.assertFalse(old_keys & set(self.net.aliases))
        self.assertEqual(set(self.net.aliases), {address_key(row) for row in current['managed_addresses']})
        self.assertEqual(len(current['managed_addresses']), 2)
        self.assertEqual([row['port'] for row in current['proxies']], [10000, 10001])
        self.assertEqual([(row['id'], row['ipv6'], row['port']) for row in current['proxies']],
                         [(row['id'], row['ipv6'], row['port']) for row in self.engine.config['proxies']])
        self.assertTrue(self.engine.running)
        self.assertLess(self.names().index('commit'), self.names().index('remove'))

    def test_recreate_removes_old_pool_across_interfaces_and_protocols(self):
        self.generate(count=2, protocol='dual')
        self.generate(count=1, interface='eth1', subnet='2606:4700:2::')
        original = self.store.read()
        old_keys = {address_key(row) for row in original['managed_addresses']}
        self.events.clear()
        result = self.generate(count=1, recreate=True, protocol='socks5')
        current = self.store.read()
        self.assertEqual(result['total'], 1)
        self.assertEqual(len(current['proxies']), 1)
        self.assertEqual(current['proxies'][0]['protocol'], 'socks5')
        self.assertNotIn('socks_port', current['proxies'][0])
        self.assertFalse(old_keys & set(self.net.aliases))
        removed = {address_key({'address': address, 'interface': event[1], 'prefix_len': event[2]})
                   for event in self.events if event[0] == 'remove' for address in event[3]}
        self.assertEqual(removed, old_keys)

    def test_explicit_append_preserves_existing_pool(self):
        self.generate(count=2)
        original = copy.deepcopy(self.store.read()['proxies'])
        result = self.generate(count=1, recreate=False)
        current = self.store.read()
        self.assertEqual(result['total'], 3)
        self.assertEqual(current['proxies'][:2], original)
        self.assertEqual([row['port'] for row in current['proxies']], [10000, 10001, 10002])
        self.assertEqual(len(current['managed_addresses']), 3)

    def test_failed_recreate_keeps_verified_previous_pool_and_cleans_new_aliases(self):
        self.generate(count=2)
        original = copy.deepcopy(self.store.read())
        config = copy.deepcopy(self.engine.config)
        self.net.failure = 'probe'
        with self.assertRaises(OperationError):
            self.generate(count=3, recreate=True)
        current = self.store.read()
        self.assertEqual(current['proxies'], original['proxies'])
        self.assertEqual(current['managed_addresses'], original['managed_addresses'])
        self.assertEqual(self.engine.config, config)
        self.assertTrue(self.engine.running)
        self.assertEqual(set(self.net.aliases), {address_key(row) for row in original['managed_addresses']})
        self.assertIsNone(current['pending_operation'])

    def test_failed_retired_alias_cleanup_is_reported_then_retry_removes_it(self):
        self.generate(count=2)
        old = copy.deepcopy(self.store.read()['managed_addresses'])
        blocked = address_key(old[0])
        self.net.failed_remove.add(blocked)
        result = self.generate(count=3, recreate=True)
        current = self.store.read()
        self.assertEqual((result['total'], len(current['proxies']), result['cleanup_pending']), (3, 3, 1))
        self.assertFalse({row['address'] for row in old} & {row['ipv6'] for row in current['proxies']})
        self.assertEqual(len(current['managed_addresses']), 4)
        retired = next(row for row in current['managed_addresses'] if address_key(row) == blocked)
        self.assertFalse(retired['active'])
        self.net.failed_remove.clear()
        self.service.reconcile()
        current = self.store.read()
        self.assertEqual(len(current['managed_addresses']), 3)
        self.assertNotIn(blocked, self.net.aliases)
        self.assertTrue(self.engine.running)


if __name__ == '__main__':
    unittest.main()
