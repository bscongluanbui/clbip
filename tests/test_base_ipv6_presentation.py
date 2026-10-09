"""Passive source/pool separation; fake interfaces and isolated SQLite only."""
import copy
import ipaddress
import unittest

import test_service as fixtures


class BaseIPv6PresentationTests(unittest.TestCase):
    setUp = fixtures.ServiceTests.setUp
    tearDown = fixtures.ServiceTests.tearDown
    names = fixtures.ServiceTests.names
    generate = fixtures.ServiceTests.generate

    def add_record(self, address, prefix=64, iface='eth0', **changes):
        record = {**self.net.system[0], 'address': address, 'prefix_len': prefix,
                  'interface': iface, **changes}
        self.net.system.append(record)
        return record

    def test_100_proxy_aliases_do_not_leak_into_base_or_subnet_sources(self):
        self.generate(count=100)
        state, aliases = self.store.read(), copy.deepcopy(self.net.aliases)
        row = self.service.interfaces({})['details'][0]
        self.assertEqual(len(row['ipv6']), 101)
        self.assertEqual(row['managed_ipv6_count'], 100)
        self.assertEqual(row['uncertain_ipv6_count'], 0)
        self.assertEqual([r['address'] for r in row['source_ipv6']], [fixtures.POOL + '1'])
        self.assertEqual(self.service._source_snapshot(state)['current_source']['address'], fixtures.POOL + '1')
        subnets = self.service.subnets({'interface': 'eth0'})['subnets']
        self.assertEqual([r['source_address'] for r in subnets], [fixtures.POOL + '1'])
        records = self.service.addresses({'interface': 'eth0'})['addresses']
        self.assertEqual(len(records), 101)
        self.assertEqual(sum(r['origin'] == 'managed' for r in records), 100)
        self.assertEqual(self.store.read(), state)
        self.assertEqual(self.net.aliases, aliases)

    def test_uncertain_and_inflight_aliases_are_excluded_with_canonical_keys(self):
        first = self.add_record(fixtures.POOL + '2')
        second = self.add_record(fixtures.POOL + '3')
        state = self.store.read()
        state['uncertain_addresses'] = [{**first, 'address': ipaddress.IPv6Address(first['address']).exploded,
                                         'operation_id': 'fixture'}]
        state['pending_operation'] = {'id': 'pending-fixture', 'added': [],
                                      'staged': [{**second, 'creation': 'attempting'}]}
        self.store.write(state)
        before = self.store.read()
        row = self.service.interfaces({})['details'][0]
        self.assertEqual(row['uncertain_ipv6_count'], 2)
        self.assertEqual(row['managed_ipv6_count'], 0)
        self.assertEqual([r['address'] for r in row['source_ipv6']], [fixtures.POOL + '1'])
        self.assertEqual(self.service.subnets({'interface': 'eth0'})['subnets'][0]['source_address'], fixtures.POOL + '1')
        self.assertEqual([r['origin'] for r in self.service.addresses({})['addresses']], ['system', 'uncertain', 'uncertain'])
        self.assertEqual(self.store.read(), before)

    def test_verified_system_address_is_preserved_within_shared_prefix(self):
        selected = self.add_record(fixtures.POOL + '2')
        self.add_record(fixtures.POOL + '3', flags=['temporary'])
        state = self.store.read()
        state['prefix_state']['eth0'] = {**selected, 'address': ipaddress.IPv6Address(selected['address']).exploded,
                                        'verified': True}
        self.store.write(state)
        self.service.interfaces({})
        view = self.service._source_snapshot(self.store.read())
        self.assertTrue(view['source_verified'])
        self.assertEqual(view['current_source']['address'], selected['address'])
        rows = self.service.subnets({'interface': 'eth0'})['subnets']
        self.assertEqual(len(rows), 1)
        self.assertTrue(rows[0]['verified'])
        self.assertEqual(rows[0]['source_address'], selected['address'])

    def test_deprecated_dadfailed_and_zero_lifetime_subnets_are_not_candidates(self):
        original = copy.deepcopy(self.net.system[0])
        for changes in ({'flags': ['deprecated']}, {'flags': ['dadfailed']},
                        {'flags': ['tentative']}, {'valid_lft': 0}, {'preferred_lft': 0}):
            with self.subTest(changes=changes):
                self.net.system = [{**original, **changes}]
                row = self.service.interfaces({})['details'][0]
                self.assertEqual(len(row['system_ipv6']), 1)
                self.assertEqual(row['source_ipv6'], [])
                self.assertEqual(self.service.subnets({'interface': 'eth0'})['subnets'], [])

    def test_malformed_previous_verified_address_does_not_erase_inventory(self):
        state = self.store.read()
        state['prefix_state']['eth0'] = {'address': 'bad', 'verified': True}
        self.store.write(state)
        self.assertEqual(self.service.interfaces({})['details'][0]['source_ipv6'][0]['address'], fixtures.POOL + '1')
        self.assertFalse(self.service._source_snapshot(state)['source_verified'])
        self.assertFalse(self.service.subnets({'interface': 'eth0'})['subnets'][0]['verified'])
