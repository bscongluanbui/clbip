"""Prefix debounce/inventory integration; fake kernel/engine and real SQLite."""
import copy
import unittest
from unittest.mock import patch

import test_service as fixtures
from service import OperationError


NEW = '2606:4700:3::'


class SourceUpgradeTests(unittest.TestCase):
    setUp = fixtures.ServiceTests.setUp
    tearDown = fixtures.ServiceTests.tearDown
    generate = fixtures.ServiceTests.generate
    names = fixtures.ServiceTests.names

    def tick(self):
        self.service.last_base_probe = 0
        self.service.reconcile()

    def change_source(self, prefix=NEW):
        self.net.system[0]['address'] = prefix + '1'

    def test_two_confirmations_stop_old_pool_and_do_not_restore_until_confirmed(self):
        self.generate(count=2)
        before = copy.deepcopy(self.store.read()['proxies'])
        self.change_source()
        self.events.clear()
        self.tick()
        self.assertFalse(self.engine.running)
        self.assertEqual(self.store.read()['proxies'], before)
        self.assertNotIn('restore', self.names())
        self.assertNotIn('add', self.names())
        self.events.clear()
        self.service.reconcile()  # Inside polling interval: no premature restart.
        self.assertNotIn('restore', self.names())
        self.assertFalse(self.engine.running)
        self.tick()
        self.assertTrue(self.engine.running)
        self.assertTrue(all(p['subnet'] == NEW for p in self.store.read()['proxies']))
        self.assertEqual(self.service.source_candidates, {})

    def test_flapping_prefix_resets_confirmation_and_old_valid_pool_can_resume(self):
        self.generate()
        original = copy.deepcopy(self.store.read()['proxies'])
        self.change_source()
        self.tick()
        self.change_source(fixtures.POOL)
        self.tick()
        self.assertTrue(self.engine.running)
        self.assertEqual(self.store.read()['proxies'], original)
        self.assertEqual(self.service.source_candidates, {})
        self.change_source()
        self.tick()
        self.assertFalse(self.engine.running)
        self.assertEqual(self.store.read()['proxies'], original)

    def test_same_prefix_slaac_change_does_not_rebuild(self):
        self.generate()
        original = copy.deepcopy(self.store.read()['proxies'])
        self.net.system[0]['address'] = fixtures.POOL + '2'
        self.events.clear()
        self.tick()
        self.assertTrue(self.engine.running)
        self.assertEqual(self.store.read()['proxies'], original)
        self.assertNotIn('add', self.names())
        self.assertNotIn('remove', self.names())

    def test_configured_single_confirmation_retains_immediate_failover(self):
        self.generate()
        state = self.store.read()
        state['settings']['source_change_confirmations'] = 1
        self.store.write(state)
        self.change_source()
        self.tick()
        self.assertTrue(self.engine.running)
        self.assertEqual(self.store.read()['settings']['subnet'], NEW)

    def test_failed_observation_breaks_consecutive_confirmation(self):
        self.generate()
        self.change_source()
        self.tick()
        with patch.object(self.net, 'select_current_lan_prefix', side_effect=RuntimeError('fixture no route')):
            with self.assertRaises(RuntimeError):
                self.tick()
        self.assertEqual(self.service.source_candidates, {})
        self.tick()
        self.assertFalse(self.engine.running)
        self.assertNotEqual(self.store.read()['settings']['subnet'], NEW)

    def test_manual_stop_is_not_overridden_during_confirmation(self):
        self.generate()
        self.change_source()
        self.tick()
        self.service.dispatch('stop', {})
        self.tick()
        self.assertFalse(self.engine.running)
        self.assertTrue(self.store.read()['manual_stop'])
        self.assertNotEqual(self.store.read()['settings']['subnet'], NEW)
        self.service.dispatch('save_settings', {'max_connections': 64})
        self.assertFalse(self.engine.running)

    def test_failed_replacement_keeps_invalid_old_pool_stopped_and_retries(self):
        self.generate()
        self.change_source()
        self.tick()
        original = self.net.probe_ipv6_egress
        def probe(address, iface, **kwargs):
            if address != NEW + '1':
                return {'success': False}
            return original(address, iface, **kwargs)
        with patch.object(self.net, 'probe_ipv6_egress', side_effect=probe):
            with self.assertRaises(OperationError):
                self.tick()
        self.assertFalse(self.engine.running)
        self.service.reconcile()
        self.assertFalse(self.engine.running)
        self.tick()
        self.assertTrue(self.engine.running)
        self.assertEqual(self.store.read()['settings']['subnet'], NEW)

    def test_removed_lan_candidate_does_not_block_remaining_routed_pool(self):
        self.generate()
        self.generate(interface='eth1', subnet='2606:4700:2::', topology_mode='routed', routed_prefix='2606:4700:2::/48')
        self.change_source()
        self.tick()
        lan = next(p for p in self.store.read()['proxies'] if p['interface'] == 'eth0')
        self.service.dispatch('delete', {'proxy_id': lan['id']})
        self.engine.running = False
        self.tick()
        self.assertEqual(self.service.source_candidates, {})
        self.assertTrue(self.engine.running)
        self.assertEqual({p['interface'] for p in self.store.read()['proxies']}, {'eth1'})

    def test_interface_snapshot_and_export_choose_source_ipv4(self):
        self.generate()
        state = self.store.read()
        state['settings']['listener_ipv4'] = '0.0.0.0'
        self.store.write(state)
        details = [{'device': 'eth0', 'name': 'Ethernet', 'active': True, 'kind': 'Ethernet',
                    'ipv4': ['192.168.1.3'], 'ipv6': copy.deepcopy(self.net.system)},
                   {'device': 'tailscale0', 'name': 'Tailscale', 'active': True, 'kind': 'Tailscale',
                    'ipv4': ['100.64.1.2'], 'ipv6': []}]
        with patch.object(self.net, 'get_interface_inventory', return_value=details, create=True):
            response = self.service.dispatch('interfaces', {})
            self.assertEqual(response['interfaces'], ['eth0', 'tailscale0'])
            self.assertTrue(response['details'][0]['pool_capable'])
            self.assertEqual(self.service.status({})['dashboard_hosts'], ['192.168.1.3', '100.64.1.2'])
            self.assertIn('192.168.1.3:', self.service.export({})['content'])
        with patch.object(self.net, 'get_interface_inventory', side_effect=RuntimeError('fixture read fail'), create=True):
            self.service.interfaces({})
        self.assertEqual(self.service.status({})['dashboard_hosts'], [])
        self.assertIsNone(self.service.status({})['current_source'])

    def test_dhcpv6_host_128_subnet_suggestion_uses_onlink_pool(self):
        self.net.system[0]['prefix_len'] = 128
        route = [{'dst': fixtures.POOL + '/64', 'dev': 'eth0', 'type': 'unicast'}]
        with patch.object(self.net, 'get_ipv6_routes', return_value=route):
            rows = self.service.subnets({'interface': 'eth0'})['subnets']
        self.assertEqual(rows[0]['prefix_len'], 64)
        self.assertEqual(rows[0]['subnet'], fixtures.POOL)
        with patch.object(self.net, 'get_ipv6_routes', return_value=[]):
            self.assertEqual(self.service.subnets({'interface': 'eth0'})['subnets'], [])

    def test_selected_interface_never_claims_other_interface_cached_source(self):
        self.generate()
        self.tick()
        self.service.interfaces({})
        self.assertTrue(self.service.status({})['source_verified'])
        self.generate(interface='eth1', subnet='2606:4700:2::')
        status = self.service.status({})
        self.assertEqual(status['interface'], 'eth1')
        self.assertIsNone(status['current_source'])
        self.assertFalse(status['source_verified'])
