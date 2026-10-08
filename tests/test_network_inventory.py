"""Read-only inventory and connection-limit regressions; no real network calls."""
import copy
import unittest
from unittest.mock import Mock, patch

import ipv6_manager as network
import network_inventory as inventory
import proxy_config
from validation import DEFAULT_SETTINGS, ValidationError, settings_patch


IP = '2606:4700:1::1'


def snapshot():
    return [{'ifname': 'eth0', 'flags': ['UP', 'LOWER_UP'], 'operstate': 'UP',
        'addr_info': [{'family': 'inet', 'local': '192.168.1.3', 'prefixlen': 24},
                      {'family': 'inet6', 'local': IP, 'prefixlen': 64, 'scope': 'global',
                       'valid_life_time': 900, 'preferred_life_time': 800}]},
        {'ifname': 'tailscale0', 'flags': ['UP', 'LOWER_UP'], 'operstate': 'UNKNOWN',
         'linkinfo': {'info_kind': 'tun'}, 'addr_info': [{'family': 'inet', 'local': '100.64.1.2', 'prefixlen': 32}]},
        {'ifname': 'eth1', 'flags': [], 'operstate': 'DOWN', 'addr_info': []}]


class Backend:
    def get_interface_inventory(self):
        return network.get_interface_inventory()


class InventoryTests(unittest.TestCase):
    def setUp(self):
        self.data = snapshot()
        self.mock = patch.object(network, '_json_snapshot', return_value=self.data).start()
        self.addCleanup(patch.stopall)

    def test_one_passive_snapshot_and_real_hosts(self):
        rows = inventory.collect(Backend())
        self.mock.assert_called_once_with(['ip', '-j', '-d', 'address', 'show'])
        self.assertTrue(rows[0]['pool_capable'])
        self.assertEqual(rows[1]['kind'], 'Tailscale')
        self.assertFalse(rows[1]['pool_capable'])
        self.assertFalse(rows[2]['active'])
        self.assertEqual(inventory.hosts(rows), ['192.168.1.3', '100.64.1.2'])

    def test_owned_and_deprecated_sources_are_not_candidates(self):
        rows = inventory.collect(Backend(), [{'address': IP, 'interface': 'eth0'}])
        self.assertFalse(rows[0]['pool_capable'])
        self.data[0]['addr_info'][1]['deprecated'] = True
        self.assertIsNone(inventory.observed_source(inventory.collect(Backend()), 'eth0'))

    def test_observation_is_not_an_egress_claim(self):
        rows = inventory.collect(Backend())
        source = inventory.observed_source(rows, 'eth0')
        self.assertEqual(source['address'], IP)
        self.assertEqual(source['subnet'], '2606:4700:1::')
        self.assertNotIn('verified', source)
        self.assertIsNone(inventory.observed_source(rows, 'eth1'))

    def test_stable_source_precedes_temporary(self):
        temporary = copy.deepcopy(self.data[0]['addr_info'][1])
        temporary.update(local='2606:4700:1::0', temporary=True)
        self.data[0]['addr_info'].append(temporary)
        self.assertEqual(inventory.observed_source(inventory.collect(Backend()), 'eth0')['address'], IP)

    def test_export_uses_source_not_unrelated_tailscale(self):
        rows = inventory.collect(Backend())
        self.assertEqual(inventory.export_host('0.0.0.0', rows, 'eth0'), '192.168.1.3')
        self.assertEqual(inventory.export_host('127.0.0.1', rows, 'eth0'), '127.0.0.1')
        with self.assertRaises(ValueError):
            inventory.export_host('0.0.0.0', rows, 'eth1')

    def test_unusable_hosts_are_filtered(self):
        for value in ('0.0.0.0', '127.0.0.1', '224.1.2.3', '::1', 'bad'):
            self.assertIsNone(inventory.usable_ipv4(value))

    def test_expired_and_host_only_prefix_fail_pool_capability(self):
        for changes in ({'preferred_life_time': 0}, {'valid_life_time': 0}, {'prefixlen': 128}, {'local': 'fd00::1'}):
            with self.subTest(changes=changes):
                self.mock.return_value = snapshot()
                self.mock.return_value[0]['addr_info'][1].update(changes)
                self.assertFalse(inventory.collect(Backend())[0]['pool_capable'])

    def test_preferred_verified_source_wins_over_stale_lexicographic_candidate(self):
        new = copy.deepcopy(self.data[0]['addr_info'][1])
        new['local'] = '2606:4700:1::2'
        self.data[0]['addr_info'].append(new)
        rows = inventory.collect(Backend())
        selected = {'address': new['local'], 'interface': 'eth0', 'verified': True}
        self.assertEqual(inventory.observed_source(rows, 'eth0', preferred=selected)['address'], new['local'])
        for previous in ({**selected, 'verified': False}, {**selected, 'interface': 'eth1'},
                         {**selected, 'address': 'bad'}, {'address': new['local']}):
            with self.subTest(previous=previous):
                self.assertEqual(inventory.observed_source(rows, 'eth0', preferred=previous)['address'], IP)

    def test_preferred_source_must_still_be_eligible_and_outside_owned_aliases(self):
        new = copy.deepcopy(self.data[0]['addr_info'][1])
        new['local'] = '2606:4700:1::2'
        self.data[0]['addr_info'].append(new)
        selected = {'address': IP, 'interface': 'eth0', 'verified': True}
        for field in ('deprecated', 'dadfailed', 'tentative'):
            with self.subTest(field=field):
                self.data[0]['addr_info'][1][field] = True
                self.assertEqual(inventory.observed_source(inventory.collect(Backend()), 'eth0', preferred=selected)['address'], new['local'])
                self.data[0]['addr_info'][1].pop(field)
        managed = [{'address': IP, 'interface': 'eth0'}]
        self.assertEqual(inventory.observed_source(inventory.collect(Backend(), managed), 'eth0', managed,
                                                  preferred=selected)['address'], new['local'])

    def test_dhcp_host_source_infers_most_specific_current_onlink_pool(self):
        self.data[0]['addr_info'][1]['prefixlen'] = 128
        backend = Backend()
        backend.get_ipv6_routes = Mock(return_value=[
            {'dev': 'eth0', 'dst': 'default', 'gateway': 'fe80::1'},
            {'dev': 'eth0', 'dst': '2606:4700:1::/64'},
            {'dev': 'eth0', 'dst': '2606:4700:1::/96'}])
        rows = inventory.collect(backend)
        backend.get_ipv6_routes.assert_called_once_with(strict=True)
        self.assertTrue(rows[0]['pool_capable'])
        self.assertEqual(rows[0]['ipv6'][0]['prefix_len'], 128)
        self.assertEqual(rows[0]['ipv6'][0]['pool_prefix_len'], 96)
        source = inventory.observed_source(rows, 'eth0')
        self.assertEqual(source['address_prefix_len'], 128)
        self.assertEqual(source['prefix_len'], 96)
        self.assertEqual(source['subnet'], '2606:4700:1::')
        self.assertNotIn('verified', source)
        # The raw kernel fixture and backend-owned data are not annotated.
        self.assertNotIn('pool_prefix_len', self.data[0]['addr_info'][1])

    def test_dhcp_host_requires_unexpired_global_covering_onlink_route_on_same_interface(self):
        self.data[0]['addr_info'][1]['prefixlen'] = 128
        valid = {'dev': 'eth0', 'dst': '2606:4700:1::/64'}
        invalid = [{**valid, 'dev': 'eth1'}, {**valid, 'gateway': 'fe80::1'},
                   {**valid, 'expires': 0}, {**valid, 'flags': ['linkdown']},
                   {**valid, 'type': 'blackhole'}, {**valid, 'dst': '2606:4700:1::/128'},
                   {**valid, 'dst': '2606:4700:1::/63'}, {**valid, 'dst': '2606:4700:2::/64'},
                   {**valid, 'dst': 'fd00::/64'}, {**valid, 'dst': 'ff00::/64'},
                   {**valid, 'dst': 'default'}, {**valid, 'dst': 'bad'}, {}]
        for route in invalid:
            with self.subTest(route=route):
                backend = Backend()
                backend.get_ipv6_routes = Mock(return_value=[route])
                rows = inventory.collect(backend)
                self.assertFalse(rows[0]['pool_capable'])
                self.assertIsNone(inventory.observed_source(rows, 'eth0'))

    def test_route_snapshot_is_once_for_multiple_dhcp_sources_and_never_for_managed_aliases(self):
        self.data[0]['addr_info'][1]['prefixlen'] = 128
        second = copy.deepcopy(self.data[0]['addr_info'][1])
        second['local'] = '2606:4700:1::2'
        self.data[0]['addr_info'].append(second)
        backend = Backend()
        backend.get_ipv6_routes = Mock(return_value=[{'dev': 'eth0', 'dst': '2606:4700:1::/64'}])
        inventory.collect(backend)
        backend.get_ipv6_routes.assert_called_once_with(strict=True)
        backend.get_ipv6_routes.reset_mock()
        managed = [{'address': row['local'], 'interface': 'eth0'} for row in self.data[0]['addr_info'] if row['family'] == 'inet6']
        self.assertFalse(inventory.collect(backend, managed)[0]['pool_capable'])
        backend.get_ipv6_routes.assert_not_called()
        self.data = snapshot()
        self.mock.return_value = self.data
        inventory.collect(backend)
        backend.get_ipv6_routes.assert_not_called()

    def test_route_failure_does_not_lose_ipv4_inventory_or_claim_a_dhcp_pool(self):
        self.data[0]['addr_info'][1]['prefixlen'] = 128
        backend = Backend()
        backend.get_ipv6_routes = Mock(side_effect=RuntimeError('fixture unavailable'))
        rows = inventory.collect(backend)
        self.assertFalse(rows[0]['pool_capable'])
        self.assertEqual(inventory.hosts(rows), ['192.168.1.3', '100.64.1.2'])


class LimitsTests(unittest.TestCase):
    def test_new_settings_and_config_emit_maxconn_64(self):
        self.assertEqual(DEFAULT_SETTINGS['max_connections'], 64)
        config = proxy_config._generate_single_config(
            [{'ipv6': '2606:4700:1::10', 'port': 10000, 'protocol': 'http'}],
            [{'username': 'tester', 'password': 'Test_42!'}],
            {'auth_type': 'userpass', 'log_enabled': False})
        self.assertIn('maxconn 64', config)

    def test_saved_limits_remain_configurable_and_debounce_typed(self):
        self.assertEqual(settings_patch({'max_connections': 64}, DEFAULT_SETTINGS)['max_connections'], 64)
        for name, bad in [('source_change_confirmations', 0), ('source_change_confirmations', True),
                          ('source_poll_interval', 1), ('source_poll_interval', 3.5)]:
            with self.subTest(name=name, bad=bad), self.assertRaises(ValidationError):
                settings_patch({name: bad})
