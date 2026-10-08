"""Boot/renumber source selection is read-only and all networking is mocked."""
import unittest
from unittest.mock import patch

import ipv6_manager as manager


OLD = '2606:4700:1::1'
NEW = '2606:4700:2::1'
ALIAS = '2606:4700:2::99'


def address(value, **changes):
    result = {'address': value, 'interface': 'eth0', 'prefix_len': 64,
              'scope': 'global', 'flags': [], 'valid_lft': 86400,
              'preferred_lft': 3600, 'ready': True}
    result.update(changes)
    return result


def routes(*networks):
    return [{'dst': 'default', 'gateway': 'fe80::1', 'dev': 'eth0'},
            *[{'dst': network, 'dev': 'eth0'} for network in networks]]


def probe_result(value, successful=True):
    return {'success': successful, 'observed_address': value if successful else None,
            'error': None if successful else 'IPv6 egress probe failed'}


class RebootSelectionTests(unittest.TestCase):
    def select(self, addresses, route_rows=None, probe=None, **options):
        with patch.object(manager, 'get_ipv6_addresses', return_value=addresses), \
                patch.object(manager, 'get_ipv6_routes', return_value=route_rows or routes(
                    '2606:4700:1::/64', '2606:4700:2::/64')), \
                patch.object(manager, 'probe_ipv6_egress', side_effect=probe or (
                    lambda value, *args, **kwargs: probe_result(value))) as mock_probe, \
                patch.object(manager, 'remove_ipv6_from_interface') as remove, \
                patch.object(manager, 'add_ipv6_to_interface') as add:
            result = manager.select_current_lan_prefix('eth0', **options)
            remove.assert_not_called()
            add.assert_not_called()
        return result, mock_probe

    def test_old_and_new_addresses_select_new_when_old_source_fails(self):
        result, probe = self.select([address(OLD), address(NEW)],
            probe=lambda value, *args, **kwargs: probe_result(value, value == NEW))
        self.assertEqual(result, {'address': NEW, 'interface': 'eth0',
                                 'subnet': '2606:4700:2::', 'full': '2606:4700:2::/64', 'prefix_len': 64,
                                 'address_prefix_len': 64, 'verified': True})
        self.assertEqual([call.args[0] for call in probe.call_args_list], [OLD, NEW])
        for call in probe.call_args_list:
            self.assertEqual(call.kwargs['expected_address'], call.args[0])
            self.assertEqual(call.kwargs['timeout'], 5)

    def test_longer_preferred_lifetime_prioritizes_fresh_prefix(self):
        result, probe = self.select([address(OLD, preferred_lft=20),
                                     address(NEW, preferred_lft=7200)])
        self.assertEqual(result['address'], NEW)
        probe.assert_called_once()

    def test_none_means_unlimited_lifetime_not_expired(self):
        result, _ = self.select([address(OLD, preferred_lft=20),
                                address(NEW, preferred_lft=None, valid_lft=None)])
        self.assertEqual(result['address'], NEW)

    def test_deprecated_tentative_dadfailed_and_expired_are_not_probed(self):
        records = [address(OLD, flags=[flag]) for flag in ('tentative', 'dadfailed', 'deprecated')]
        records += [address(OLD, valid_lft=0), address(OLD, preferred_lft=0),
                    address(OLD, ready=False), address(NEW)]
        result, probe = self.select(records)
        self.assertEqual(result['address'], NEW)
        probe.assert_called_once()

    def test_managed_alias_excluded_even_when_prefix_or_text_differs(self):
        result, probe = self.select([address(ALIAS, preferred_lft=None), address(NEW)],
            managed_addresses=[{'address': '2606:4700:0002:0:0:0:0:99',
                                'interface': 'eth0', 'prefix_len': 128}])
        self.assertEqual(result['address'], NEW)
        probe.assert_called_once()

    def test_same_address_on_other_interface_is_not_owned_here(self):
        result, _ = self.select([address(NEW)],
            managed_addresses=[{'address': NEW, 'interface': 'eth1', 'prefix_len': 128}])
        self.assertEqual(result['address'], NEW)

    def test_ula_linklocal_documentation_multicast_are_ignored(self):
        records = [address(value) for value in ('fd00::1', 'fe80::1', '2001:db8::1', 'ff02::1')]
        records += [address(NEW)]
        result, probe = self.select(records)
        self.assertEqual(result['address'], NEW)
        probe.assert_called_once()

    def test_dhcpv6_host_128_derives_pool_from_current_onlink_route(self):
        result, _ = self.select([address(NEW, prefix_len=128)])
        self.assertEqual(result['subnet'], '2606:4700:2::')
        self.assertEqual(result['full'], '2606:4700:2::/64')
        self.assertEqual(result['prefix_len'], 64)
        self.assertEqual(result['address_prefix_len'], 128)

    def test_narrower_host_prefix_retains_pool_not_entire_covering_lan(self):
        result, _ = self.select([address(NEW, prefix_len=80)])
        self.assertEqual(result['subnet'], '2606:4700:2::')
        self.assertEqual(result['full'], '2606:4700:2::/80')
        self.assertEqual(result['prefix_len'], 80)

    def test_no_default_route_prevents_probe(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address(NEW)]), \
                patch.object(manager, 'get_ipv6_routes', return_value=[{'dst': '2606:4700:2::/64'}]), \
                patch.object(manager, 'probe_ipv6_egress') as probe:
            with self.assertRaisesRegex(RuntimeError, 'default route'):
                manager.select_current_lan_prefix('eth0')
        probe.assert_not_called()

    def test_expired_linkdown_nonunicast_and_other_interface_routes_are_unusable(self):
        for change in ({'expires': 0}, {'flags': ['linkdown']}, {'type': 'unreachable'}, {'dev': 'eth1'}):
            row = {'dst': 'default', 'gateway': 'fe80::1', 'dev': 'eth0', **change}
            with self.subTest(change=change), \
                    patch.object(manager, 'get_ipv6_addresses', return_value=[address(NEW)]), \
                    patch.object(manager, 'get_ipv6_routes', return_value=[row, {'dst': '2606:4700:2::/64'}]), \
                    patch.object(manager, 'probe_ipv6_egress') as probe:
                with self.assertRaisesRegex(RuntimeError, 'default route'):
                    manager.select_current_lan_prefix('eth0')
                probe.assert_not_called()

    def test_no_current_onlink_route_prevents_probe(self):
        for row in ({'dst': '2606:4700:2::/64', 'gateway': 'fe80::1'},
                    {'dst': '2606:4700:2::/64', 'expires': 0},
                    {'dst': '2606:4700:2::/64', 'flags': ['linkdown']},
                    {'dst': '2606:4700:2::/48'}):
            with self.subTest(route=row), \
                    patch.object(manager, 'get_ipv6_addresses', return_value=[address(NEW)]), \
                    patch.object(manager, 'get_ipv6_routes', return_value=[
                        {'dst': 'default', 'gateway': 'fe80::1'}, row]), \
                    patch.object(manager, 'probe_ipv6_egress') as probe:
                with self.assertRaisesRegex(RuntimeError, 'on-link LAN prefix'):
                    manager.select_current_lan_prefix('eth0')
                probe.assert_not_called()

    def test_success_with_wrong_observed_source_is_not_accepted(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address(NEW)]), \
                patch.object(manager, 'get_ipv6_routes', return_value=routes('2606:4700:2::/64')), \
                patch.object(manager, 'probe_ipv6_egress', return_value=probe_result(OLD)):
            with self.assertRaisesRegex(RuntimeError, 'verified Internet egress'):
                manager.select_current_lan_prefix('eth0')

    def test_candidate_disappears_during_probe_uses_next_source(self):
        with patch.object(manager, 'get_ipv6_addresses', side_effect=[
                    [address(OLD), address(NEW)], [address(NEW)], [address(NEW)]]), \
                patch.object(manager, 'get_ipv6_routes', return_value=routes(
                    '2606:4700:1::/64', '2606:4700:2::/64')), \
                patch.object(manager, 'probe_ipv6_egress', side_effect=(
                    lambda value, *args, **kwargs: probe_result(value))) as probe:
            result = manager.select_current_lan_prefix('eth0')
        self.assertEqual(result['address'], NEW)
        self.assertEqual(probe.call_count, 2)

    def test_all_failed_sources_leave_every_base_address_untouched(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address(OLD), address(NEW)]), \
                patch.object(manager, 'get_ipv6_routes', return_value=routes(
                    '2606:4700:1::/64', '2606:4700:2::/64')), \
                patch.object(manager, 'probe_ipv6_egress', return_value=probe_result(NEW, False)), \
                patch.object(manager, 'remove_ipv6_from_interface') as remove:
            with self.assertRaisesRegex(RuntimeError, 'verified Internet egress'):
                manager.select_current_lan_prefix('eth0')
        remove.assert_not_called()

    def test_checkpoint_cancels_before_network_probe_and_is_not_swallowed(self):
        calls = []
        def checkpoint():
            calls.append(True)
            if len(calls) == 3:
                raise RuntimeError('Stop requested')
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address(NEW)]), \
                patch.object(manager, 'get_ipv6_routes', return_value=routes('2606:4700:2::/64')), \
                patch.object(manager, 'probe_ipv6_egress') as probe:
            with self.assertRaisesRegex(RuntimeError, 'Stop requested'):
                manager.select_current_lan_prefix('eth0', checkpoint=checkpoint)
        probe.assert_not_called()

    def test_same_prefix_privacy_source_falls_back_when_stable_source_fails(self):
        privacy = '2606:4700:2::2'
        result, probe = self.select([address(NEW), address(privacy, flags=['temporary'])],
            probe=lambda value, *args, **kwargs: probe_result(value, value == privacy))
        self.assertEqual(result['address'], privacy)
        self.assertEqual(probe.call_count, 2)

    def test_router_preferred_source_is_a_candidate_not_unconditional_success(self):
        route_rows = routes('2606:4700:1::/64', '2606:4700:2::/64')
        route_rows[0]['prefsrc'] = OLD
        result, probe = self.select([address(OLD), address(NEW)], route_rows,
            probe=lambda value, *args, **kwargs: probe_result(value, value == NEW))
        self.assertEqual(result['address'], NEW)
        self.assertEqual(probe.call_count, 2)

    def test_current_working_prefix_prevents_churn_from_lifetime_changes(self):
        result, probe = self.select([address(OLD, preferred_lft=20),
                                     address(NEW, preferred_lft=7200)],
                                    prefer_networks={'2606:4700:0001::99/64'})
        self.assertEqual(result['address'], OLD)
        probe.assert_called_once()

    def test_preferred_current_prefix_still_fails_over_when_old_source_is_broken(self):
        result, probe = self.select([address(OLD), address(NEW)],
            prefer_networks={'2606:4700:1::/64'},
            probe=lambda value, *args, **kwargs: probe_result(value, value == NEW))
        self.assertEqual(result['address'], NEW)
        self.assertEqual(probe.call_count, 2)

    def test_router_preferred_source_ranks_above_configured_working_prefix(self):
        route_rows = routes('2606:4700:1::/64', '2606:4700:2::/64')
        route_rows[0]['prefsrc'] = NEW
        result, probe = self.select([address(OLD), address(NEW)], route_rows,
                                   prefer_networks={'2606:4700:1::/64'})
        self.assertEqual(result['address'], NEW)
        probe.assert_called_once()

    def test_narrower_configured_pool_prefers_its_covering_lan_source(self):
        result, probe = self.select([address(OLD, preferred_lft=20),
                                     address(NEW, preferred_lft=7200)],
                                    prefer_networks={'2606:4700:1::/80'})
        self.assertEqual(result['address'], OLD)
        probe.assert_called_once()


if __name__ == '__main__':
    unittest.main()
