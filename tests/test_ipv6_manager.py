"""Unit tests use only mocks: no kernel changes, curl, or DNS traffic."""
import ipaddress
import json
import socket
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import ipv6_manager as manager


def address(value='2001:db8::1', interface='eth0', prefix_len=128, **changes):
    record = {'address': value, 'interface': interface, 'prefix_len': prefix_len,
              'scope': 'global', 'flags': [], 'valid_lft': None,
              'preferred_lft': None, 'ready': True}
    record.update(changes)
    return record


def response(stdout='', returncode=0, stderr=''):
    return SimpleNamespace(stdout=stdout, returncode=returncode, stderr=stderr)


def creation(value='2001:db8::2', *, success=True, created=True):
    return [{'address': value, 'interface': 'eth0', 'prefix_len': 128,
             'success': success, 'created': created, 'existing': created is False, 'error': ''}]


class ValidationAndGeneratorTests(unittest.TestCase):
    def test_canonical_address(self):
        self.assertEqual(manager.normalize_ipv6('2001:0DB8:0000::1'), '2001:db8::1')

    def test_reject_argument_injection(self):
        for value in ['eth0 up', 'eth0\nflush', '-all', 'x' * 16, 'eth0;reboot', None]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                manager.validate_interface(value)
        for value in ['::1/64', 'fe80::1%eth0', '::1 dev eth0', '1.2.3.4']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                manager.normalize_ipv6(value)

    def test_generator_exact_unique_in_pool(self):
        generated = manager.generate_random_ipv6('2001:db8::', 64, 500)
        self.assertEqual(len(generated), 500)
        self.assertEqual(len(set(generated)), 500)
        self.assertTrue(all(ipaddress.IPv6Address(a) in ipaddress.IPv6Network('2001:db8::/64') for a in generated))

    def test_small_pool_insufficient_capacity(self):
        with self.assertRaisesRegex(ValueError, 'only 1'):
            manager.generate_random_ipv6('2001:db8::', 127, 2)

    def test_host_pool_128_accepts_only_its_address(self):
        self.assertEqual(manager.generate_random_ipv6('2001:db8::7', 128, 1), ['2001:db8::7'])
        with self.assertRaises(ValueError):
            manager.generate_random_ipv6('2001:db8::7', 128, 1, exclude_addresses=['2001:0db8::7'])

    def test_bounded_generator_even_when_random_draws_repeat(self):
        with patch.object(manager.secrets, 'randbelow', return_value=0) as random:
            generated = manager.generate_random_ipv6('2001:db8::', 124, 12,
                exclude_addresses=['2001:db8::2', {'address': '2001:0db8::4'}, '2001:db8::6'])
        self.assertEqual(random.call_count, 12)
        self.assertEqual(len(set(generated)), 12)
        self.assertFalse(set(generated) & {'2001:db8::', '2001:db8::2', '2001:db8::4', '2001:db8::6'})

    def test_generator_excludes_system_snapshot(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address('2001:db8::1')]) as snapshot:
            self.assertEqual(set(manager.generate_random_ipv6('2001:db8::', 126, 2, interface='eth0')),
                             {'2001:db8::2', '2001:db8::3'})
            snapshot.assert_called_once_with('eth0', strict=True)
        with patch.object(manager, 'get_ipv6_addresses', side_effect=RuntimeError('read failed')):
            with self.assertRaises(RuntimeError):
                manager.generate_random_ipv6('2001:db8::', 64, 1, interface='eth0')

    def test_generator_input_range(self):
        for count in [-1, 10001, 1.5, True, '1e3']:
            with self.subTest(count=count), self.assertRaises(ValueError):
                manager.generate_random_ipv6('2001:db8::', 64, count)
        self.assertEqual(manager.generate_random_ipv6('2001:db8::', 64, 0), [])


class KernelSnapshotTests(unittest.TestCase):
    def test_json_address_flags_lifetimes_and_canonicalization(self):
        data = [{'ifname': 'eth0', 'addr_info': [
            {'family': 'inet', 'local': '192.0.2.1', 'prefixlen': 24},
            {'family': 'inet6', 'local': '2001:0db8::1', 'prefixlen': 64,
             'scope': 'global', 'dynamic': True, 'tentative': True,
             'valid_life_time': 90, 'preferred_life_time': 60},
            {'family': 'inet6', 'local': '2001:db8::2', 'prefixlen': 128,
             'scope': 'global', 'valid_life_time': 4294967295, 'preferred_life_time': 'forever'},
            {'family': 'inet6', 'local': '2001:db8::3', 'prefixlen': 64,
             'scope': 'global', 'preferred_life_time': 0},
        ]}]
        with patch.object(manager, '_run', return_value=response(json.dumps(data))) as run:
            actual = manager.get_ipv6_addresses('eth0', strict=True)
        self.assertEqual(run.call_args.args[0], ['ip', '-j', '-6', 'addr', 'show', 'dev', 'eth0'])
        self.assertEqual(actual[0]['address'], '2001:db8::1')
        self.assertEqual(actual[0]['flags'], ['dynamic', 'tentative'])
        self.assertEqual(actual[0]['valid_lft'], 90)
        self.assertFalse(actual[0]['ready'])
        self.assertTrue(actual[1]['ready'])
        self.assertIsNone(actual[1]['valid_lft'])
        self.assertFalse(actual[2]['ready'])

    def test_strict_snapshot_fails_closed(self):
        for result in [response('', 1, 'permission denied'), response('broken'), response('{}')]:
            with self.subTest(result=result), patch.object(manager, '_run', return_value=result):
                with self.assertRaises(RuntimeError):
                    manager.get_ipv6_addresses('eth0', strict=True)
                self.assertEqual(manager.get_ipv6_addresses('eth0'), [])

    def test_interface_json(self):
        with patch.object(manager, '_run', return_value=response(json.dumps([
            {'ifname': 'lo'}, {'ifname': 'eth0'}, {'ifname': 'veth0@if4'}]))):
            self.assertEqual(manager.get_interfaces(), ['eth0', 'veth0'])

    def test_dad_waits_then_ready(self):
        with patch.object(manager, 'get_ipv6_addresses', side_effect=[
            [address(flags=['tentative'], ready=False)], [address()]]), patch.object(manager.time, 'sleep'):
            self.assertTrue(manager.wait_for_ipv6_ready('2001:db8::1', 'eth0'))

    def test_dad_failed_and_timeout(self):
        for item in [address(flags=['dadfailed'], ready=False), address(flags=['tentative'], ready=False),
                     address(preferred_lft=0, ready=False), address(valid_lft=0, ready=False)]:
            with self.subTest(item=item), patch.object(manager, 'get_ipv6_addresses', return_value=[item]):
                self.assertFalse(manager.wait_for_ipv6_ready('2001:db8::1', 'eth0', timeout=0))

    def test_add_has_validated_argv_and_noprefixroute(self):
        with patch.object(manager, '_run', return_value=response()) as run, \
             patch.object(manager, 'wait_for_ipv6_ready', return_value=True) as ready:
            self.assertTrue(manager.add_ipv6_to_interface('2001:0db8::1', 'eth0'))
        self.assertEqual(run.call_args.args[0], ['ip', '-6', 'addr', 'add', '2001:db8::1/128', 'dev', 'eth0', 'noprefixroute'])
        ready.assert_called_once_with('2001:db8::1', 'eth0', timeout=5)

    def test_add_file_exists_verifies_exact_prefix(self):
        with patch.object(manager, '_run', return_value=response('', 2, 'other language')), \
             patch.object(manager, 'get_ipv6_addresses', return_value=[address(prefix_len=64)]):
            self.assertFalse(manager.add_ipv6_to_interface('2001:db8::1', 'eth0', 128))
            self.assertTrue(manager.add_ipv6_to_interface('2001:db8::1', 'eth0', 64, wait_ready=False))

    def test_add_timeout_returns_failure(self):
        with patch.object(manager, '_run', side_effect=subprocess.TimeoutExpired('ip', 10)):
            self.assertFalse(manager.add_ipv6_to_interface('2001:db8::1', 'eth0'))

    def test_exclusive_creation_never_adopts_matching_eexist(self):
        with patch.object(manager, '_run', return_value=response('', 2, 'other language')), \
                patch.object(manager, 'get_ipv6_addresses', return_value=[address()]), \
                patch.object(manager, 'wait_for_ipv6_ready') as ready:
            callback = Mock()
            row = manager.bulk_add_ipv6(['2001:db8::1'], 'eth0', on_created=callback)[0]
        self.assertFalse(row['success'])
        self.assertFalse(row['created'])
        self.assertTrue(row['existing'])
        callback.assert_not_called()
        ready.assert_not_called()

    def test_exclusive_creation_callback_precedes_dad_and_retains_created_on_failure(self):
        events = []
        callback = lambda row: events.append(('created', row['created'], row['success']))
        with patch.object(manager, '_run', return_value=response()) as run, \
                patch.object(manager, 'wait_for_ipv6_ready', side_effect=lambda *args, **kwargs: events.append(('dad',)) or False):
            row = manager.bulk_add_ipv6(['2001:0db8::1'], 'eth0', wait_ready=True, on_created=callback)[0]
        self.assertTrue(row['created'])
        self.assertFalse(row['success'])
        self.assertEqual(row['address'], '2001:db8::1')
        self.assertEqual(events, [('created', True, True), ('dad',)])
        self.assertEqual(run.call_args.args[0], ['ip', '-6', 'addr', 'add', '2001:db8::1/128', 'dev', 'eth0', 'noprefixroute'])

    def test_exclusive_creation_timeout_is_unknown_not_cleanup_authority(self):
        with patch.object(manager, '_run', side_effect=subprocess.TimeoutExpired('ip', 10)), \
                patch.object(manager, 'get_ipv6_addresses') as snapshot:
            callback = Mock()
            row = manager.bulk_add_ipv6(['2001:db8::1'], 'eth0', on_created=callback)[0]
        self.assertFalse(row['success'])
        self.assertIsNone(row['created'])
        self.assertIn('unknown', row['error'])
        callback.assert_not_called()
        snapshot.assert_not_called()

    def test_exclusive_creation_journal_failure_propagates_before_dad(self):
        with patch.object(manager, '_run', return_value=response()), \
                patch.object(manager, 'wait_for_ipv6_ready') as ready:
            with self.assertRaisesRegex(RuntimeError, 'fixture journal failed'):
                manager.bulk_add_ipv6(['2001:db8::1'], 'eth0', wait_ready=True,
                                      on_created=Mock(side_effect=RuntimeError('fixture journal failed')))
        ready.assert_not_called()

    def test_exclusive_creation_invalid_dad_options_fail_before_kernel_mutation(self):
        with patch.object(manager, '_run') as run:
            for options in [{'ready_timeout': 121}, {'ready_timeout': float('nan')},
                            {'wait_ready': 'yes'}, {'on_created': 'not-callable'}]:
                with self.subTest(options=options), self.assertRaises(ValueError):
                    manager.create_ipv6_alias('2001:db8::1', 'eth0', **options)
        run.assert_not_called()

    def test_ndp_snapshot_counts_string_and_list_states_without_mac(self):
        data = [{'dst': 'fe80::1', 'dev': 'eth0', 'state': ['REACHABLE'], 'lladdr': '00:00:00:00:00:01'},
                {'dst': '2001:db8::2', 'dev': 'eth0', 'state': 'FAILED'},
                {'dst': '2001:db8::3', 'dev': 'eth0', 'state': ['INCOMPLETE']}]
        with patch.object(manager, '_run', return_value=response(json.dumps(data))) as run:
            observed = manager.observe_ndp('eth0')
        self.assertEqual(observed, {'interface': 'eth0', 'neighbor_count': 3,
                                    'states': {'REACHABLE': 1, 'FAILED': 1, 'INCOMPLETE': 1}})
        self.assertEqual(run.call_args.args[0], ['ip', '-j', '-6', 'neigh', 'show', 'dev', 'eth0'])
        self.assertNotIn('lladdr', json.dumps(observed))

    def test_ndp_failure_is_not_reported_as_zero_neighbors(self):
        for result in [response('', 1), response('{}'), response('broken')]:
            with self.subTest(result=result), patch.object(manager, '_run', return_value=result), self.assertRaises(RuntimeError):
                manager.observe_ndp('eth0')

    def test_remove_no_error_string_assumptions(self):
        with patch.object(manager, '_run', return_value=response('', 2, 'other language')), \
             patch.object(manager, 'get_ipv6_addresses', return_value=[]):
            self.assertTrue(manager.remove_ipv6_from_interface('2001:db8::1', 'eth0'))
        with patch.object(manager, '_run', return_value=response('', 2)), \
             patch.object(manager, 'get_ipv6_addresses', side_effect=RuntimeError('read failed')):
            self.assertFalse(manager.remove_ipv6_from_interface('2001:db8::1', 'eth0'))


class OwnershipRestoreRotationTests(unittest.TestCase):
    def test_cleanup_without_ledger_keeps_all_static_addresses(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address(), address('fd00::1')]), \
             patch.object(manager, 'remove_ipv6_from_interface') as remove:
            result = manager.cleanup_orphan_ipv6('eth0')
        self.assertEqual(result['removed'], 0)
        self.assertEqual(result['unmanaged'], 2)
        remove.assert_not_called()

    def test_cleanup_only_exact_owner_tuple_even_noprefixroute(self):
        records = [address(flags=['noprefixroute']), address('2001:db8::2', prefix_len=64),
                   address('2001:db8::3'), address('fe80::1', scope='link')]
        with patch.object(manager, 'get_ipv6_addresses', return_value=records), \
             patch.object(manager, 'remove_ipv6_from_interface', return_value=True) as remove:
            result = manager.cleanup_orphan_ipv6('eth0', keep_addresses=['2001:0db8::3'],
                managed_addresses=[address(), address('2001:db8::2', prefix_len=128),
                                   address('2001:db8::3'), address('fe80::1', scope='link')])
        remove.assert_called_once_with('2001:db8::1', 'eth0', 128)
        self.assertEqual(result['removed'], 1)
        self.assertEqual(result['kept'], 3)

    def test_cleanup_failure_does_not_claim_removed(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address()]), \
             patch.object(manager, 'remove_ipv6_from_interface', return_value=False):
            result = manager.cleanup_orphan_ipv6('eth0', managed_addresses=[address()])
        self.assertEqual(result['removed'], 0)
        self.assertEqual(result['failed'], ['2001:db8::1'])

    def test_restore_per_proxy_interface_and_prefix_success_count(self):
        proxies = [{'ipv6': '2001:0db8::1', 'interface': 'eth0', 'address_prefix_len': 128},
                   {'ipv6': '2001:db8::2', 'interface': 'eth1', 'address_prefix_len': 64},
                   {'ipv6': '2001:db8::3', 'interface': 'eth1', 'address_prefix_len': 128}]
        with patch.object(manager, 'get_ipv6_addresses', side_effect=[[], []]) as snap, \
             patch.object(manager, 'add_ipv6_to_interface', side_effect=[True, False, True]) as add, \
             patch.object(manager, 'probe_ipv6_egress', return_value={'success': True}) as probe:
            result = manager.restore_proxy_addresses(proxies, {'interface': 'other'}, probe=True)
        self.assertEqual(result['restored'], 2)
        self.assertEqual(result['failed'], 1)
        self.assertEqual(snap.call_count, 2)
        self.assertEqual(add.call_args_list, [unittest.mock.call('2001:db8::1', 'eth0', 128),
                                            unittest.mock.call('2001:db8::2', 'eth1', 64),
                                            unittest.mock.call('2001:db8::3', 'eth1', 128)])
        self.assertEqual(probe.call_count, 2)

    def test_restore_probe_failure_not_success(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[]), \
             patch.object(manager, 'add_ipv6_to_interface', return_value=True), \
             patch.object(manager, 'probe_ipv6_egress', return_value={'success': False, 'error': 'egress failed'}):
            result = manager.restore_proxy_addresses([{'ipv6': '2001:db8::1', 'interface': 'eth0'}], probe=True)
        self.assertEqual(result['restored'], 0)
        self.assertEqual(result['failed'], 1)

    def test_restore_canonical_existing_not_readded(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address()]), \
             patch.object(manager, 'add_ipv6_to_interface') as add:
            result = manager.restore_proxy_addresses([{'ipv6': '2001:0db8::1', 'interface': 'eth0'}])
        self.assertEqual(result['already_present'], 1)
        self.assertEqual(result['restored'], 0)
        add.assert_not_called()

    def test_restore_skips_full_existing_pool_probes_when_requested(self):
        proxies = [{'ipv6': f'2001:db8::{index:x}', 'interface': 'eth0'}
                   for index in range(1, 201)]
        snapshot = [address(proxy['ipv6']) for proxy in proxies]
        with patch.object(manager, 'get_ipv6_addresses', return_value=snapshot) as read, \
             patch.object(manager, 'add_ipv6_to_interface') as add, \
             patch.object(manager, 'probe_ipv6_egress') as probe:
            result = manager.restore_proxy_addresses(proxies, probe=True, probe_existing=False)
        self.assertEqual(result['already_present'], 200)
        self.assertEqual(result['restored'], 0)
        self.assertEqual(result['failed'], 0)
        self.assertTrue(all(item['success'] for item in result['results']))
        read.assert_called_once_with('eth0', strict=True)
        add.assert_not_called()
        probe.assert_not_called()

    def test_restore_existing_probe_default_remains_enabled(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address()]), \
             patch.object(manager, 'add_ipv6_to_interface') as add, \
             patch.object(manager, 'probe_ipv6_egress', return_value={'success': True}) as probe:
            result = manager.restore_proxy_addresses(
                [{'ipv6': '2001:db8::1', 'interface': 'eth0'}], probe=True)
        self.assertEqual(result['already_present'], 1)
        self.assertEqual(result['failed'], 0)
        add.assert_not_called()
        probe.assert_called_once_with('2001:db8::1', 'eth0',
                                      target_url=manager.DEFAULT_PROBE_URL, timeout=10)

    def test_restore_missing_source_is_probed_even_when_existing_probes_skipped(self):
        proxies = [{'ipv6': '2001:db8::1', 'interface': 'eth0'},
                   {'ipv6': '2001:db8::2', 'interface': 'eth0'}]
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address()]), \
             patch.object(manager, 'add_ipv6_to_interface', return_value=True) as add, \
             patch.object(manager, 'probe_ipv6_egress', return_value={'success': True}) as probe:
            result = manager.restore_proxy_addresses(proxies, probe=True, probe_existing=False)
        self.assertEqual(result['already_present'], 1)
        self.assertEqual(result['restored'], 1)
        self.assertEqual(result['failed'], 0)
        add.assert_called_once_with('2001:db8::2', 'eth0', 128)
        probe.assert_called_once_with('2001:db8::2', 'eth0',
                                      target_url=manager.DEFAULT_PROBE_URL, timeout=10)

    def test_restore_missing_source_probe_failure_is_not_success_when_existing_skipped(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[]), \
             patch.object(manager, 'add_ipv6_to_interface', return_value=True), \
             patch.object(manager, 'probe_ipv6_egress',
                          return_value={'success': False, 'error': 'egress failed'}) as probe:
            result = manager.restore_proxy_addresses(
                [{'ipv6': '2001:db8::1', 'interface': 'eth0'}], probe=True, probe_existing=False)
        self.assertEqual(result['restored'], 0)
        self.assertEqual(result['failed'], 1)
        self.assertFalse(result['results'][0]['success'])
        probe.assert_called_once()

    def test_restore_unusable_existing_source_still_requires_dad_when_probes_skipped(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address(ready=False)]), \
             patch.object(manager, 'wait_for_ipv6_ready', return_value=False) as dad, \
             patch.object(manager, 'probe_ipv6_egress') as probe:
            result = manager.restore_proxy_addresses(
                [{'ipv6': '2001:db8::1', 'interface': 'eth0'}], probe=True, probe_existing=False)
        self.assertEqual(result['failed'], 1)
        self.assertFalse(result['results'][0]['success'])
        dad.assert_called_once_with('2001:db8::1', 'eth0')
        probe.assert_not_called()

    def test_restore_snapshot_failure_never_adds(self):
        with patch.object(manager, 'get_ipv6_addresses', side_effect=RuntimeError('no snapshot')), \
             patch.object(manager, 'add_ipv6_to_interface') as add:
            result = manager.restore_proxy_addresses([{'ipv6': '2001:db8::1', 'interface': 'eth0'}])
        self.assertEqual(result['failed'], 1)
        add.assert_not_called()

    def test_auto_restore_failed_add_does_not_restart_or_claim_success(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[]), \
             patch.object(manager, 'add_ipv6_to_interface', return_value=False):
            restart = Mock()
            result = manager.auto_restore_ips(restart, proxies=[{'ipv6': '2001:db8::1', 'interface': 'eth0'}], settings={})
        self.assertEqual(result, 0)
        restart.assert_not_called()

    def test_rotation_rejects_legacy_destructive_calls_before_io(self):
        with patch.object(manager, '_run') as run:
            with self.assertRaises(ValueError):
                manager.rotate_ipv6_addresses('2001:db8::', 64, 1, 'eth0', ['2001:db8::1'])
        run.assert_not_called()

    def test_rotation_order_stage_probe_activate_retire(self):
        events = []
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address()]), \
             patch.object(manager, 'generate_random_ipv6', return_value=['2001:db8::2']), \
             patch.object(manager, 'bulk_add_ipv6', side_effect=lambda *args, **kwargs: events.append('add') or creation()), \
             patch.object(manager, 'probe_ipv6_egress', side_effect=lambda *args, **kw: events.append('probe') or {'success': True}), \
             patch.object(manager, 'remove_ipv6_from_interface', side_effect=lambda *args: events.append('remove') or True):
            result = manager.rotate_ipv6_addresses('2001:db8::', 64, 1, 'eth0', ['2001:db8::1'],
                managed_addresses=[address()], activate_func=lambda new: events.append('activate') or True,
                rollback_func=lambda: True)
        self.assertEqual(result, ['2001:db8::2'])
        self.assertEqual(events, ['add', 'probe', 'activate', 'remove'])

    def test_rotation_add_failure_keeps_old_and_removes_failed_staging(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address()]), \
             patch.object(manager, 'generate_random_ipv6', return_value=['2001:db8::2']), \
             patch.object(manager, 'bulk_add_ipv6', return_value=creation(success=False)), \
             patch.object(manager, 'remove_ipv6_from_interface', return_value=True) as remove:
            activate, rollback = Mock(), Mock()
            with self.assertRaisesRegex(RuntimeError, 'previous addresses/configuration restored'):
                manager.rotate_ipv6_addresses('2001:db8::', 64, 1, 'eth0', ['2001:db8::1'],
                    managed_addresses=[address()], activate_func=activate, rollback_func=rollback)
        remove.assert_called_once_with('2001:db8::2', 'eth0', 128)
        activate.assert_not_called()
        rollback.assert_not_called()

    def test_rotation_eexist_foreign_alias_is_never_deleted(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address()]), \
                patch.object(manager, 'generate_random_ipv6', return_value=['2001:db8::2']), \
                patch.object(manager, 'bulk_add_ipv6', return_value=creation(success=False, created=False)), \
                patch.object(manager, 'remove_ipv6_from_interface') as remove:
            with self.assertRaises(RuntimeError):
                manager.rotate_ipv6_addresses('2001:db8::', 64, 1, 'eth0', ['2001:db8::1'],
                                             managed_addresses=[address()], activate_func=lambda new: True,
                                             rollback_func=lambda: True)
        remove.assert_not_called()

    def test_rotation_unknown_add_retains_alias_for_explicit_review(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address()]), \
                patch.object(manager, 'generate_random_ipv6', return_value=['2001:db8::2']), \
                patch.object(manager, 'bulk_add_ipv6', return_value=creation(success=False, created=None)), \
                patch.object(manager, 'remove_ipv6_from_interface') as remove:
            with self.assertRaisesRegex(RuntimeError, 'acknowledgement unknown.*manual review'):
                manager.rotate_ipv6_addresses('2001:db8::', 64, 1, 'eth0', ['2001:db8::1'],
                                             managed_addresses=[address()], activate_func=lambda new: True,
                                             rollback_func=lambda: True)
        remove.assert_not_called()

    def test_rotation_activation_failure_rolls_back_config(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address()]), \
             patch.object(manager, 'generate_random_ipv6', return_value=['2001:db8::2']), \
             patch.object(manager, 'bulk_add_ipv6', return_value=creation()), \
             patch.object(manager, 'add_ipv6_to_interface', return_value=True), \
             patch.object(manager, 'remove_ipv6_from_interface', return_value=True) as remove:
            rollback = Mock(return_value=True)
            with self.assertRaises(RuntimeError):
                manager.rotate_ipv6_addresses('2001:db8::', 64, 1, 'eth0', ['2001:db8::1'],
                    managed_addresses=[address()], activate_func=lambda new: False,
                    rollback_func=rollback, probe=False)
        rollback.assert_called_once_with()
        remove.assert_called_once_with('2001:db8::2', 'eth0', 128)

    def test_rotation_incomplete_rollback_is_explicit(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address()]), \
             patch.object(manager, 'generate_random_ipv6', return_value=['2001:db8::2']), \
             patch.object(manager, 'bulk_add_ipv6', return_value=creation(success=False)), \
             patch.object(manager, 'remove_ipv6_from_interface', return_value=False):
            with self.assertRaisesRegex(RuntimeError, 'rollback incomplete'):
                manager.rotate_ipv6_addresses('2001:db8::', 64, 1, 'eth0', ['2001:db8::1'],
                    managed_addresses=[address()], activate_func=lambda new: True,
                    rollback_func=lambda: True, probe=False)

    def test_failed_config_rollback_retains_new_aliases_for_recovery(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address()]), \
             patch.object(manager, 'generate_random_ipv6', return_value=['2001:db8::2']), \
             patch.object(manager, 'bulk_add_ipv6', return_value=creation()), \
             patch.object(manager, 'add_ipv6_to_interface', return_value=True), \
             patch.object(manager, 'remove_ipv6_from_interface') as remove:
            with self.assertRaisesRegex(RuntimeError, 'staged aliases retained: 2001:db8::2'):
                manager.rotate_ipv6_addresses('2001:db8::', 64, 1, 'eth0', ['2001:db8::1'],
                    managed_addresses=[address()], activate_func=lambda new: False,
                    rollback_func=lambda: False, probe=False)
        remove.assert_not_called()


class EgressAndTopologyTests(unittest.TestCase):
    def test_probe_target_validation_blocks_private_and_non_https(self):
        for target in ['http://api64.ipify.org', 'https://u:p@example.org', 'https://localhost/',
                       'https://[::1]/', 'https://[fd00::1]/', 'https://127.0.0.1/',
                       'https://[ff02::1]/', 'https://[fec0::1]/',
                       'https://example.org/\n--interface', 'https://example.org/#fragment']:
            with self.subTest(target=target), self.assertRaises(ValueError):
                manager.validate_probe_target(target)

    def test_probe_dns_private_rebinding_rejected(self):
        answers = [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2606:4700::1111', 443, 0, 0)),
                   (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]
        with patch.object(manager.socket, 'getaddrinfo', return_value=answers), self.assertRaises(ValueError):
            manager.validate_probe_target('https://example.org/')

    def test_probe_dns_pinned_to_validated_public_aaaa(self):
        answers = [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2606:4700::1111', 443, 0, 0))]
        with patch.object(manager.socket, 'getaddrinfo', return_value=answers):
            target = manager.validate_probe_target('https://example.org/ip')
        self.assertEqual(target['resolve'], 'example.org:443:[2606:4700::1111]')

    def test_egress_source_bound_no_proxy_redirect_or_config(self):
        target = {'url': 'https://example.org/ip', 'resolve': 'example.org:443:[2606:4700::1111]'}
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address()]), \
             patch.object(manager, 'validate_probe_target', return_value=target), \
             patch.object(manager, '_run', return_value=response('2001:0db8::1\n')) as run:
            actual = manager.probe_ipv6_egress('2001:db8::1', 'eth0', target_url=target['url'])
        self.assertTrue(actual['success'])
        argv = run.call_args.args[0]
        self.assertEqual(argv[:2], ['curl', '--disable'])
        for flag, value in [('--noproxy', '*'), ('--proto', '=https'), ('--max-redirs', '0'),
                            ('--interface', '2001:db8::1'), ('--resolve', target['resolve'])]:
            self.assertEqual(argv[argv.index(flag) + 1], value)
        self.assertNotIn('--location', argv)

    def test_egress_mismatch_fails(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[address()]), \
             patch.object(manager, 'validate_probe_target', return_value={'url': 'https://example.org', 'resolve': None}), \
             patch.object(manager, '_run', return_value=response('2001:db8::2')):
            self.assertFalse(manager.probe_ipv6_egress('2001:db8::1', 'eth0')['success'])

    def test_egress_absent_never_executes_curl(self):
        with patch.object(manager, 'get_ipv6_addresses', return_value=[]), patch.object(manager, '_run') as run:
            self.assertFalse(manager.probe_ipv6_egress('2001:db8::1', 'eth0')['success'])
        run.assert_not_called()

    def test_observe_prefix_change_expiry_excludes_owned(self):
        records = [address('2606:4700:1::1', prefix_len=64, preferred_lft=0, ready=False),
                   address('2606:4700:2::2', prefix_len=64)]
        with patch.object(manager, 'get_ipv6_addresses', return_value=records), \
             patch.object(manager, 'get_ipv6_routes', return_value=[]):
            state = manager.observe_prefix_state('eth0', previous={'prefixes': [{'network': '2606:4700:3::/64'}]},
                managed_addresses=[records[1], address('2606:4700:2::3')])
        self.assertTrue(state['changed'])
        self.assertEqual(state['added_prefixes'], ['2606:4700:1::/64'])
        self.assertEqual(len(state['expired']), 1)
        self.assertEqual(state['missing_managed'][0]['address'], '2606:4700:2::3')

    def test_deprecated_privacy_ip_does_not_expire_live_prefix(self):
        records = [address('2606:4700:1::1', prefix_len=64, valid_lft=90, preferred_lft=0, ready=False),
                   address('2606:4700:1::2', prefix_len=64, valid_lft=900, preferred_lft=800)]
        with patch.object(manager, 'get_ipv6_addresses', return_value=records), \
             patch.object(manager, 'get_ipv6_routes', return_value=[]):
            state = manager.observe_prefix_state('eth0')
        self.assertEqual(state['expired'], [])
        self.assertEqual(state['prefixes'][0]['preferred_lft'], 800)

    def test_lan_topology_requires_matching_route_and_default(self):
        state = {'addresses': [address('2606:4700:1::1', prefix_len=64)],
                 'routes': [{'dst': 'default', 'gateway': 'fe80::1'}, {'dst': '2606:4700:1::/64'}]}
        with patch.object(manager, 'observe_prefix_state', return_value=state):
            self.assertTrue(manager.topology_preflight('2606:4700:1::', 64, 'eth0')['success'])
            self.assertTrue(manager.topology_preflight('2606:4700:1::', 80, 'eth0')['success'])
            self.assertFalse(manager.topology_preflight('2606:4700:2::', 64, 'eth0')['success'])
            self.assertFalse(manager.topology_preflight('2606:4700::', 48, 'eth0')['success'])
        state['routes'] = [{'dst': '2606:4700:1::/64'}]
        with patch.object(manager, 'observe_prefix_state', return_value=state):
            self.assertFalse(manager.topology_preflight('2606:4700:1::', 64, 'eth0')['success'])

    def test_routed_topology_requires_explicit_covering_allocation(self):
        state = {'addresses': [], 'routes': [{'dst': 'default', 'gateway': 'fe80::1'}]}
        with patch.object(manager, 'observe_prefix_state', return_value=state):
            self.assertFalse(manager.topology_preflight('2606:4700:1::', 64, 'eth0', topology_mode='routed')['success'])
            self.assertTrue(manager.topology_preflight('2606:4700:1::', 64, 'eth0', topology_mode='routed',
                routed_prefix='2606:4700:1::/48')['success'])

    def test_nonpublic_pool_fails_preflight_before_read(self):
        with patch.object(manager, 'observe_prefix_state') as observe:
            for prefix in ['fd00::', 'fe80::', '2001:db8::', 'ff02::']:
                self.assertFalse(manager.topology_preflight(prefix, 64, 'eth0')['success'])
        observe.assert_not_called()


if __name__ == '__main__':
    unittest.main()
