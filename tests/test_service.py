"""Offline transactional service/store integration with fake NIC and engine.

SQLite fixtures are ordinary workspace directories (not Windows 0700 tempdirs).
No subprocess, signal, DNS request, or network interface operation is executed.
"""
import copy
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import threading
import time
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import ipv6_manager
import proxy_config
from service import OperationError, ProxyService, address_key
from state_store import StateStore
from validation import ValidationError


USER = {'username': 'tester', 'password': 'Offline_Test_42!'}
POOL = '2606:4700:1::'


class RecordingStore(StateStore):
    def __init__(self, directory, events):
        self.events = events
        super().__init__(directory)

    def write(self, state):
        if state.get('pending_operation'):
            self.events.append(('journal', copy.deepcopy(state['pending_operation']['added'])))
        elif state.get('events') and state['events'][-1]['result'] == 'committed':
            self.events.append(('commit', state['events'][-1]['action']))
        return super().write(state)


class FakeNetwork:
    def __init__(self, events):
        self.events = events
        self.aliases = {}
        self.system = [{'address': POOL + '1', 'interface': 'eth0', 'prefix_len': 64,
                        'scope': 'global', 'flags': ['dynamic'], 'ready': True,
                        'valid_lft': 900, 'preferred_lft': 800}]
        self.failure = None
        self.failed_remove = set()
        self.counter = 10

    def get_ipv6_addresses(self, interface=None, *, strict=False):
        self.events.append(('snapshot', interface))
        rows = self.system + list(self.aliases.values())
        result = copy.deepcopy([r for r in rows if interface is None or r['interface'] == interface])
        if self.failure == 'dad':
            aliases = {(row['address'], row['interface'], row['prefix_len'])
                       for row in self.aliases.values()}
            for row in result:
                if (row['address'], row['interface'], row['prefix_len']) in aliases:
                    row.update(ready=False, flags=list(row.get('flags', [])) + ['dadfailed'])
        return result

    def topology_preflight(self, prefix, prefix_len, interface, **kwargs):
        self.events.append(('preflight', interface, prefix, prefix_len, kwargs))
        success = self.failure != 'topology'
        if kwargs.get('topology_mode') == 'routed':
            allocation = kwargs.get('routed_prefix')
            success = success and bool(allocation) and ipaddress.IPv6Network(f'{prefix}/{prefix_len}', strict=False).subnet_of(
                ipaddress.IPv6Network(allocation, strict=False))
        return {'success': success, 'errors': ['fixture topology failed']}

    def get_ipv6_routes(self, interface=None, **kwargs):
        routes = [{'dst': 'default', 'dev': interface or 'eth0'}]
        for row in self.system:
            if interface is None or row['interface'] == interface:
                routes.append({'dst': str(ipaddress.IPv6Network(
                    f"{row['address']}/{row['prefix_len']}", strict=False)), 'dev': row['interface']})
        return routes

    def select_current_lan_prefix(self, interface, **kwargs):
        with patch.object(ipv6_manager, 'get_ipv6_addresses', side_effect=self.get_ipv6_addresses), \
                patch.object(ipv6_manager, 'get_ipv6_routes', side_effect=self.get_ipv6_routes), \
                patch.object(ipv6_manager, 'probe_ipv6_egress', side_effect=self.probe_ipv6_egress):
            return ipv6_manager.select_current_lan_prefix(interface, **kwargs)

    def generate_random_ipv6(self, prefix, prefix_len, count=1, *, exclude_addresses=None, **kwargs):
        self.events.append(('generate', count))
        network = ipaddress.IPv6Network(f'{prefix}/{prefix_len}', strict=False)
        excluded = {str(ipaddress.IPv6Address(a)) for a in (exclude_addresses or [])}
        capacity = network.num_addresses - (0 if network.prefixlen == 128 else 1)
        if count > capacity:
            raise ValueError('Insufficient fixture capacity')
        result = []
        while len(result) < count:
            self.counter += 1
            candidate = str(network.network_address + (0 if network.prefixlen == 128 else self.counter))
            if candidate not in excluded:
                result.append(candidate)
                excluded.add(candidate)
        return result

    def bulk_add_ipv6(self, addresses, interface, prefix_len=128, **kwargs):
        self.events.append(('add', interface, prefix_len, list(addresses)))
        rows = []
        for address in addresses:
            key = (str(ipaddress.IPv6Address(address)), interface, prefix_len)
            if key in self.aliases:
                rows.append({'address': key[0], 'interface': interface, 'prefix_len': prefix_len,
                             'success': False, 'created': False, 'existing': True, 'error': 'fixture existing'})
                continue
            self.aliases[key] = {'address': key[0], 'interface': interface, 'prefix_len': prefix_len,
                                 'scope': 'global', 'flags': ['noprefixroute'], 'ready': True,
                                 'valid_lft': None, 'preferred_lft': None}
            row = {'address': key[0], 'interface': interface, 'prefix_len': prefix_len,
                   'success': True, 'created': True, 'existing': False, 'error': ''}
            if kwargs.get('on_created'):
                kwargs['on_created'](dict(row))
            row['success'] = self.failure != 'add'
            rows.append(row)
        return rows

    def bulk_remove_ipv6(self, addresses, interface, prefix_len=128):
        self.events.append(('remove', interface, prefix_len, list(addresses)))
        rows = []
        for address in addresses:
            key = (str(ipaddress.IPv6Address(address)), interface, prefix_len)
            success = key not in self.failed_remove
            if success:
                self.aliases.pop(key, None)
            rows.append({'address': address, 'success': success})
        return rows

    def wait_for_ipv6_ready(self, address, interface, **kwargs):
        self.events.append(('dad', address, interface))
        return self.failure != 'dad'

    def probe_ipv6_egress(self, address, interface, **kwargs):
        self.events.append(('probe', address, interface, kwargs))
        return {'success': self.failure != 'probe', 'address': address, 'observed_address': address}

    def restore_proxy_addresses(self, proxies, settings=None, *, probe=False, probe_existing=True, checkpoint=None):
        if checkpoint:
            checkpoint()
        self.events.append(('restore', len(proxies), probe, probe_existing))
        return {'restored': 0, 'failed': int(self.failure == 'restore'), 'already_present': len(proxies), 'results': []}

    def observe_prefix_state(self, interface, **kwargs):
        self.events.append(('observe', interface, kwargs))
        return {'routes': [{'dst': 'default', 'dev': interface}], 'prefixes': [], 'changed': False, 'expired': []}

    def get_interfaces(self):
        return ['eth0', 'eth1']

    def observe_ndp(self, interface=None):
        return {'interface': interface, 'neighbor_count': 1, 'states': {'REACHABLE': 1}}


class FakeEngine:
    def __init__(self, events):
        self.events = events
        self.config = {'proxies': [], 'users': [], 'settings': {}}
        self.running = False
        self.fail_restart_once = False
        self.fail_stop = False
        self.fail_start = False

    def validate_config_inputs(self, proxies, users, settings):
        self.events.append(('validate', len(proxies)))
        return proxy_config.validate_config_inputs(proxies, users, settings)

    def snapshot_configs(self):
        self.events.append(('snapshot_config',))
        return copy.deepcopy(self.config)

    def generate_config(self, proxies, users, settings):
        self.events.append(('config', len(proxies)))
        self.config = {'proxies': copy.deepcopy(proxies), 'users': copy.deepcopy(users), 'settings': copy.deepcopy(settings)}
        return 'fixture config'

    def save_config(self, config):
        self.events.append(('save_config',))

    def restore_configs(self, snapshot):
        self.events.append(('rollback_config',))
        self.config = copy.deepcopy(snapshot)

    def restart_3proxy(self):
        self.events.append(('activate',))
        if self.fail_restart_once:
            self.fail_restart_once = False
            return False, 'fixture engine start failed'
        self.running = bool(self.config['proxies'])
        return True, 'fixture activated'

    def stop_3proxy(self):
        self.events.append(('stop',))
        if self.fail_stop:
            return False, 'fixture stop failed'
        self.running = False
        return True, 'fixture stopped'

    def start_3proxy(self):
        self.events.append(('start',))
        if self.fail_start:
            return False, 'fixture recovery start failed'
        self.running = bool(self.config['proxies'])
        return True, 'fixture started'

    def running_instances(self):
        count = int(bool(self.config['proxies']))
        return {'ready': self.running, 'running': int(self.running), 'expected': count,
                'instances': [{'index': 0, 'ready': True}] if self.running else []}


class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parent
        self.directory = self.root / ('.tmp_service_' + uuid.uuid4().hex)
        self.directory.mkdir()
        self.events = []
        self.store = RecordingStore(self.directory, self.events)
        self.net = FakeNetwork(self.events)
        self.engine = FakeEngine(self.events)
        self.service = ProxyService(store=self.store, net=self.net, proxy=self.engine)
        self.environment = patch.dict(os.environ, {'MAX_PROXY_SERVICES': '1024', 'MAX_TOTAL_CONNECTIONS': '65536'})
        self.environment.start()
        # Use a numeric DNS fixture; a separate test checks real default port syntax.
        state = self.store.read()
        state['settings']['dns1'] = '127.0.0.1'
        self.store.write(state)
        self.events.clear()

    def tearDown(self):
        self.environment.stop()
        assert self.directory.resolve().is_relative_to(self.root)
        shutil.rmtree(self.directory)

    def names(self):
        return [event[0] for event in self.events]

    def generate(self, **changes):
        return self.service.dispatch('generate', {'count': 1, 'subnet': POOL, 'prefix_len': 64,
            'interface': 'eth0', 'username': USER['username'], 'password': USER['password'], **changes})

    def test_default_dns_port_accepted_by_engine_validation(self):
        state = self.store.read()
        state['settings']['dns1'] = '127.0.0.1:5353'
        state['users'] = [USER]
        proxy = {'ipv6': POOL + '3', 'port': 10000, 'protocol': 'http'}
        self.engine.validate_config_inputs([proxy], state['users'], state['settings'])

    def test_missing_user_fails_closed_before_any_nic_snapshot(self):
        with self.assertRaises(ValueError):
            self.service.dispatch('generate', {'count': 1, 'subnet': POOL})
        self.assertFalse(set(self.names()) & {'preflight', 'snapshot', 'generate', 'add'})
        self.assertEqual(self.store.read()['proxies'], [])

    def test_missing_ip_allowlist_and_public_opt_in_fail_before_nic(self):
        for params in [{'auth_type': 'ip'}, {'auth_type': 'none', 'public_proxy': False}]:
            self.events.clear()
            with self.subTest(params=params), self.assertRaises(ValueError):
                self.service.dispatch('generate', {'subnet': POOL, 'count': 1, **params})
            self.assertNotIn('snapshot', self.names())
            self.assertNotIn('add', self.names())

    def test_injection_and_typed_validation_before_nic(self):
        cases = [{'interface': 'eth0\nflush'}, {'count': True}, {'protocol': 'unknown'},
                 {'start_port': 65536}, {'prefix_len': 129}, {'password': 'x\nauth none'},
                 {'dns1': '127.0.0.1\nallow *'}, {'probe_url': 'http://example.org'}]
        for changes in cases:
            self.events.clear()
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.generate(**changes)
            self.assertNotIn('add', self.names())

    def test_topology_failure_never_mutates_nic_or_state(self):
        self.net.failure = 'topology'
        before = self.store.read()
        with self.assertRaises(ValidationError):
            self.generate()
        self.assertNotIn('add', self.names())
        self.assertEqual(self.store.read(), before)

    def test_order_journal_add_dad_probe_activate_commit_before_remove(self):
        self.generate()
        old = self.store.read()['proxies'][0]
        old_address = old['ipv6']
        self.events.clear()
        result = self.service.dispatch('rotate', {})
        self.assertTrue(result['success'])
        names = self.names()
        ordered = ['journal', 'add', 'dad', 'probe', 'activate', 'commit', 'remove']
        self.assertEqual([names.index(name) for name in ordered], sorted(names.index(name) for name in ordered))
        removal = next(e for e in self.events if e[0] == 'remove')
        self.assertEqual(removal[1:3], ('eth0', 128))
        self.assertEqual(removal[3], [old_address])
        state = self.store.read()
        self.assertIsNone(state['pending_operation'])
        self.assertEqual(len(state['managed_addresses']), 1)
        self.assertEqual(state['managed_addresses'][0]['prefix_len'], 128)
        self.assertEqual(state['proxies'][0]['prefix_len'], 64)
        self.assertEqual(state['proxies'][0]['address_prefix_len'], 128)

    def test_legacy_64_alias_rotates_to_128_and_retires_exact_old_prefix(self):
        self.generate()
        state = self.store.read()
        old = state['proxies'][0]
        old_key = address_key(old)
        old['address_prefix_len'] = 64
        state['managed_addresses'][0]['prefix_len'] = 64
        self.store.write(state)
        previous = self.net.aliases.pop(old_key)
        previous['prefix_len'] = 64
        self.net.aliases[address_key(old)] = previous
        self.events.clear()
        self.service.dispatch('rotate', {})
        current = self.store.read()
        self.assertEqual(current['proxies'][0]['address_prefix_len'], 128)
        self.assertEqual(current['managed_addresses'][0]['prefix_len'], 128)
        addition = next(e for e in self.events if e[0] == 'add')
        removal = next(e for e in self.events if e[0] == 'remove')
        self.assertEqual(addition[2], 128)
        self.assertEqual(removal[2], 64)

    def test_failure_add_dad_probe_engine_restores_state_config_ledger(self):
        self.generate()
        original = self.store.read()
        original_config = copy.deepcopy(self.engine.config)
        for failure in ['add', 'dad', 'probe', 'engine']:
            self.events.clear()
            self.net.failure = None if failure == 'engine' else failure
            self.engine.fail_restart_once = failure == 'engine'
            with self.subTest(failure=failure), self.assertRaises(OperationError):
                self.service.dispatch('rotate', {})
            current = self.store.read()
            for field in ['proxies', 'managed_addresses', 'users', 'desired_state', 'settings']:
                self.assertEqual(current[field], original[field], (failure, field))
            self.assertIsNone(current['pending_operation'])
            self.assertEqual(self.engine.config, original_config)
            self.assertTrue(self.engine.running)
            self.assertEqual(set(self.net.aliases), {address_key(original['managed_addresses'][0])})
            self.assertIn('rollback_config', self.names())
            self.assertEqual(current['events'][-1]['result'], 'rolled_back')
        self.net.failure = None

    def test_failed_cleanup_retains_inactive_ownership_for_retry(self):
        self.generate()
        old = self.store.read()['managed_addresses'][0]
        self.net.failed_remove.add(address_key(old))
        result = self.service.dispatch('rotate', {})
        self.assertEqual(result['cleanup_pending'], 1)
        ledger = self.store.read()['managed_addresses']
        self.assertEqual(len(ledger), 2)
        retired = next(r for r in ledger if r['address'] == old['address'])
        self.assertFalse(retired['active'])
        self.net.failed_remove.clear()
        cleaned = self.service.dispatch('cleanup', {})
        self.assertEqual(cleaned['removed'], 1)
        self.assertEqual(len(self.store.read()['managed_addresses']), 1)

    def test_unverified_runtime_rollback_retains_journal_and_staged_ownership(self):
        self.generate()
        original = self.store.read()['proxies']
        self.engine.fail_restart_once = True
        self.engine.fail_stop = True
        self.events.clear()
        with self.assertRaises(OperationError):
            self.service.dispatch('rotate', {})
        pending = self.store.read()
        self.assertIsNotNone(pending['pending_operation'])
        self.assertEqual(pending['proxies'], original)
        self.assertEqual(len(pending['managed_addresses']), 2)
        self.assertNotIn('remove', self.names())
        self.assertIn('Rollback incomplete', pending['last_error'])

    def test_cleanup_never_deletes_foreign_owner_records(self):
        state = self.store.read()
        foreign = {'address': POOL + '88', 'interface': 'eth0', 'prefix_len': 64,
                   'owner': 'other-service', 'active': False}
        state['managed_addresses'] = [foreign]
        self.store.write(state)
        self.events.clear()
        result = self.service.dispatch('cleanup', {})
        self.assertFalse(result['success'])
        self.assertEqual(result['removed'], 0)
        self.assertEqual(self.store.read()['managed_addresses'], [foreign])
        self.assertNotIn('remove', self.names())

    def test_delete_final_proxy_cleans_zero_config_and_owned_only(self):
        self.generate()
        state = self.store.read()
        identifier = state['proxies'][0]['id']
        unmanaged = ('2606:4700:1::abcd', 'eth0', 64)
        self.net.aliases[unmanaged] = {'address': unmanaged[0], 'interface': 'eth0', 'prefix_len': 64, 'ready': True}
        result = self.service.dispatch('delete', {'proxy_id': identifier})
        self.assertEqual(result['remaining'], 0)
        state = self.store.read()
        self.assertEqual(state['proxies'], [])
        self.assertEqual(state['managed_addresses'], [])
        self.assertEqual(state['desired_state'], 'stopped')
        self.assertEqual(self.engine.config['proxies'], [])
        self.assertFalse(self.engine.running)
        self.assertIn(unmanaged, self.net.aliases)

    def test_delete_all_cleans_all_config_and_per_interface_prefix(self):
        self.generate()
        self.generate(interface='eth1', subnet='2606:4700:2::', prefix_len=80)
        self.events.clear()
        self.service.dispatch('delete_all', {})
        removed = [e for e in self.events if e[0] == 'remove']
        self.assertEqual({e[1:3] for e in removed}, {('eth0', 128), ('eth1', 128)})
        self.assertEqual(self.store.read()['managed_addresses'], [])
        self.assertEqual(self.engine.config['proxies'], [])

    def test_lan_and_routed_groups_preserve_per_proxy_topology(self):
        self.generate(topology_mode='lan')
        self.generate(interface='eth1', subnet='2606:4700:2::', topology_mode='routed', routed_prefix='2606:4700:2::/48')
        self.service.dispatch('rotate', {})
        proxies = self.store.read()['proxies']
        lan = next(p for p in proxies if p['interface'] == 'eth0')
        routed = next(p for p in proxies if p['interface'] == 'eth1')
        self.assertEqual(lan['topology_mode'], 'lan')
        self.assertEqual(routed['topology_mode'], 'routed')
        self.assertEqual(routed['routed_prefix'], '2606:4700:2::/48')

    def test_lan_renumber_works_with_routed_group_as_latest_global_default(self):
        self.generate(topology_mode='lan')
        self.generate(interface='eth1', subnet='2606:4700:2::', topology_mode='routed', routed_prefix='2606:4700:2::/48')
        before = self.store.read()['proxies']
        routed_before = next(p for p in before if p['interface'] == 'eth1')
        lan_before = next(p for p in before if p['interface'] == 'eth0')
        self.net.system[0]['address'] = '2606:4700:3::1'
        self.service.reconcile()
        self.service.last_base_probe = 0
        self.service.reconcile()
        proxies = self.store.read()['proxies']
        routed_after = next(p for p in proxies if p['interface'] == 'eth1')
        lan_after = next(p for p in proxies if p['interface'] == 'eth0')
        self.assertEqual(routed_after, routed_before)
        self.assertNotEqual(lan_after['ipv6'], lan_before['ipv6'])
        self.assertEqual(lan_after['subnet'], '2606:4700:3::')

    def test_lan_renumber_preserves_routed_group_on_the_same_interface(self):
        self.generate(topology_mode='lan')
        self.generate(interface='eth0', subnet='2606:4700:2::', topology_mode='routed',
                      routed_prefix='2606:4700:2::/48')
        before = self.store.read()['proxies']
        routed_before = next(p for p in before if p['subnet'] == '2606:4700:2::')
        lan_before = next(p for p in before if p['subnet'] == POOL)
        self.net.system[0]['address'] = '2606:4700:3::1'
        self.service.reconcile()
        self.service.last_base_probe = 0
        self.service.reconcile()
        after = self.store.read()['proxies']
        routed_after = next(p for p in after if p['id'] == routed_before['id'])
        lan_after = next(p for p in after if p['id'] == lan_before['id'])
        self.assertEqual(routed_after, routed_before)
        self.assertNotEqual(lan_after['ipv6'], lan_before['ipv6'])
        self.assertEqual(lan_after['subnet'], '2606:4700:3::')

    def test_stop_persists_desired_state_and_reconciler_never_restarts(self):
        self.generate()
        self.service.dispatch('stop', {})
        self.events.clear()
        self.service.reconcile()
        self.service.reconcile()
        self.assertEqual(self.store.read()['desired_state'], 'stopped')
        self.assertNotIn('activate', self.names())
        self.assertNotIn('restore', self.names())
        self.assertFalse(self.engine.running)

    def test_stop_invalid_legacy_auth_still_closes_owned_processes(self):
        self.generate()
        state = self.store.read()
        state['users'] = []
        self.store.write(state)
        self.service.dispatch('stop', {})
        self.assertEqual(self.store.read()['desired_state'], 'stopped')
        self.assertFalse(self.engine.running)

    def test_emergency_stop_dominates_pending_transaction_recovery(self):
        self.generate()
        self.engine.fail_restart_once = True
        self.engine.fail_stop = True
        with self.assertRaises(OperationError):
            self.service.dispatch('rotate', {})
        self.assertIsNotNone(self.store.read()['pending_operation'])
        self.engine.fail_stop = False
        self.service.dispatch('stop', {})
        self.assertEqual(self.store.read()['desired_state'], 'stopped')
        self.events.clear()
        self.service.reconcile()
        self.assertEqual(self.store.read()['desired_state'], 'stopped')
        self.assertFalse(self.engine.running)
        self.assertNotIn('activate', self.names())
        self.assertNotIn('start', self.names())

    def test_new_address_eexist_race_is_not_adopted_or_deleted(self):
        self.generate()
        before = self.store.read()
        collided = []

        def foreign_races_add(addresses, interface, prefix_len=128, **kwargs):
            # A foreign owner adds the randomly selected alias after the
            # preflight snapshot but before our exclusive netlink add.
            key = (str(ipaddress.IPv6Address(addresses[0])), interface, prefix_len)
            collided.append(key)
            self.net.aliases[key] = {'address': key[0], 'interface': interface,
                                     'prefix_len': prefix_len, 'ready': True}
            self.events.append(('add', interface, prefix_len, list(addresses)))
            return [{'address': key[0], 'success': False, 'created': False}]

        with patch.object(self.net, 'bulk_add_ipv6', side_effect=foreign_races_add):
            with self.assertRaises(OperationError):
                self.service.dispatch('rotate', {})
        self.assertIn(collided[0], self.net.aliases)
        self.assertEqual(self.store.read()['managed_addresses'], before['managed_addresses'])
        removals = [address_key({'address': address, 'interface': e[1], 'prefix_len': e[2]})
                    for e in self.events if e[0] == 'remove' for address in e[3]]
        self.assertNotIn(collided[0], removals)

    def test_priority_stop_persists_while_generate_probe_is_blocked(self):
        self.generate()
        entered, release = threading.Event(), threading.Event()
        generated, stopped = [], []
        def blocked_probe(*args, **kwargs):
            entered.set()
            if not release.wait(10):
                raise RuntimeError('Fixture deadline')
            return {'success': True}
        def generate_thread():
            try:
                self.generate()
            except Exception as error:
                generated.append(error)
        with patch.object(self.net, 'probe_ipv6_egress', side_effect=blocked_probe):
            generating = threading.Thread(target=generate_thread)
            stopping = threading.Thread(target=lambda: stopped.append(self.service.dispatch('stop', {})))
            generating.start()
            try:
                self.assertTrue(entered.wait(5))
                stopping.start()
                # request_stop is independent of the service RLock held by generate.
                self.assertTrue(self.service.cancel_operation.wait(5))
                for _ in range(1000):
                    if self.store.read()['desired_state'] == 'stopped':
                        break
                self.assertEqual(self.store.read()['desired_state'], 'stopped')
                self.assertEqual(self.store.read()['stop_epoch'], 1)
            finally:
                release.set()
                generating.join(10)
                if stopping.ident is not None:
                    stopping.join(10)
            self.assertFalse(generating.is_alive())
            self.assertFalse(stopping.is_alive())
        self.assertEqual(len(generated), 1)
        self.assertIsInstance(generated[0], OperationError)
        self.assertTrue(stopped[0]['success'])
        self.assertFalse(self.engine.running)
        self.assertEqual(self.store.read()['desired_state'], 'stopped')
        self.assertEqual(len(self.store.read()['proxies']), 1)

    def test_stale_snapshot_cannot_erase_durable_stop_epoch(self):
        self.generate()
        stale = self.store.read()
        self.store.request_stop()
        merged = self.store.write(stale)
        self.assertEqual(merged['desired_state'], 'stopped')
        self.assertEqual(merged['stop_epoch'], 1)
        self.service.dispatch('stop', {})
        self.service.dispatch('start', {})
        self.assertEqual(self.store.read()['desired_state'], 'running')

    def test_batch_time_budget_rolls_back_before_runtime_commit(self):
        self.generate()
        before = self.store.read()
        clock = [0]
        def slow_probe(*args, **kwargs):
            clock[0] = 11
            return {'success': True}
        with patch.dict(os.environ, {'MAX_OPERATION_SECONDS': '10'}), \
                patch('service.time.monotonic', side_effect=lambda: clock[0]), \
                patch.object(self.net, 'probe_ipv6_egress', side_effect=slow_probe):
            with self.assertRaisesRegex(OperationError, 'time budget'):
                self.generate()
        self.assertEqual(self.store.read()['proxies'], before['proxies'])
        self.assertTrue(self.engine.running)
        self.assertIsNone(self.service.operation_deadline)

    def test_health_detects_per_group_topology_loss(self):
        self.generate()
        self.net.failure = 'topology'
        self.assertFalse(self.service.dispatch('health', {})['ready'])

    def test_multi_add_failure_never_removes_unattempted_foreign_alias(self):
        planned = [POOL + 'abc', POOL + 'def']
        foreign_key = (planned[1], 'eth0', 128)

        def first_add_fails(addresses, interface, prefix_len=128, **kwargs):
            self.net.aliases[foreign_key] = {'address': foreign_key[0], 'interface': interface,
                                            'prefix_len': prefix_len, 'ready': True}
            self.events.append(('add', interface, prefix_len, list(addresses)))
            return [{'address': addresses[0], 'success': False, 'created': False}]

        with patch.object(self.net, 'generate_random_ipv6', return_value=planned), \
                patch.object(self.net, 'bulk_add_ipv6', side_effect=first_add_fails):
            with self.assertRaises(OperationError):
                self.generate(count=2)
        self.assertIn(foreign_key, self.net.aliases)
        self.assertEqual(self.store.read()['managed_addresses'], [])
        self.assertEqual(len([e for e in self.events if e[0] == 'add']), 1)

    def test_unknown_add_timeout_preserves_alias_without_ownership(self):
        self.generate()
        before = self.store.read()
        unknown = []

        def timeout_after_possible_kernel_add(addresses, interface, prefix_len=128, **kwargs):
            key = (addresses[0], interface, prefix_len)
            unknown.append(key)
            self.net.aliases[key] = {'address': key[0], 'interface': interface,
                                     'prefix_len': prefix_len, 'ready': True}
            return [{'address': key[0], 'success': False, 'created': None, 'existing': False,
                     'error': 'fixture acknowledgement unknown'}]

        with patch.object(self.net, 'bulk_add_ipv6', side_effect=timeout_after_possible_kernel_add):
            with self.assertRaises(OperationError):
                self.service.dispatch('rotate', {})
        current = self.store.read()
        self.assertIn(unknown[0], self.net.aliases)
        self.assertEqual(current['proxies'], before['proxies'])
        self.assertEqual(current['managed_addresses'], before['managed_addresses'])
        self.assertEqual(len(current['uncertain_addresses']), 1)
        self.assertEqual(address_key(current['uncertain_addresses'][0]), unknown[0])
        self.assertFalse(self.service.dispatch('health', {})['ready'])
        self.events.clear()
        self.service.cleanup({})
        self.assertIn(unknown[0], self.net.aliases)
        self.assertNotIn('remove', self.names())

    def test_unknown_crash_before_created_callback_is_non_destructive_on_recovery(self):
        self.generate()
        before = self.store.read()
        unknown = {'address': POOL + '999', 'interface': 'eth0', 'prefix_len': 128,
                   'creation': 'attempting', 'owner': 'ipv6-manager', 'active': True}
        key = address_key(unknown)
        self.net.aliases[key] = {'address': key[0], 'interface': key[1], 'prefix_len': key[2], 'ready': True}
        state = copy.deepcopy(before)
        state['pending_operation'] = {'id': 'before-callback-crash', 'action': 'proxies.rotate',
                                      'before': before, 'configs': copy.deepcopy(self.engine.config),
                                      'added': [], 'staged': [unknown]}
        self.store.write(state)
        self.events.clear()
        with self.assertRaises(OperationError):
            self.service.reconcile()
        current = self.store.read()
        self.assertIsNone(current['pending_operation'])
        self.assertEqual(current['managed_addresses'], before['managed_addresses'])
        self.assertIn(key, self.net.aliases)
        self.assertEqual(address_key(current['uncertain_addresses'][0]), key)
        self.assertEqual(current['uncertain_addresses'][0]['operation_id'], 'before-callback-crash')
        self.assertNotIn('remove', self.names())
        self.assertFalse(self.service.dispatch('health', {})['ready'])

    def test_unknown_review_acknowledgement_only_discards_record_not_nic(self):
        self.generate()
        state = self.store.read()
        unknown = {'address': POOL + '999', 'interface': 'eth0', 'prefix_len': 128,
                   'creation': 'unknown', 'operation_id': 'review-op'}
        key = address_key(unknown)
        self.net.aliases[key] = {'address': key[0], 'interface': key[1], 'prefix_len': key[2], 'ready': True}
        state['uncertain_addresses'] = [unknown]
        self.store.write(state)
        self.events.clear()
        params = {'operation_id': 'review-op', 'address': unknown['address'], 'interface': 'eth0',
                  'acknowledge_unmanaged': True}
        result = self.service.dispatch('resolve_uncertain', params)
        self.assertFalse(result['nic_changed'])
        self.assertEqual(self.store.read()['uncertain_addresses'], [])
        self.assertIn(key, self.net.aliases)
        self.assertEqual(self.events, [])
        with self.assertRaises(ValidationError):
            self.service.dispatch('resolve_uncertain', params)

    def test_unknown_ownership_blocks_scheduled_rotation_until_review(self):
        self.generate()
        state = self.store.read()
        before = copy.deepcopy(state['proxies'])
        state['uncertain_addresses'] = [{'address': POOL + '999', 'interface': 'eth0', 'prefix_len': 128,
                                         'creation': 'unknown', 'operation_id': 'review-op'}]
        state['settings']['rotation_enabled'] = True
        state['rotation_due'] = 0
        self.store.write(state)
        self.events.clear()
        try:
            self.service.reconcile()
        except OperationError:
            pass
        self.assertEqual(self.store.read()['proxies'], before)
        self.assertNotIn('add', self.names())

    def test_unknown_ownership_blocks_renumber_mutations_until_review(self):
        self.generate()
        state = self.store.read()
        before = copy.deepcopy(state['proxies'])
        state['uncertain_addresses'] = [{'address': POOL + '999', 'interface': 'eth0', 'prefix_len': 128,
                                         'creation': 'unknown', 'operation_id': 'review-op'}]
        self.store.write(state)
        self.net.system[0]['address'] = '2606:4700:3::1'
        self.events.clear()
        try:
            self.service.reconcile()
        except OperationError:
            pass
        self.assertEqual(self.store.read()['proxies'], before)
        self.assertNotIn('add', self.names())

    def test_pending_mutations_are_blocked_but_emergency_stop_is_allowed(self):
        self.generate()
        before = self.store.read()
        state = copy.deepcopy(before)
        state['pending_operation'] = {'id': 'crash', 'action': 'settings.apply', 'before': before,
                                      'configs': copy.deepcopy(self.engine.config), 'added': [], 'staged': []}
        self.store.write(state)
        self.events.clear()
        for method, params in [('rotate', {}), ('start', {}), ('save_settings', {'max_connections': 128}),
                               ('add_user', {'username': 'blocked', 'password': 'Offline_Blocked_42!'}),
                               ('cleanup', {}), ('delete_all', {})]:
            with self.subTest(method=method), self.assertRaises(OperationError):
                self.service.dispatch(method, params)
        self.assertEqual(self.events, [])
        self.assertTrue(self.service.dispatch('stop', {})['success'])
        self.assertFalse(self.engine.running)
        self.assertEqual(self.store.read()['desired_state'], 'stopped')

    def test_revocation_applies_new_users_to_running_config(self):
        self.generate()
        self.service.dispatch('add_user', {'username': 'second', 'password': 'Offline_Second_42!'})
        self.events.clear()
        self.service.dispatch('delete_user', {'username': 'tester'})
        self.assertEqual([u['username'] for u in self.engine.config['users']], ['second'])
        self.assertIn('activate', self.names())
        self.assertEqual([u['username'] for u in self.service.dispatch('users', {})['users']], ['second'])
        self.assertNotIn('password', self.service.dispatch('users', {})['users'][0])

    def test_last_user_deletion_fails_closed_without_replacing_config(self):
        self.generate()
        before = copy.deepcopy(self.engine.config)
        self.events.clear()
        with self.assertRaises(ValueError):
            self.service.dispatch('delete_user', {'username': 'tester'})
        self.assertEqual(self.engine.config, before)
        self.assertNotIn('activate', self.names())

    def test_ports_skip_existing_full_interval_not_just_first_port(self):
        existing = [{'port': 10001, 'socks_port': 10004}]
        self.assertEqual(self.service._ports(existing, 4, 10000, 'http', 10000),
                         [[10000], [10002], [10003], [10005]])

    def test_dual_ports_check_cross_protocol_collisions_and_upper_bound(self):
        self.assertEqual(self.service._ports([{'port': 20000, 'socks_port': None}], 2, 10000, 'dual', 10000),
                         [[10001, 20001], [10002, 20002]])
        with self.assertRaises(ValidationError):
            self.service._ports([], 1, 65535, 'dual', 1)
        with self.assertRaises(ValidationError):
            self.generate(start_port=65535, count=2)

    def test_resource_budget_fails_before_nic(self):
        with patch.dict(os.environ, {'MAX_TOTAL_CONNECTIONS': '256'}), self.assertRaises(ValueError):
            self.generate(count=2, max_connections=256)
        self.assertNotIn('add', self.names())
        self.assertNotIn('snapshot', self.names())

    def test_idempotent_generate_does_not_reapply_nic_or_credentials(self):
        first = self.generate(_idempotency_key='fixed-request-1')
        state = self.store.read()
        self.events.clear()
        second = self.generate(_idempotency_key='fixed-request-1')
        self.assertEqual(first, second)
        self.assertEqual(self.store.read(), state)
        self.assertEqual(self.events, [])
        with self.assertRaises(ValidationError):
            self.generate(_idempotency_key='fixed-request-1', count=2)

    def test_failed_idempotency_key_never_reexecutes_uncertain_operation(self):
        self.net.failure = 'add'
        with self.assertRaises(OperationError):
            self.generate(_idempotency_key='failed-request-1')
        self.net.failure = None
        self.events.clear()
        with self.assertRaises(OperationError):
            self.generate(_idempotency_key='failed-request-1')
        self.assertEqual(self.events, [])
        self.assertEqual(self.store.read()['operations']['failed-request-1']['status'], 'failed')

    def test_pending_crash_journal_recovery_restores_old_config_and_ledger(self):
        self.generate()
        before = self.store.read()
        previous_config = copy.deepcopy(self.engine.config)
        staged = {'address': POOL + '999', 'interface': 'eth0', 'prefix_len': 128, 'owner': 'ipv6-manager', 'active': False}
        self.net.bulk_add_ipv6([staged['address']], 'eth0', 128)
        pending = copy.deepcopy(before)
        pending['managed_addresses'].append(staged)
        pending['pending_operation'] = {'id': 'crash', 'action': 'proxies.rotate', 'before': before,
                                         'configs': previous_config, 'added': [staged]}
        self.store.write(pending)
        self.engine.config = {'proxies': [{'ipv6': staged['address']}], 'users': [], 'settings': {}}
        self.events.clear()
        self.service.reconcile()
        recovered = self.store.read()
        self.assertEqual(recovered['proxies'], before['proxies'])
        self.assertEqual(recovered['managed_addresses'], before['managed_addresses'])
        self.assertIsNone(recovered['pending_operation'])
        self.assertNotIn(address_key(staged), self.net.aliases)
        self.assertTrue(self.engine.running)
        self.assertEqual([address_key(p) for p in self.engine.config['proxies']],
                         [address_key(p) for p in previous_config['proxies']])
        self.assertEqual([p['port'] for p in self.engine.config['proxies']],
                         [p['port'] for p in previous_config['proxies']])
        self.assertTrue(any(e['result'] == 'recovered_after_crash' for e in recovered['events']))

    def test_pending_recovery_stopped_does_not_restart(self):
        self.generate(start=False)
        before = self.store.read()
        state = copy.deepcopy(before)
        state['pending_operation'] = {'id': 'crash', 'action': 'settings.apply', 'before': before,
                                      'configs': copy.deepcopy(self.engine.config), 'added': []}
        self.store.write(state)
        self.events.clear()
        self.service.reconcile()
        self.assertNotIn('activate', self.names())
        self.assertEqual(self.store.read()['desired_state'], 'stopped')

    def test_forever_system_prefix_is_detected_and_subnet_80_does_not_renumber(self):
        self.generate(prefix_len=80)
        self.net.system[0]['preferred_lft'] = None
        self.net.system[0]['valid_lft'] = None
        self.events.clear()
        self.service.reconcile()
        self.assertNotIn('add', self.names())
        subnets = self.service.dispatch('subnets', {'interface': 'eth0'})
        self.assertTrue(any(s['prefix_len'] == 64 for s in subnets['subnets']))

    def test_existing_80_pool_inside_live_64_is_not_isp_renumbering(self):
        self.generate(prefix_len=80)
        original = self.store.read()['proxies']
        self.events.clear()
        self.service.reconcile()
        self.assertEqual(self.store.read()['proxies'], original)
        self.assertNotIn('add', self.names())

    def test_pending_recovery_failed_stop_keeps_journal_and_staged_alias(self):
        self.generate()
        before = self.store.read()
        staged = {'address': POOL + '999', 'interface': 'eth0', 'prefix_len': 128,
                  'owner': 'ipv6-manager', 'active': False}
        self.net.bulk_add_ipv6([staged['address']], 'eth0', 128)
        state = copy.deepcopy(before)
        state['managed_addresses'].append(staged)
        state['pending_operation'] = {'id': 'crash', 'action': 'proxies.rotate', 'before': before,
                                      'configs': copy.deepcopy(self.engine.config), 'added': [staged]}
        self.store.write(state)
        self.engine.fail_stop = True
        self.events.clear()
        with self.assertRaises(OperationError):
            self.service.reconcile()
        self.assertIsNotNone(self.store.read()['pending_operation'])
        self.assertIn(address_key(staged), self.net.aliases)
        self.assertNotIn('remove', self.names())

    def test_restore_failure_reconciler_does_not_restart_loop(self):
        self.generate()
        self.net.failure = 'restore'
        self.events.clear()
        for _ in range(2):
            with self.assertRaises(OperationError):
                self.service.reconcile()
        self.assertNotIn('activate', self.names())

    def test_reconcile_skips_existing_pool_restore_probes_between_periodic_checks(self):
        self.generate(count=3)
        self.service.last_base_probe = self.service.last_probe = self.service.started_at
        self.events.clear()
        self.service.reconcile()
        self.assertEqual([event for event in self.events if event[0] == 'restore'],
                         [('restore', 3, True, False)])
        self.assertNotIn('probe', self.names())
        self.assertNotIn('activate', self.names())

    def test_reconcile_keeps_periodic_probe_per_interface_and_prefix(self):
        self.generate(count=3)
        self.generate(count=2, interface='eth0', subnet='2606:4700:2::',
                      topology_mode='routed', routed_prefix='2606:4700:2::/48')
        self.generate(count=2, interface='eth1', subnet=POOL,
                      topology_mode='routed', routed_prefix='2606:4700:1::/48')
        proxies = self.store.read()['proxies']
        # Suppress a base probe independently of how long fixture generation took.
        now = time.time()
        self.service.last_base_probe = now
        self.service.last_probe = 0
        self.events.clear()
        with patch('service.time.time', return_value=now):
            self.service.reconcile()
        self.assertEqual([event for event in self.events if event[0] == 'restore'],
                         [('restore', 7, True, False)])
        probes = [event for event in self.events if event[0] == 'probe']
        self.assertEqual(len(probes), 3)
        records = {(p['ipv6'], p['interface']): p for p in proxies}
        groups = {(records[(event[1], event[2])]['interface'],
                   records[(event[1], event[2])]['subnet'],
                   records[(event[1], event[2])]['prefix_len']) for event in probes}
        self.assertEqual(groups, {('eth0', POOL, 64), ('eth0', '2606:4700:2::', 64),
                                  ('eth1', POOL, 64)})
        self.assertTrue(all(event[3]['expected_address'] == event[1] for event in probes))
        self.assertGreater(self.service.last_probe, 0)

    def test_explicit_start_retains_existing_pool_probe_default(self):
        self.generate(count=2)
        self.service.dispatch('stop', {})
        self.events.clear()
        self.service.dispatch('start', {})
        self.assertEqual([event for event in self.events if event[0] == 'restore'],
                         [('restore', 2, True, True)])

    def test_health_running_requires_dad_and_processes(self):
        self.generate()
        self.assertTrue(self.service.dispatch('health', {})['ready'])
        self.net.failure = 'dad'
        self.assertFalse(self.service.dispatch('health', {})['ready'])
        self.net.failure = None
        self.engine.running = False
        self.assertFalse(self.service.dispatch('health', {})['ready'])

    def test_health_200_aliases_use_one_strict_snapshot_and_no_per_alias_wait(self):
        self.generate()
        state = self.store.read()
        template = state['proxies'][0]
        alias = copy.deepcopy(next(iter(self.net.aliases.values())))
        state['proxies'] = [{**template, 'id': index, 'port': 10000 + index,
                             'ipv6': POOL + format(1000 + index, 'x')}
                            for index in range(1, 201)]
        state['managed_addresses'] = [self.service._ownership(p) for p in state['proxies']]
        self.net.aliases = {address_key(p): {**alias, 'address': p['ipv6']}
                            for p in state['proxies']}
        self.store.write(state)
        self.events.clear()
        with patch.object(self.net, 'get_ipv6_addresses', wraps=self.net.get_ipv6_addresses) as snapshot, \
                patch.object(self.net, 'wait_for_ipv6_ready') as wait:
            health = self.service.dispatch('health', {})
        self.assertTrue(health['ready'], health['errors'])
        self.assertEqual(health['proxy_count'], 200)
        snapshot.assert_called_once_with('eth0', strict=True)
        wait.assert_not_called()

    def test_health_snapshot_is_per_interface_and_canonicalizes_aliases(self):
        self.generate()
        self.generate(interface='eth1', subnet='2606:4700:2::', topology_mode='routed',
                      routed_prefix='2606:4700:2::/48')
        for row in self.net.aliases.values():
            row['address'] = ipaddress.IPv6Address(row['address']).exploded
        with patch.object(self.net, 'get_ipv6_addresses', wraps=self.net.get_ipv6_addresses) as snapshot, \
                patch.object(self.net, 'wait_for_ipv6_ready') as wait:
            health = self.service.dispatch('health', {})
        self.assertTrue(health['ready'], health['errors'])
        self.assertEqual(snapshot.call_count, 2)
        self.assertEqual({call.args[0] for call in snapshot.call_args_list}, {'eth0', 'eth1'})
        self.assertTrue(all(call.kwargs == {'strict': True} for call in snapshot.call_args_list))
        wait.assert_not_called()

    def test_health_alias_snapshot_failures_are_not_ready_and_preserve_error_shape(self):
        self.generate()
        for failure in (RuntimeError('fixture snapshot failed'), OSError('fixture permission failed'),
                        ValueError('fixture invalid snapshot')):
            with self.subTest(failure=failure), \
                    patch.object(self.net, 'get_ipv6_addresses', side_effect=failure):
                health = self.service.dispatch('health', {})
            self.assertFalse(health['ready'])
            self.assertIn('IPv6 chưa ready trên eth0', health['errors'])
            self.assertTrue(all(isinstance(error, str) for error in health['errors']))

    def test_health_alias_snapshot_rejects_missing_wrong_nic_prefix_flags_and_lifetimes(self):
        self.generate()
        original = copy.deepcopy(next(iter(self.net.aliases.values())))
        samples = [[], [{**original, 'interface': 'eth1'}], [{**original, 'prefix_len': 64}],
                   [{**original, 'ready': False}], [{**original, 'flags': ['tentative']}],
                   [{**original, 'flags': ['dadfailed']}], [{**original, 'flags': ['deprecated']}],
                   [{**original, 'valid_lft': 0}], [{**original, 'preferred_lft': 0}],
                   [{**original, 'address': 'invalid-address'}]]
        for rows in samples:
            with self.subTest(rows=rows), \
                    patch.object(self.net, 'get_ipv6_addresses', return_value=rows), \
                    patch.object(self.net, 'wait_for_ipv6_ready') as wait:
                health = self.service.dispatch('health', {})
            self.assertFalse(health['ready'])
            self.assertIn('IPv6 chưa ready trên eth0', health['errors'])
            wait.assert_not_called()

    def test_health_alias_snapshot_is_refreshed_on_each_request(self):
        self.generate()
        present = copy.deepcopy(list(self.net.aliases.values()))
        with patch.object(self.net, 'get_ipv6_addresses', side_effect=[present, []]) as snapshot:
            self.assertTrue(self.service.dispatch('health', {})['ready'])
            self.assertFalse(self.service.dispatch('health', {})['ready'])
        self.assertEqual(snapshot.call_count, 2)

    def test_health_pending_crash_journal_is_not_ready(self):
        self.generate()
        before = self.store.read()
        staged = copy.deepcopy(before)
        staged['pending_operation'] = {'id': 'interrupted', 'action': 'settings.apply',
                                       'before': before, 'configs': copy.deepcopy(self.engine.config), 'added': []}
        self.store.write(staged)
        self.assertFalse(self.service.dispatch('health', {})['ready'])

    def test_health_requires_usable_default_route_not_just_route_name(self):
        self.generate()
        for route in [{'dst': 'default', 'dev': 'eth0', 'expires': 0},
                      {'dst': 'default', 'dev': 'eth0', 'flags': ['linkdown']},
                      {'dst': 'default', 'dev': 'eth0', 'type': 'unreachable'}]:
            observed = {'routes': [route], 'prefixes': [], 'changed': False, 'expired': []}
            with self.subTest(route=route), patch.object(self.net, 'observe_prefix_state', return_value=observed):
                self.assertFalse(self.service.dispatch('health', {})['ready'])

    def test_health_metrics_include_ndp_and_exclude_credentials(self):
        self.generate()
        state = self.store.read()
        state['settings']['telegram_bot_token'] = 'OFFLINE_SECRET_TOKEN_SENTINEL'
        self.store.write(state)
        health = self.service.dispatch('health', {})
        self.assertEqual(health['metrics']['ndp']['neighbor_count'], 1)
        self.assertEqual(health['metrics']['ndp']['states'], {'REACHABLE': 1})
        self.assertEqual(health['metrics']['ndp']['interfaces']['eth0']['neighbor_count'], 1)
        rendered = json.dumps(health)
        self.assertNotIn(USER['password'], rendered)
        self.assertNotIn('OFFLINE_SECRET_TOKEN_SENTINEL', rendered)

    def test_health_metrics_ndp_failure_is_unknown_not_zero(self):
        self.generate()
        with patch.object(self.net, 'observe_ndp', side_effect=RuntimeError('fixture unavailable')):
            metrics = self.service.dispatch('health', {})['metrics']
        self.assertIsNone(metrics['ndp']['neighbor_count'])
        self.assertEqual(metrics['ndp']['errors'], ['eth0: observation unavailable'])

    def test_speedtest_rejects_unmanaged_proxy_and_ssrf_before_curl(self):
        self.generate()
        identifier = self.store.read()['proxies'][0]['id']
        cases = [{'proxy_id': identifier, 'target_url': 'http://example.org'},
                 {'proxy_id': identifier, 'target_url': 'https://127.0.0.1/'},
                 {'proxy_id': identifier, 'proxy_host': 'attacker.example'},
                 {'proxy_port': 443, 'target_url': 'https://example.org'}]
        with patch('service.subprocess.run') as run:
            for params in cases:
                with self.subTest(params=params), self.assertRaises(ValidationError):
                    self.service.dispatch('speedtest', params)
            run.assert_not_called()

    def test_speedtest_dns_private_answer_rejected_before_curl(self):
        self.generate()
        identifier = self.store.read()['proxies'][0]['id']
        answers = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 443))]
        with patch('validation.socket.getaddrinfo', return_value=answers), patch('service.subprocess.run') as run:
            with self.assertRaises(ValidationError):
                self.service.dispatch('speedtest', {'proxy_id': identifier, 'target_url': 'https://example.org'})
            run.assert_not_called()

    def test_speedtest_multicast_not_mistaken_for_global_public(self):
        self.generate()
        identifier = self.store.read()['proxies'][0]['id']
        answers = [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('ff02::1', 443, 0, 0))]
        with patch('validation.socket.getaddrinfo', return_value=answers), patch('service.subprocess.run') as run:
            run.return_value = SimpleNamespace(returncode=0, stdout='{"http_code":"200"}')
            with self.assertRaises(ValidationError):
                self.service.dispatch('speedtest', {'proxy_id': identifier, 'target_url': 'https://[ff02::1]/'})
            run.assert_not_called()

    def test_source_probe_target_rejects_multicast_and_pins_dns(self):
        with self.assertRaises(ValueError):
            ipv6_manager.validate_probe_target('https://[ff02::1]/')
        answers = [(socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('2606:4700::1111', 443, 0, 0))]
        with patch('ipv6_manager.socket.getaddrinfo', return_value=answers):
            self.assertEqual(ipv6_manager.validate_probe_target('https://example.org')['resolve'],
                             'example.org:443:[2606:4700::1111]')


class StateStoreTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parent
        self.directory = self.root / ('.tmp_store_' + uuid.uuid4().hex)
        self.directory.mkdir()

    def tearDown(self):
        assert self.directory.resolve().is_relative_to(self.root)
        shutil.rmtree(self.directory)

    def test_sqlite_canonical_migration_retains_original_address_prefix(self):
        legacy_settings = {'subnet': POOL, 'prefix_len': 64, 'interface': 'eth0', 'max_connections': 10000}
        legacy_proxy = {'id': 1, 'ipv6': '2606:4700:0001:0000:0000:0000:0000:000A', 'port': 10000, 'protocol': 'http'}
        for name, value in [('settings.json', legacy_settings), ('proxies.json', [legacy_proxy]), ('users.json', [USER])]:
            (self.directory / name).write_text(json.dumps(value), encoding='utf-8')
        state = StateStore(self.directory).read()
        self.assertEqual(state['proxies'][0]['ipv6'], POOL + 'a')
        self.assertEqual(state['managed_addresses'][0]['address'], POOL + 'a')
        self.assertEqual(state['proxies'][0]['address_prefix_len'], 64)
        self.assertEqual(state['managed_addresses'][0]['prefix_len'], 64)
        self.assertEqual(state['settings']['max_connections'], 64)
        self.assertEqual(state['desired_state'], 'stopped')

    def test_migration_once_does_not_read_modified_legacy_json(self):
        (self.directory / 'users.json').write_text(json.dumps([USER]), encoding='utf-8')
        first = StateStore(self.directory)
        (self.directory / 'users.json').write_text('broken legacy json', encoding='utf-8')
        self.assertEqual(StateStore(self.directory).read()['users'], first.read()['users'])

    def test_corrupt_legacy_fails_without_silently_resetting(self):
        path = self.directory / 'proxies.json'
        path.write_text('{broken', encoding='utf-8')
        with self.assertRaises(ValueError):
            StateStore(self.directory)
        self.assertEqual(path.read_text(), '{broken')

    def test_sqlite_write_atomic_revision_and_deep_copy(self):
        store = StateStore(self.directory)
        first = store.read()
        committed = store.write(first)
        self.assertEqual(committed['revision'], first['revision'] + 1)
        committed['users'].append(USER)
        self.assertEqual(store.read()['users'], [])
        store.write(committed)
        self.assertEqual(store.read()['users'], [USER])


if __name__ == '__main__':
    unittest.main()
