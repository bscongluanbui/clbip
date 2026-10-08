"""Power-outage/restart scenarios. Fake NIC/engine only, real durable SQLite."""
import copy
import ipaddress
import unittest
import threading
from unittest.mock import patch

from service import OperationError, ProxyService, address_key
from validation import ValidationError
import test_service as fixtures

USER, POOL = fixtures.USER, fixtures.POOL

NEW_POOL = '2606:4700:2::'


class RebootServiceTests(unittest.TestCase):
    setUp = fixtures.ServiceTests.setUp
    tearDown = fixtures.ServiceTests.tearDown
    names = fixtures.ServiceTests.names
    generate = fixtures.ServiceTests.generate

    def configure(self, count=3):
        state = self.store.read()
        state['settings'].update(startup_rebuild_enabled=True, startup_proxy_count=count)
        state['users'] = [copy.deepcopy(USER)]
        state['manual_stop'] = False
        self.store.write(state)

    def boot(self):
        self.service = ProxyService(store=self.store, net=self.net, proxy=self.engine)
        self.service.reconcile()
        return self.store.read()

    def new_base(self, old_present=False):
        row = copy.deepcopy(self.net.system[0])
        row.update(address=NEW_POOL+'1', valid_lft=1000, preferred_lft=1000)
        self.net.system = self.net.system+[row] if old_present else [row]

    def test_cold_reboot_replaces_prefix_and_exact_configured_count(self):
        self.generate(count=2)
        self.configure(4)
        old = {row['ipv6'] for row in self.store.read()['proxies']}
        self.net.aliases.clear()  # Host reboot loses all aliases, SQLite survives.
        self.new_base()
        state = self.boot()
        self.assertEqual(len(state['proxies']), 4)
        self.assertEqual(state['settings']['subnet'], NEW_POOL)
        self.assertFalse(old & {row['ipv6'] for row in state['proxies']})
        self.assertEqual([row['port'] for row in state['proxies']], [10000,10001,10002,10003])
        self.assertEqual(state['startup_recovery']['state'], 'ready')
        self.assertTrue(self.engine.running)
        self.assertTrue(self.service.health({})['ready'])

    def test_same_prefix_reboot_still_creates_fresh_addresses_once(self):
        self.generate(count=2)
        self.configure(3)
        old = {row['ipv6'] for row in self.store.read()['proxies']}
        state = self.boot()
        new = {row['ipv6'] for row in state['proxies']}
        self.assertEqual(len(new), 3)
        self.assertFalse(old & new)
        self.events.clear()
        self.service.reconcile()
        self.assertEqual(new, {row['ipv6'] for row in self.store.read()['proxies']})
        self.assertNotIn('add', self.names())
        self.assertNotIn('remove', self.names())

    def test_two_ready_base_prefixes_choose_only_reachable_source(self):
        self.generate()
        self.configure(2)
        self.new_base(old_present=True)
        real = self.net.probe_ipv6_egress
        def probe(address, iface, **kwargs):
            if address == POOL+'1':
                self.events.append(('probe_old_failed', address))
                return {'success': False}
            return real(address, iface, **kwargs)
        with patch.object(self.net, 'probe_ipv6_egress', side_effect=probe):
            state = self.boot()
        self.assertEqual(state['settings']['subnet'], NEW_POOL)
        self.assertEqual(state['startup_recovery']['base_ipv6'], NEW_POOL+'1')
        self.assertEqual(len(self.net.system), 2)  # No OS base address is deleted.

    def test_network_not_ready_waits_without_deleting_then_recovers(self):
        self.generate()
        self.configure(2)
        old = copy.deepcopy(self.store.read()['managed_addresses'])
        self.net.system.clear()
        self.events.clear()
        with self.assertRaises(RuntimeError):
            self.boot()
        self.assertFalse(self.engine.running)
        self.assertNotIn('remove', self.names())
        self.assertNotIn('add', self.names())
        self.assertEqual(self.store.read()['managed_addresses'], old)
        self.assertFalse(self.service.health({})['ready'])
        self.net.system = [{'address': NEW_POOL+'1', 'interface': 'eth0', 'prefix_len':64,
            'scope':'global','flags':['dynamic'],'ready':True,'valid_lft':1000,'preferred_lft':900}]
        self.service.reconcile()
        self.assertEqual(len(self.store.read()['proxies']), 2)
        self.assertTrue(self.engine.running)

    def test_cleanup_failure_retains_ledger_and_never_creates_until_retry(self):
        self.generate(count=2)
        self.configure(3)
        key = address_key(self.store.read()['managed_addresses'][0])
        self.net.failed_remove.add(key)
        self.events.clear()
        with self.assertRaises(OperationError):
            self.boot()
        state = self.store.read()
        self.assertEqual(state['proxies'], [])
        self.assertEqual(len(state['managed_addresses']), 1)
        self.assertEqual(address_key(state['managed_addresses'][0]), key)
        self.assertNotIn('add', self.names())
        self.assertFalse(self.engine.running)
        self.net.failed_remove.clear()
        self.service.reconcile()
        self.assertEqual(len(self.store.read()['proxies']), 3)
        self.assertNotIn(key, self.net.aliases)

    def test_stop_remains_stopped_after_new_worker_then_start_rebuilds(self):
        self.generate()
        self.configure(2)
        self.service.dispatch('stop', {})
        self.events.clear()
        state = self.boot()
        self.assertTrue(state['manual_stop'])
        self.assertEqual(state['desired_state'], 'stopped')
        self.assertFalse(self.engine.running)
        self.assertNotIn('add', self.names())
        response = self.service.dispatch('start', {})
        self.assertTrue(response['queued'])
        self.service.reconcile()
        self.assertFalse(self.store.read()['manual_stop'])
        self.assertEqual(len(self.store.read()['proxies']), 2)
        self.assertTrue(self.engine.running)

    def test_dad_failure_after_cleanup_rolls_back_only_to_empty_state(self):
        self.generate()
        self.configure(3)
        old = set(self.net.aliases)
        self.net.failure = 'dad'
        with self.assertRaises(OperationError):
            self.boot()
        state = self.store.read()
        self.assertEqual(state['proxies'], [])
        self.assertFalse(old & set(self.net.aliases))
        self.assertFalse(self.engine.running)
        self.assertEqual(self.engine.config['proxies'], [])
        self.assertNotEqual(state['startup_recovery']['phase'], 'done')
        self.net.failure = None
        self.service.reconcile()
        self.assertEqual(len(self.store.read()['proxies']), 3)

    def test_foreign_addresses_survive_full_owned_cleanup(self):
        self.generate()
        self.configure(2)
        key = (POOL+'ffff', 'eth0',128)
        self.net.aliases[key] = {'address':key[0],'interface':'eth0','prefix_len':128,
            'scope':'global','ready':True,'flags':[],'preferred_lft':None,'valid_lft':None}
        original_system = copy.deepcopy(self.net.system)
        self.boot()
        self.assertIn(key, self.net.aliases)
        self.assertEqual(self.net.system, original_system)
        removed = [a for e in self.events if e[0]=='remove' for a in e[3]]
        self.assertNotIn(key[0], removed)
        self.assertNotIn(POOL+'1', removed)

    def test_absent_unknown_crash_intent_resolves_after_cold_boot(self):
        self.generate()
        self.configure(2)
        state = self.store.read()
        state['uncertain_addresses'] = [{'address':POOL+'999', 'interface':'eth0',
            'prefix_len':128,'owner':'ipv6-manager','creation':'attempting','operation_id':'crash'}]
        self.store.write(state)
        state = self.boot()
        self.assertEqual(state['uncertain_addresses'], [])
        self.assertEqual(len(state['proxies']), 2)

    def test_present_unknown_intent_is_never_deleted_or_adopted(self):
        self.generate()
        self.configure(2)
        row = {'address':POOL+'999','interface':'eth0','prefix_len':128,
               'owner':'ipv6-manager','creation':'attempting','operation_id':'crash'}
        state = self.store.read()
        state['uncertain_addresses'] = [row]
        self.store.write(state)
        self.net.aliases[address_key(row)] = {**row,'scope':'global','ready':True,'preferred_lft':None,'valid_lft':None}
        self.events.clear()
        with self.assertRaises(OperationError):
            self.boot()
        self.assertIn(address_key(row), self.net.aliases)
        self.assertNotIn('remove', self.names())
        self.assertNotIn('add', self.names())

    def test_invalid_ports_fail_before_stop_or_nic_delete(self):
        self.generate()
        self.configure(2)
        state = self.store.read()
        state['settings'].update(start_port=65535)
        self.store.write(state)
        self.events.clear()
        with self.assertRaises(ValidationError):
            self.boot()
        self.assertNotIn('remove', self.names())
        self.assertNotIn('stop', self.names())

    def test_stop_engine_failure_keeps_all_addresses(self):
        self.generate()
        self.configure(2)
        self.engine.fail_stop = True
        self.events.clear()
        with self.assertRaises(OperationError):
            self.boot()
        self.assertNotIn('remove', self.names())
        self.assertNotIn('add', self.names())
        self.assertEqual(len(self.store.read()['proxies']), 1)

    def test_emergency_stop_during_source_probe_prevents_cleanup_and_next_boot(self):
        self.generate()
        self.configure(2)
        real = self.net.probe_ipv6_egress
        def stopping_probe(*args, **kwargs):
            self.store.request_stop()
            self.service.cancel_operation.set()
            return real(*args, **kwargs)
        self.events.clear()
        with patch.object(self.net,'probe_ipv6_egress',side_effect=stopping_probe):
            with self.assertRaises(OperationError):
                self.boot()
        self.assertTrue(self.store.read()['manual_stop'])
        self.assertNotIn('remove',self.names())
        self.assertNotIn('add',self.names())
        state = self.boot()
        self.assertEqual(state['desired_state'],'stopped')
        self.assertFalse(self.engine.running)

    def test_emergency_stop_during_cleanup_never_generates(self):
        self.generate(count=2)
        self.configure(3)
        real = self.net.bulk_remove_ipv6
        def stopping_remove(*args, **kwargs):
            result = real(*args, **kwargs)
            self.store.request_stop()
            self.service.cancel_operation.set()
            return result
        self.events.clear()
        with patch.object(self.net,'bulk_remove_ipv6',side_effect=stopping_remove):
            with self.assertRaises(OperationError):
                self.boot()
        self.assertNotIn('add',self.names())
        self.assertTrue(self.store.read()['manual_stop'])
        self.boot()
        self.assertFalse(self.engine.running)

    def test_stale_write_preserves_manual_stop_along_with_stop_epoch(self):
        self.configure()
        stale = self.store.read()
        self.store.request_stop()
        merged = self.store.write(stale)
        self.assertTrue(merged['manual_stop'])
        self.assertEqual(merged['desired_state'],'stopped')
        self.assertEqual(merged['stop_epoch'],1)

    def test_live_two_prefixes_renumber_when_old_still_ready_but_unreachable(self):
        self.generate(count=2)
        self.new_base(old_present=True)
        real = self.net.probe_ipv6_egress
        def probe(addr, iface, **kwargs):
            if ipaddress.IPv6Address(addr) in ipaddress.IPv6Network(POOL+'/64'):
                return {'success':False}
            return real(addr,iface,**kwargs)
        with patch.object(self.net,'probe_ipv6_egress',side_effect=probe):
            self.service.reconcile()
            self.service.last_base_probe = 0
            self.service.reconcile()
        state = self.store.read()
        self.assertEqual(len(state['proxies']),2)
        self.assertEqual(state['settings']['subnet'],NEW_POOL)
        self.assertTrue(self.engine.running)

    def test_missing_credentials_fail_before_cleanup(self):
        self.generate()
        self.configure()
        state=self.store.read()
        state['users']=[]
        self.store.write(state)
        self.events.clear()
        with self.assertRaises(ValueError):
            self.boot()
        self.assertNotIn('remove',self.names())
        self.assertNotIn('stop',self.names())

    def test_recovery_ready_is_atomic_with_proxy_commit(self):
        self.configure(2)
        state=self.boot()
        self.assertEqual(state['startup_recovery']['phase'],'done')
        self.assertGreater(state['startup_recovery']['completed_at'],0)
        self.assertIsNone(state['pending_operation'])
        self.assertEqual(len(state['managed_addresses']),2)
        self.assertEqual(state['desired_state'],'running')

    def test_explicit_restart_queues_fresh_rebuild(self):
        self.generate()
        self.configure(4)
        self.boot()
        old = {p['ipv6'] for p in self.store.read()['proxies']}
        self.assertTrue(self.service.dispatch('restart',{})['queued'])
        self.service.reconcile()
        self.assertFalse(old & {p['ipv6'] for p in self.store.read()['proxies']})
        self.assertEqual(len(self.store.read()['proxies']),4)

    def test_crash_with_confirmed_generation_journal_recovers_then_rebuilds(self):
        self.configure(2)
        self.service.startup_pending=False
        before=self.store.read()
        before['desired_state']='running'
        before['startup_recovery']={'state':'rebuilding','phase':'generating','target_count':2}
        row={'address':POOL+'abc','interface':'eth0','prefix_len':128,
             'owner':'ipv6-manager','active':True,'creation':'confirmed'}
        state=copy.deepcopy(before)
        state['managed_addresses']=[row]
        state['pending_operation']={'id':'crash','action':'proxies.generate','before':before,
            'configs':copy.deepcopy(self.engine.config),'added':[row],'staged':[row]}
        self.net.aliases[address_key(row)]={**row,'scope':'global','ready':True}
        self.store.write(state)
        state=self.boot()
        self.assertEqual(len(state['proxies']),2)
        self.assertNotIn(address_key(row),self.net.aliases)
        self.assertIsNone(state['pending_operation'])

    def test_settings_and_user_edits_do_not_reactivate_old_runtime_while_waiting(self):
        self.generate()
        self.configure()
        self.net.system.clear()
        with self.assertRaises(RuntimeError):
            self.boot()
        self.events.clear()
        self.service.dispatch('save_settings', {'log_enabled': False})
        self.service.dispatch('add_user', {'username':'second','password':'Second_Offline_42!'})
        self.assertFalse(self.engine.running)
        self.assertNotIn('activate',self.names())
        with self.assertRaises(OperationError):
            self.service.dispatch('rotate',{})

    def test_status_and_health_remain_readable_during_blocked_source_probe(self):
        self.configure(2)
        entered, release = threading.Event(), threading.Event()
        result=[]
        real=self.net.probe_ipv6_egress
        def blocked(*args, **kwargs):
            entered.set()
            if not release.wait(5):
                raise RuntimeError('Fixture timeout')
            return real(*args, **kwargs)
        def boot_thread():
            try:
                result.append(self.boot())
            except Exception as exc:
                result.append(exc)
        with patch.object(self.net,'probe_ipv6_egress',side_effect=blocked):
            thread=threading.Thread(target=boot_thread)
            thread.start()
            try:
                self.assertTrue(entered.wait(5))
                self.assertFalse(self.service.dispatch('health',{})['ready'])
                self.assertEqual(self.service.dispatch('status',{})['startup_recovery']['phase'],'waiting_network')
                self.assertEqual(self.service.dispatch('settings',{})['startup_proxy_count'],2)
            finally:
                release.set()
                thread.join(10)
            self.assertFalse(thread.is_alive())
        self.assertIsInstance(result[0],dict)

    def test_cleanup_checkpoint_timeout_retains_ledger_for_retry(self):
        self.generate(count=2)
        self.configure(3)
        old=copy.deepcopy(self.store.read()['managed_addresses'])
        real=self.net.bulk_remove_ipv6
        def expired(*args, **kwargs):
            rows=real(*args,**kwargs)
            self.service.operation_deadline=0
            return rows
        with patch.object(self.net,'bulk_remove_ipv6',side_effect=expired):
            with self.assertRaisesRegex(OperationError,'time budget'):
                self.boot()
        self.assertEqual(self.store.read()['managed_addresses'],[{**r,'active':False} for r in old])
        self.assertEqual(self.store.read()['proxies'],[])
        self.service.reconcile()
        self.assertEqual(len(self.store.read()['proxies']),3)

    def test_subnet_candidates_exclude_managed_aliases(self):
        self.generate(count=2)
        rows=self.service.subnets({'interface':'eth0'})['subnets']
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['source_address'],POOL+'1')

    def test_turning_off_recovery_during_wait_stops_auto_retry(self):
        self.generate()
        self.configure()
        self.net.system.clear()
        with self.assertRaises(RuntimeError):
            self.boot()
        self.service.dispatch('save_settings',{'startup_rebuild_enabled':False})
        self.assertTrue(self.store.read()['manual_stop'])
        self.assertEqual(self.store.read()['desired_state'],'stopped')
        self.assertFalse(self.engine.running)
        self.boot()
        self.assertFalse(self.engine.running)


if __name__ == '__main__':
    unittest.main()
