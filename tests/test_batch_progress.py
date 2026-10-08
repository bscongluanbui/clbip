"""Offline batch/cancellation/progress regressions; no NIC or DNS changes."""
import threading
import time
import unittest
from unittest.mock import patch

import test_service as fixtures
from service import ALIAS_BATCH_SIZE, VERIFY_WORKERS, OperationError


class BatchProgressTests(unittest.TestCase):
    setUp = fixtures.ServiceTests.setUp
    tearDown = fixtures.ServiceTests.tearDown
    generate = fixtures.ServiceTests.generate
    names = fixtures.ServiceTests.names

    def background(self, function):
        results, errors = [], []

        def run():
            try:
                results.append(function())
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=run)
        thread.start()
        return thread, results, errors

    def test_batches_are_sixteen_and_verifiers_bounded_to_eight(self):
        guard = threading.Lock()
        active, peak, completed = 0, 0, 0
        original = self.net.probe_ipv6_egress

        def probe(*args, **kwargs):
            nonlocal active, peak, completed
            with guard:
                active += 1
                peak = max(peak, active)
            try:
                time.sleep(0.025)
                return original(*args, **kwargs)
            finally:
                with guard:
                    completed += 1
                    active -= 1

        original_activate = self.engine.restart_3proxy

        def activate():
            self.assertEqual(completed, 35)
            self.assertEqual(active, 0)
            return original_activate()

        with patch.object(self.net, 'probe_ipv6_egress', side_effect=probe), \
                patch.object(self.engine, 'restart_3proxy', side_effect=activate):
            result = self.generate(count=35)
        self.assertTrue(result['success'])
        self.assertEqual(peak, VERIFY_WORKERS)
        self.assertEqual(ALIAS_BATCH_SIZE, 16)
        names = self.names()
        self.assertEqual(names[:names.index('dad')].count('add'), 16)
        add_indices = [i for i, name in enumerate(names) if name == 'add']
        self.assertEqual(names[:add_indices[16]].count('probe'), 16)
        self.assertEqual(names[:add_indices[32]].count('probe'), 32)
        progress = self.service.dispatch('status', {})['progress']
        self.assertEqual((progress['total'], progress['added'], progress['ready'], progress['verified']), (35, 35, 35, 35))
        self.assertEqual(progress['stage'], 'complete')
        self.assertFalse(progress['active'])

    def test_status_proxies_and_health_remain_responsive_during_manual_build(self):
        self.generate()
        old = self.store.read()['proxies']
        self.service.dispatch('health', {})  # Populate verified process/metrics cache.
        entered, release = threading.Event(), threading.Event()
        guard = threading.Lock()
        count = 0

        def probe(*args, **kwargs):
            nonlocal count
            with guard:
                count += 1
                if count == VERIFY_WORKERS:
                    entered.set()
            if not release.wait(30):
                raise RuntimeError('fixture timeout')
            return {'success': True}

        with patch.object(self.net, 'probe_ipv6_egress', side_effect=probe):
            building, results, errors = self.background(lambda: self.generate(count=16, recreate=True))
            try:
                self.assertTrue(entered.wait(15), f'Build failed before verifier barrier: {errors!r}')
                with patch.object(self.engine, 'running_instances', side_effect=AssertionError('hot reader touched engine')), \
                        patch.object(self.net, 'get_ipv6_addresses', side_effect=AssertionError('hot reader touched NIC')), \
                        patch.object(self.net, 'observe_ndp', side_effect=AssertionError('hot reader touched NDP')):
                    begin = time.monotonic()
                    status = self.service.dispatch('status', {})
                    proxies = self.service.dispatch('proxies', {})
                    health = self.service.dispatch('health', {})
                    self.assertLess(time.monotonic() - begin, 0.5)
                    self.assertEqual(proxies['proxies'], old)
                    self.assertFalse(health['ready'])
                    self.assertEqual(health['metrics']['ndp']['neighbor_count'], 1)
                    self.assertEqual(status['progress']['stage'], 'verifying')
                    self.assertEqual(status['progress']['added'], 16)
                    self.assertEqual(status['progress']['ready'], 8)
                    self.assertEqual(status['progress']['verified'], 0)
                    self.assertTrue(status['progress']['active'])
                    self.assertEqual(status['observation'], 'cached_during_mutation')
                    elapsed = status['progress']['elapsed_seconds']
                    time.sleep(0.01)
                    self.assertGreater(self.service.dispatch('status', {})['progress']['elapsed_seconds'], elapsed)
            finally:
                release.set()
                building.join(30)
            self.assertFalse(building.is_alive())
            self.assertEqual(errors, [])
            self.assertTrue(results[0]['success'])

    def test_failure_joins_all_inflight_jobs_before_rollback_and_never_activates(self):
        entered, failure_seen, release = threading.Event(), threading.Event(), threading.Event()
        guard = threading.Lock()
        active = 0
        first = []
        original_remove = self.net.bulk_remove_ipv6

        def probe(address, *args, **kwargs):
            nonlocal active
            with guard:
                if not first:
                    first.append(address)
                active += 1
                if active == VERIFY_WORKERS:
                    entered.set()
            try:
                self.assertTrue(entered.wait(15))
                if address == first[0]:
                    failure_seen.set()
                    return {'success': False}
                self.assertTrue(release.wait(30))
                return {'success': True}
            finally:
                with guard:
                    active -= 1

        def remove(*args, **kwargs):
            self.assertEqual(active, 0, 'cleanup raced a running source verifier')
            return original_remove(*args, **kwargs)

        with patch.object(self.net, 'probe_ipv6_egress', side_effect=probe), \
                patch.object(self.net, 'bulk_remove_ipv6', side_effect=remove):
            building, results, errors = self.background(lambda: self.generate(count=16))
            try:
                self.assertTrue(failure_seen.wait(15))
                time.sleep(0.15)
                self.assertTrue(building.is_alive())
                self.assertNotIn('remove', self.names())
                self.assertNotIn('activate', self.names())
                self.assertEqual(self.store.read()['proxies'], [])
            finally:
                release.set()
                building.join(30)
        self.assertEqual(results, [])
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], OperationError)
        self.assertEqual(len(self.net.aliases), 0)
        state = self.store.read()
        self.assertIsNone(state['pending_operation'])
        self.assertEqual(state['uncertain_addresses'], [])
        self.assertNotIn('activate', self.names())
        progress = self.service.dispatch('status', {})['progress']
        self.assertTrue(progress['failed'])
        self.assertEqual(progress['stage'], 'failed')
        self.assertFalse(progress['active'])

    def test_stop_is_durable_before_verifiers_join_and_no_late_activation(self):
        entered, release = threading.Event(), threading.Event()
        guard = threading.Lock()
        started = 0

        def probe(*args, **kwargs):
            nonlocal started
            with guard:
                started += 1
                if started == VERIFY_WORKERS:
                    entered.set()
            self.assertTrue(release.wait(30))
            return {'success': True}

        with patch.object(self.net, 'probe_ipv6_egress', side_effect=probe):
            building, results, errors = self.background(lambda: self.generate(count=32))
            stopping = None
            try:
                self.assertTrue(entered.wait(15))
                stopping, stop_results, stop_errors = self.background(lambda: self.service.dispatch('stop', {}))
                self.assertTrue(self.service.cancel_operation.wait(5))
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    if self.store.read()['manual_stop']:
                        break
                    time.sleep(0.01)
                state = self.store.read()
                self.assertTrue(state['manual_stop'])
                self.assertEqual(state['desired_state'], 'stopped')
                self.assertTrue(stopping.is_alive())
                self.assertNotIn('activate', self.names())
            finally:
                release.set()
                building.join(30)
                if stopping is not None:
                    stopping.join(30)
        self.assertEqual(results, [])
        self.assertEqual(len(errors), 1)
        self.assertEqual(stop_errors, [])
        self.assertTrue(stop_results[0]['success'])
        self.assertLessEqual(started, VERIFY_WORKERS)
        self.assertFalse(self.engine.running)
        self.assertNotIn('activate', self.names())
        progress = self.service.dispatch('status', {})['progress']
        self.assertEqual(progress['stage'], 'canceled')
        self.assertFalse(progress['failed'])
        self.service.reconcile()
        self.assertEqual(self.store.read()['managed_addresses'], [])
        self.assertEqual(self.net.aliases, {})
        self.assertTrue(self.store.read()['manual_stop'])

    def test_source_probe_receives_exact_alias_and_requested_limits(self):
        with patch.object(self.net, 'probe_ipv6_egress', wraps=self.net.probe_ipv6_egress) as probe:
            self.generate(count=20, probe_timeout=9)
        self.assertEqual(probe.call_count, 20)
        for call in probe.call_args_list:
            self.assertEqual(call.kwargs['expected_address'], call.args[0])
            self.assertEqual(call.kwargs['timeout'], 9)
            self.assertEqual(call.args[1], 'eth0')

    def test_progress_cleanup_snapshot_does_not_call_engine_or_nic(self):
        self.generate()
        state = self.store.read()
        state['managed_addresses'][0]['active'] = False
        self.store.write(state)
        entered, release = threading.Event(), threading.Event()
        remove = self.net.bulk_remove_ipv6

        def blocked_remove(*args, **kwargs):
            entered.set()
            self.assertTrue(release.wait(30))
            return remove(*args, **kwargs)

        with patch.object(self.net, 'bulk_remove_ipv6', side_effect=blocked_remove):
            cleaning, results, errors = self.background(lambda: self.service.dispatch('cleanup', {}))
            try:
                self.assertTrue(entered.wait(15))
                with patch.object(self.engine, 'running_instances', side_effect=AssertionError('read touched engine')):
                    self.assertEqual(self.service.dispatch('status', {})['progress']['stage'], 'cleaning')
                    self.assertTrue(self.service.dispatch('proxies', {})['progress']['active'])
                    self.assertFalse(self.service.dispatch('health', {})['ready'])
            finally:
                release.set()
                cleaning.join(30)
        self.assertFalse(cleaning.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results[0]['removed'], 1)

    def test_second_batch_failure_rolls_back_confirmed_aliases_from_all_batches(self):
        count = 0
        guard = threading.Lock()

        def probe(*args, **kwargs):
            nonlocal count
            with guard:
                count += 1
                return {'success': count <= ALIAS_BATCH_SIZE}

        with patch.object(self.net, 'probe_ipv6_egress', side_effect=probe):
            with self.assertRaises(OperationError):
                self.generate(count=40)
        self.assertEqual(self.names().count('add'), 32)
        self.assertEqual(self.names().count('remove'), 32)
        self.assertEqual(self.net.aliases, {})
        self.assertNotIn('activate', self.names())

    def test_no_created_callback_never_becomes_cleanup_ownership(self):
        def add(addresses, interface, prefix_len=128, **kwargs):
            return [{'address': addresses[0], 'success': True, 'created': True}]

        with patch.object(self.net, 'bulk_add_ipv6', side_effect=add):
            with self.assertRaisesRegex(OperationError, 'durable kernel creation callback'):
                self.generate(count=16)
        self.assertNotIn('remove', self.names())
        self.assertEqual(self.store.read()['managed_addresses'], [])
        self.assertEqual(len(self.store.read()['uncertain_addresses']), 1)

    def test_idle_status_uses_cache_and_deep_health_refreshes_it(self):
        self.generate()
        with patch.object(self.engine, 'running_instances', side_effect=AssertionError('status touched engine')), \
                patch.object(self.net, 'get_ipv6_addresses', side_effect=AssertionError('status touched NIC')), \
                patch.object(self.net, 'observe_ndp', side_effect=AssertionError('status touched NDP')):
            status = self.service.dispatch('status', {})
        self.assertTrue(status['proxy_running'])
        self.assertEqual(status['observation'], 'cached')
        self.assertGreater(status['processes']['observed_at'], 0)
        # A cached status is not fresh proof: deep health observes process loss.
        self.engine.running = False
        self.assertTrue(self.service.dispatch('status', {})['proxy_running'])
        self.assertFalse(self.service.dispatch('health', {})['ready'])
        self.assertFalse(self.service.dispatch('status', {})['proxy_running'])
        self.service.dispatch('stop', {})
        self.assertFalse(self.service.dispatch('status', {})['proxy_running'])


if __name__ == '__main__':
    unittest.main()
