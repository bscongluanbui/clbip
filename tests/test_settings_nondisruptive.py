"""Settings changes preserve active tunnels unless rendered listener inputs change."""
import copy
import unittest
from unittest.mock import Mock, patch

import test_service as fixtures
from host_control import HostControlError
from service import OperationError
from validation import ValidationError


class FakeHostControl:
    def __init__(self, events, limit=4096):
        self.events = events
        self.limit = limit
        self.fail_apply = False
        self.fail_restore = False
        self.wrong_confirmation = False

    def apply_limit(self, limit):
        self.events.append(('host_apply', limit))
        if self.fail_apply:
            raise OperationError('fixture host update failed')
        previous, self.limit = self.limit, limit
        return {'previous_limit': previous,
                'effective_limit': limit + 1 if self.wrong_confirmation else limit}

    def restore_limit(self, limit):
        self.events.append(('host_restore', limit))
        if self.fail_restore:
            raise OperationError('fixture host restore failed')
        self.limit = limit
        return {'effective_limit': limit}


class SettingsNondisruptiveTests(unittest.TestCase):
    tearDown = fixtures.ServiceTests.tearDown
    names = fixtures.ServiceTests.names
    generate = fixtures.ServiceTests.generate

    def setUp(self):
        fixtures.ServiceTests.setUp(self)
        self.host = FakeHostControl(self.events)
        self.service.host_control = self.host
        self.generate(count=2)
        state = self.store.read()
        state['rotation_due'] = 1234567890
        state['last_error'] = 'fixture observation still pending'
        self.store.write(state)
        self.events.clear()

    def save(self, params):
        return self.service.dispatch('save_settings', params)

    def assert_no_engine_mutation(self):
        self.assertFalse(set(self.names()) & {'config', 'snapshot_config', 'save_config',
                         'activate', 'start', 'stop', 'rollback_config', 'add', 'remove'})

    def assert_pool_preserved(self, before):
        state = self.store.read()
        for key in ('proxies', 'managed_addresses', 'users', 'desired_state', 'manual_stop',
                    'pending_operation', 'uncertain_addresses', 'prefix_state', 'startup_recovery'):
            self.assertEqual(state[key], before[key], key)
        self.assertTrue(self.engine.running)

    def test_empty_patch_is_exact_noop_without_store_write(self):
        before = self.store.read()
        with patch.object(self.store, 'write', wraps=self.store.write) as write:
            result = self.save({})
        write.assert_not_called()
        self.assertFalse(result['changed'])
        self.assertFalse(result['restarted'])
        self.assertEqual(result['revision'], before['revision'])
        self.assertEqual(self.store.read(), before)
        self.assertEqual(self.events, [])

    def test_full_unchanged_form_is_noop_and_preserves_observation(self):
        before = self.store.read()
        result = self.save(copy.deepcopy(before['settings']))
        self.assertFalse(result['changed'])
        self.assertEqual(self.store.read(), before)
        self.assert_no_engine_mutation()
        self.assertNotIn('host_apply', self.names())

    def test_noop_with_new_idempotency_key_does_not_write_request_journal(self):
        before = self.store.read()
        result = self.save({'_idempotency_key': 'settings-noop-1'})
        self.assertFalse(result['changed'])
        self.assertEqual(self.store.read(), before)

    def test_existing_idempotency_key_conflict_still_rejected_for_noop(self):
        self.save({'telegram_chat_id': '123', '_idempotency_key': 'control-1'})
        with self.assertRaises(ValidationError):
            self.save({'_idempotency_key': 'control-1'})

    def test_telegram_save_is_single_commit_preserving_pool_and_rotation_due(self):
        before = self.store.read()
        config = copy.deepcopy(self.engine.config)
        with patch.object(self.store, 'write', wraps=self.store.write) as write:
            result = self.save({'telegram_chat_id': '123', 'telegram_bot_token': 'fixture-token'})
        self.assertEqual(write.call_count, 1)
        self.assertTrue(result['changed'])
        self.assertFalse(result['restarted'])
        self.assertFalse(result['engine_config_changed'])
        self.assert_pool_preserved(before)
        self.assertEqual(self.engine.config, config)
        state = self.store.read()
        self.assertEqual(state['rotation_due'], before['rotation_due'])
        self.assertEqual(state['last_error'], before['last_error'])
        self.assertEqual(state['events'][-1]['result'], 'updated_without_activation')
        self.assertNotIn('telegram_bot_token', result['settings'])
        self.assert_no_engine_mutation()

    def test_control_save_does_not_cleanup_retired_owned_alias(self):
        state = self.store.read()
        retired = copy.deepcopy(state['managed_addresses'][0])
        retired.update(address=fixtures.POOL + 'ffff', active=False)
        state['managed_addresses'].append(retired)
        self.store.write(state)
        before = self.store.read()
        self.events.clear()
        self.save({'probe_timeout': 12})
        self.assert_pool_preserved(before)
        self.assert_no_engine_mutation()

    def test_generation_and_observation_defaults_do_not_restart_existing_pool(self):
        changes = {'subnet': '2606:4700:9::', 'prefix_len': 65, 'interface': 'eth1',
                   'start_port': 11000, 'protocol': 'dual', 'topology_mode': 'routed',
                   'routed_prefix': '2606:4700:9::/48', 'probe_timeout': 12,
                   'probe_url': 'https://example.com', 'auto_start': True,
                   'startup_proxy_count': 31, 'startup_rebuild_enabled': True,
                   'source_poll_interval': 10, 'source_change_confirmations': 3}
        for name, value in changes.items():
            before = self.store.read()
            self.events.clear()
            with self.subTest(name=name):
                result = self.save({name: value})
                self.assertFalse(result['restarted'])
                self.assert_pool_preserved(before)
                self.assertEqual(self.store.read()['rotation_due'], before['rotation_due'])
                self.assert_no_engine_mutation()

    def test_rotation_controls_reschedule_only_when_changed_without_restart(self):
        before = self.store.read()
        with patch('service.time.time', return_value=1000):
            self.save({'rotation_enabled': True, 'rotation_interval': 20})
        self.assertEqual(self.store.read()['rotation_due'], 2200)
        self.assert_pool_preserved(before)
        self.assert_no_engine_mutation()
        self.save({'rotation_enabled': False})
        self.assertEqual(self.store.read()['rotation_due'], 0)
        self.assert_no_engine_mutation()

    def test_engine_fields_take_existing_transaction_and_preserve_rotation_deadline(self):
        changes = {'dns1': '9.9.9.9', 'dns2': '8.8.4.4', 'dns3': '1.0.0.1',
                   'timeout_connect': 15, 'timeout_idle': 180, 'max_connections': 80,
                   'log_enabled': False, 'listener_ipv4': '0.0.0.0',
                   'allow_private_destinations': True}
        for name, value in changes.items():
            before = self.store.read()
            self.events.clear()
            with self.subTest(name=name):
                result = self.save({name: value})
                self.assertTrue(result['restarted'])
                self.assertTrue(result['engine_config_changed'])
                self.assertIn('snapshot_config', self.names())
                self.assertIn('activate', self.names())
                self.assertEqual(self.store.read()['rotation_due'], before['rotation_due'])
                self.assertEqual(self.store.read()['proxies'], before['proxies'])

    def test_whitelist_ignored_by_non_ip_mode_does_not_restart(self):
        self.save({'allowed_ips': ['192.168.1.0/24']})
        self.assert_no_engine_mutation()
        result = self.save({'auth_type': 'ip'})
        self.assertTrue(result['restarted'])
        self.events.clear()
        result = self.save({'allowed_ips': ['192.168.2.0/24']})
        self.assertTrue(result['restarted'])
        self.assertIn('activate', self.names())

    def test_public_flag_without_auth_change_does_not_restart(self):
        result = self.save({'public_proxy': True})
        self.assertFalse(result['restarted'])
        self.assert_no_engine_mutation()

    def test_invalid_public_mode_rejected_before_engine_or_host_mutation(self):
        before = self.store.read()
        with self.assertRaises(ValueError):
            self.save({'auth_type': 'none', 'public_proxy': False, 'thread_limit': 8192})
        self.assertEqual(self.store.read(), before)
        self.assert_no_engine_mutation()
        self.assertNotIn('host_apply', self.names())

    def test_control_only_save_on_stopped_pool_never_activates_it(self):
        self.service.dispatch('stop', {})
        before = self.store.read()
        self.events.clear()
        result = self.save({'probe_timeout': 12})
        self.assertFalse(result['restarted'])
        self.assertEqual(self.store.read()['desired_state'], 'stopped')
        self.assertEqual(self.store.read()['proxies'], before['proxies'])
        self.assertFalse(self.engine.running)
        self.assert_no_engine_mutation()

    def recovery(self):
        state = self.store.read()
        state['settings']['startup_rebuild_enabled'] = True
        state['startup_recovery'] = {'state': 'waiting', 'phase': 'waiting_network'}
        self.store.write(state)
        self.engine.running = False
        self.events.clear()
        return self.store.read()

    def test_recovery_engine_and_control_changes_remain_queued_without_activation(self):
        before = self.recovery()
        result = self.save({'dns1': '9.9.9.9', 'telegram_chat_id': '123'})
        self.assertTrue(result['queued'])
        self.assertFalse(result['restarted'])
        self.assertEqual(self.store.read()['managed_addresses'], before['managed_addresses'])
        self.assert_no_engine_mutation()

    def test_recovery_disable_and_engine_change_keeps_old_pool_stopped(self):
        before = self.recovery()
        result = self.save({'startup_rebuild_enabled': False, 'dns1': '9.9.9.9'})
        state = self.store.read()
        self.assertTrue(result['queued'])
        self.assertFalse(result['restarted'])
        self.assertIsNone(state['startup_recovery'])
        self.assertTrue(state['manual_stop'])
        self.assertEqual(state['desired_state'], 'stopped')
        self.assertEqual(state['proxies'], before['proxies'])
        self.assert_no_engine_mutation()

    def test_ownership_review_guard_still_rejects_settings_save(self):
        state = self.store.read()
        state['uncertain_addresses'] = [{'address': fixtures.POOL + 'abcd'}]
        self.store.write(state)
        with self.assertRaises(OperationError):
            self.save({'telegram_chat_id': '123'})
        self.assert_no_engine_mutation()

    def test_thread_limit_change_is_confirmed_before_single_settings_commit(self):
        before = self.store.read()
        original_write = self.store.write
        def write(state):
            self.events.append(('settings_write', state['settings']['thread_limit']))
            return original_write(state)
        with patch.object(self.store, 'write', side_effect=write):
            result = self.save({'thread_limit': 8192})
        self.assertTrue(result['thread_limit_applied'])
        self.assertEqual(result['effective_thread_limit'], 8192)
        self.assertFalse(result['restarted'])
        self.assertLess(self.names().index('host_apply'), self.names().index('settings_write'))
        self.assertEqual(self.host.limit, 8192)
        self.assert_pool_preserved(before)
        self.assert_no_engine_mutation()

    def test_unchanged_thread_limit_never_requires_host_controller(self):
        self.host.fail_apply = True
        self.save({'thread_limit': 4096, 'telegram_chat_id': '123'})
        self.assertNotIn('host_apply', self.names())
        self.assert_no_engine_mutation()

    def test_host_apply_failure_keeps_settings_and_pool_unchanged(self):
        before = self.store.read()
        self.host.fail_apply = True
        with self.assertRaises(OperationError):
            self.save({'thread_limit': 8192, 'telegram_chat_id': '123'})
        self.assertEqual(self.store.read(), before)
        self.assert_no_engine_mutation()

    def test_host_headroom_error_is_visible_without_changing_state(self):
        before = self.store.read()
        with patch.object(self.host, 'apply_limit', side_effect=HostControlError('Trần thread cần ít nhất 3264')):
            with self.assertRaisesRegex(OperationError, '3264'):
                self.save({'thread_limit': 3200})
        self.assertEqual(self.store.read(), before)
        self.assert_no_engine_mutation()

    def test_wrong_limit_confirmation_rolls_back_without_state_commit(self):
        before = self.store.read()
        self.host.wrong_confirmation = True
        with self.assertRaises(OperationError):
            self.save({'thread_limit': 8192})
        self.assertEqual(self.store.read(), before)
        self.assertEqual(self.host.limit, 4096)
        self.assertIn('host_restore', self.names())
        self.assert_no_engine_mutation()

    def test_settings_commit_failure_restores_previous_live_limit(self):
        before = self.store.read()
        with patch.object(self.store, 'write', side_effect=RuntimeError('fixture commit failed')):
            with self.assertRaises(RuntimeError):
                self.save({'thread_limit': 8192})
        self.assertEqual(self.store.read(), before)
        self.assertEqual(self.host.limit, 4096)
        self.assertIn('host_restore', self.names())
        self.assert_no_engine_mutation()

    def test_mixed_engine_failure_restores_limit_config_and_settings(self):
        before = self.store.read()
        original_config = copy.deepcopy(self.engine.config)
        self.engine.fail_restart_once = True
        with self.assertRaises(OperationError):
            self.save({'thread_limit': 8192, 'dns1': '9.9.9.9', 'telegram_chat_id': '123'})
        self.assertEqual(self.store.read()['settings'], before['settings'])
        self.assertEqual(self.store.read()['proxies'], before['proxies'])
        self.assertEqual(self.engine.config, original_config)
        self.assertEqual(self.host.limit, 4096)
        self.assertIn('rollback_config', self.names())
        self.assertIn('host_restore', self.names())

    def test_thread_limit_restore_failure_is_reported(self):
        self.host.fail_restore = True
        with patch.object(self.store, 'write', side_effect=RuntimeError('fixture commit failed')):
            with self.assertRaisesRegex(OperationError, 'trần thread'):
                self.save({'thread_limit': 8192})

    def test_live_unlimited_baseline_restores_max_on_commit_failure(self):
        self.host.limit = 'max'
        with patch.object(self.store, 'write', side_effect=RuntimeError('fixture commit failed')):
            with self.assertRaises(RuntimeError):
                self.save({'thread_limit': 8192})
        self.assertEqual(self.host.limit, 'max')
        self.assertIn(('host_restore', 'max'), self.events)

    def test_mixed_engine_rotation_change_uses_new_schedule(self):
        with patch('service.time.time', return_value=1000):
            result = self.save({'dns1': '9.9.9.9', 'rotation_enabled': True,
                                'rotation_interval': 20, 'telegram_chat_id': '123'})
        self.assertTrue(result['restarted'])
        self.assertEqual(self.store.read()['rotation_due'], 2200)
        self.events.clear()
        self.save({'dns1': '1.0.0.1', 'rotation_enabled': False})
        self.assertEqual(self.store.read()['rotation_due'], 0)

    def test_engine_edit_on_stopped_pool_never_restarts(self):
        self.service.dispatch('stop', {})
        self.events.clear()
        result = self.save({'dns1': '9.9.9.9'})
        self.assertFalse(result['restarted'])
        self.assertTrue(result['engine_config_changed'])
        self.assertIn('save_config', self.names())
        self.assertIn('stop', self.names())
        self.assertNotIn('activate', self.names())
        self.assertEqual(self.store.read()['desired_state'], 'stopped')

    def test_recovery_control_and_thread_save_preserves_progress_and_does_not_clear_error(self):
        before = self.recovery()
        result = self.save({'thread_limit': 8192, 'telegram_chat_id': '123'})
        state = self.store.read()
        self.assertTrue(result['queued'])
        self.assertFalse(result['restarted'])
        self.assertEqual(state['startup_recovery'], before['startup_recovery'])
        self.assertEqual(state['last_error'], before['last_error'])
        self.assertEqual(state['rotation_due'], before['rotation_due'])
        self.assert_no_engine_mutation()

    def test_postcommit_cleanup_failure_keeps_committed_live_limit(self):
        with patch.object(self.service, '_remove_owned', side_effect=RuntimeError('fixture cleanup failed')):
            with self.assertRaises(RuntimeError):
                self.save({'thread_limit': 8192, 'dns1': '9.9.9.9'})
        self.assertEqual(self.store.read()['settings']['thread_limit'], 8192)
        self.assertEqual(self.store.read()['settings']['dns1'], '9.9.9.9')
        self.assertEqual(self.host.limit, 8192)
        self.assertNotIn('host_restore', self.names())

    def test_status_refreshes_resource_sampler_without_engine_or_network_calls(self):
        self.service.cached_metrics = {'proxy_children': {'rss_bytes': 99}}
        self.service.metrics_sampler = Mock()
        self.service.metrics_sampler.collect.side_effect = [
            {'threads': {'current': 1000}}, {'threads': {'current': 1500}}]
        with (patch.object(self.engine, 'running_instances', side_effect=AssertionError('engine command')),
              patch.object(self.net, 'observe_ndp', side_effect=AssertionError('network command'))):
            first = self.service.status({})
            second = self.service.status({})
        self.assertEqual(first['metrics']['resources']['threads']['current'], 1000)
        self.assertEqual(second['metrics']['resources']['threads']['current'], 1500)
        self.service.metrics_sampler.collect.assert_called_with(proxies=self.store.read()['proxies'],
            engine_metrics={'rss_bytes': 99}, configured_limit=4096)
        self.assertEqual(self.service.cached_metrics, {'proxy_children': {'rss_bytes': 99}})

    def test_resource_controller_observation_uses_status_when_supported(self):
        self.host.status = Mock(return_value={'available': True, 'effective_limit': 4096})
        result = self.service.status({})
        self.assertEqual(result['metrics']['resources']['host_control']['effective_limit'], 4096)
        self.host.status.assert_called_once_with()

    def test_unavailable_unix_socket_platform_keeps_status_readable(self):
        self.host.status = Mock(side_effect=AttributeError('AF_UNIX unavailable'))
        result = self.service.status({})
        self.assertFalse(result['metrics']['resources']['host_control']['available'])
        self.assertIsNone(result['metrics']['resources']['host_control']['effective_limit'])


if __name__ == '__main__':
    unittest.main()
