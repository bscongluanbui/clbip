"""Offline config/lifecycle regressions: no real process signals or IP changes."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import shutil
import unittest
import uuid
from unittest.mock import Mock, patch

import proxy_config as pc

USER = {'username': 'tester', 'password': 'Only_Test_42!'}
PROXY = {'ipv6': '2001:db8::10', 'port': 10000, 'protocol': 'http'}
SETTINGS = {'auth_type': 'userpass', 'log_enabled': False}


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(__file__).resolve().parent / ('.tmp_proxy_' + uuid.uuid4().hex)
        self.directory.mkdir()
        self.patches = [patch.object(pc, 'DATA_DIR', str(self.directory)),
                        patch.object(pc, 'PROXIES_PER_INSTANCE', 2),
                        patch.dict(os.environ, {'MAX_TOTAL_CONNECTIONS': '65536', 'MAX_PROXY_SERVICES': '1024'})]
        for context in self.patches:
            context.start()

    def tearDown(self):
        for context in reversed(self.patches):
            context.stop()
        root = Path(__file__).resolve().parent
        assert self.directory.resolve().is_relative_to(root)
        shutil.rmtree(self.directory)

    def validate(self, proxies=None, users=None, settings=None):
        return pc.validate_config_inputs(proxies if proxies is not None else [PROXY],
                                         users if users is not None else [USER],
                                         {**SETTINGS, **(settings or {})})

    def test_fail_closed_auth(self):
        for users, settings in [([], {'auth_type': 'userpass'}), ([], {'auth_type': 'ip'}),
                                ([], {'auth_type': 'none'}), ([USER], {'auth_type': 'typo'})]:
            with self.subTest(settings=settings), self.assertRaises(ValueError):
                self.validate(users=users, settings=settings)

    def test_injection_rejected_in_every_config_field(self):
        for key in ('dns1', 'dns2', 'dns3', 'listener_ipv4', 'timeout_connect', 'timeout_idle', 'max_connections'):
            with self.subTest(field=key), self.assertRaises(ValueError):
                self.validate(settings={key: '1\nallow *'})
        for key in ('username', 'password'):
            for value in ('name\nauth none', '$/etc/passwd', 'bad:token', 'bad token', '"quote"'):
                with self.subTest(field=key, value=value), self.assertRaises(ValueError):
                    self.validate(users=[{**USER, key: value}])

    def test_auth_booleans_are_not_coerced(self):
        for key in ('public_proxy', 'log_enabled', 'allow_private_destinations'):
            with self.subTest(field=key), self.assertRaises(ValueError):
                self.validate(settings={key: 'false'})

    def test_cidr_allowlist(self):
        config = pc._generate_single_config([PROXY], [], {'auth_type': 'ip', 'allowed_ips': ['192.0.2.3/24'], 'log_enabled': False})
        self.assertIn('allow * 192.0.2.0/24\ndeny *', config)
        for value in ([], ['0.0.0.0/0'], ['not-an-ip'], '192.0.2.0/24', ['192.0.2.1\nallow *']):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validate(users=[], settings={'auth_type': 'ip', 'allowed_ips': value})

    def test_public_keeps_destination_acl(self):
        config = pc._generate_single_config([PROXY], [], {'auth_type': 'none', 'public_proxy': True, 'log_enabled': False})
        self.assertIn('auth iponly', config)  # auth none would skip all ACLs.
        self.assertNotIn('auth none\n', config)
        self.assertIn('deny * * ' + pc.PRIVATE_DESTINATIONS, config)
        self.assertLess(config.index('deny * *'), config.index('allow *\n'))

    def test_private_destinations_require_explicit_boolean(self):
        config = pc._generate_single_config([PROXY], [USER], {**SETTINGS, 'allow_private_destinations': True})
        self.assertNotIn('deny * *', config)

    def test_timeouts_ipv6_cache_and_service_connection_limit(self):
        config = pc._generate_single_config([PROXY], [USER], {**SETTINGS, 'timeout_connect': 17, 'timeout_idle': 400, 'max_connections': 23})
        self.assertIn('timeouts 1 5 30 60 400 400 15 60 17 5', config)
        self.assertIn('nscache6 65536', config)
        self.assertIn('maxconn 23', config)
        self.assertIn('internal 127.0.0.1', config)
        self.assertNotIn('\ndaemon\n', config)

    def test_dns_port_and_shared_credential_policy(self):
        password = 'A/b;c<d>(e)[f]{g}!@%=+?~-' * 8
        config = pc._generate_single_config([PROXY], [{**USER, 'password': password}], {**SETTINGS, 'dns1': '127.0.0.1:5353', 'dns2': '2001:4860:4860::8888'})
        self.assertIn('nserver 127.0.0.1:5353', config)
        self.assertIn('nserver 2001:4860:4860::8888', config)
        self.assertIn(':CL:' + password, config)
        for bad in ('127.0.0.1:0', '127.0.0.1:65536', '127.0.0.1:53/tcp', '127.0.0.1:bad', 'fe80::1%eth0'):
            with self.subTest(dns=bad), self.assertRaises(ValueError):
                self.validate(settings={'dns1': bad})

    def test_logging_stays_enabled_at_large_instance_counts(self):
        config = pc._generate_single_config([PROXY], [USER], {'auth_type': 'userpass', 'log_enabled': True}, 3, 10)
        self.assertIn('logs/3proxy_3.log D', config)
        self.assertNotIn('log /dev/null', config)

    def test_protocol_port_and_address_validation(self):
        for overrides in ({'protocol': 'oops'}, {'port': 70000}, {'port': True}, {'port': 80},
                          {'ipv6': '127.0.0.1'}, {'ipv6': 'fe80::1'}, {'ipv6': 'ff02::1'},
                          {'ipv6': '::1'}, {'ipv6': '::'}, {'protocol': 'dual', 'socks_port': 10000}):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                self.validate(proxies=[{**PROXY, **overrides}])
        with self.assertRaises(ValueError):
            self.validate(proxies=[PROXY, {**PROXY, 'ipv6': '2001:db8::11'}])

    def test_resource_budget_counts_dual_listeners(self):
        with patch.dict(os.environ, {'MAX_TOTAL_CONNECTIONS': '127'}), self.assertRaises(ValueError):
            self.validate(proxies=[{**PROXY, 'protocol': 'dual'}])
        with patch.object(pc, 'PROXIES_PER_INSTANCE', 0), self.assertRaises(ValueError):
            self.validate()

    def test_resource_budget_enforces_per_process_file_descriptors(self):
        proxies = [{**PROXY, 'port': 10000 + i} for i in range(32)]
        with patch.object(pc, 'PROXIES_PER_INSTANCE', 32), self.assertRaises(ValueError):
            self.validate(proxies=proxies, settings={'max_connections': 2000})
        with patch.object(pc, 'PROXIES_PER_INSTANCE', 8):
            self.validate(proxies=proxies, settings={'max_connections': 2000})
        with patch.dict(os.environ, {'PROXY_NOFILE_LIMIT': '256'}), self.assertRaises(ValueError):
            self.validate()

    def test_validation_is_pure(self):
        proxies, users, settings = [copy.deepcopy(PROXY)], [copy.deepcopy(USER)], dict(SETTINGS)
        original = copy.deepcopy((proxies, users, settings))
        pc.validate_config_inputs(proxies, users, settings)
        self.assertEqual((proxies, users, settings), original)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_staged_generation_and_restore(self):
        first = pc.generate_config([PROXY], [USER], SETTINGS)
        pc.save_config(first)
        snapshot = pc.snapshot_configs()
        first_path = pc._instance_config_path(0)
        pc.generate_config([{**PROXY, 'port': 10001}], [USER], SETTINGS)
        self.assertNotEqual(pc._instance_config_path(0), first_path)
        pc.restore_configs(snapshot)
        self.assertEqual(pc._instance_config_path(0), first_path)
        self.assertEqual(pc.snapshot_configs(), snapshot)

    def test_invalid_generation_keeps_active_config(self):
        pc.generate_config([PROXY], [USER], SETTINGS)
        previous = pc.snapshot_configs()
        with self.assertRaises(ValueError):
            pc.generate_config([PROXY], [], SETTINGS)
        self.assertEqual(pc.snapshot_configs(), previous)

    def test_write_failure_keeps_manifest(self):
        pc.generate_config([PROXY], [USER], SETTINGS)
        snapshot = pc.snapshot_configs()
        original = pc._atomic_write
        count = 0
        def fail_second(path, text):
            nonlocal count
            count += 1
            if count == 2:
                raise OSError('simulated write failure')
            return original(path, text)
        proxies = [{**PROXY, 'port': 10000 + i} for i in range(3)]
        with patch.object(pc, '_atomic_write', side_effect=fail_second), self.assertRaises(OSError):
            pc.generate_config(proxies, [USER], SETTINGS)
        self.assertEqual(pc.snapshot_configs(), snapshot)

    def test_zero_proxies_retires_previous_generation(self):
        pc.generate_config([PROXY], [USER], SETTINGS)
        pc.generate_config([], [], SETTINGS)
        self.assertEqual(pc._get_instance_count(), 0)
        self.assertFalse(pc.start_3proxy()[0])

    def test_bounded_config_retention_protects_rollback_generation(self):
        pc.generate_config([PROXY], [USER], SETTINGS)
        snapshot = pc.snapshot_configs()
        protected = json.loads(snapshot['manifest'])['generation']
        for i in range(4):
            pc.generate_config([{**PROXY, 'port': 10001 + i}], [USER], SETTINGS)
        self.assertEqual(pc.prune_configs(retain=2, protected_generations=[protected]), 2)
        pc.restore_configs(snapshot)
        self.assertEqual(pc._get_instance_count(), 1)

    def test_tampered_config_fails_closed(self):
        pc.generate_config([PROXY], [USER], SETTINGS)
        Path(pc._instance_config_path(0)).write_text('auth none\nallow *\n')
        self.assertFalse(pc.running_instances()['ready'])
        self.assertFalse(pc.start_3proxy()[0])
        with self.assertRaises(ValueError):
            pc.snapshot_configs()

    def test_all_instances_and_listeners_required(self):
        pc.generate_config([{**PROXY, 'port': 10000 + i} for i in range(3)], [USER], SETTINGS)
        records = [{'index': i['index'], 'pid': 700 + i['index'], 'config': str(pc._config_location(i))} for i in pc._load_manifest()['instances']]
        with patch.object(pc, '_load_processes', return_value=records), patch.object(pc, '_owns_process', return_value=True), patch.object(pc, '_listener_set', return_value={('127.0.0.1', 10000), ('127.0.0.1', 10001)}):
            health = pc.running_instances()
            self.assertEqual(health['running'], 2)
            self.assertFalse(health['ready'])
            self.assertFalse(pc.is_3proxy_running()[0])
        with patch.object(pc, '_load_processes', return_value=records), patch.object(pc, '_owns_process', return_value=True), patch.object(pc, '_listener_set', return_value={('127.0.0.1', 10000), ('127.0.0.1', 10001), ('127.0.0.1', 10002)}):
            self.assertTrue(pc.running_instances()['ready'])

    def test_empty_manifest_does_not_hide_owned_old_generation(self):
        pc.generate_config([PROXY], [USER], SETTINGS)
        old_config = pc._instance_config_path(0)
        pc.generate_config([], [], SETTINGS)
        record = {'index': 0, 'pid': 800, 'config': old_config}
        with patch.object(pc, '_load_processes', return_value=[record]), patch.object(pc, '_owns_process', return_value=True):
            health = pc.running_instances()
        self.assertEqual(health['expected'], 0)
        self.assertEqual(health['running'], 1)
        self.assertEqual(health['active_running'], 0)
        self.assertEqual(health['orphaned_instances'][0]['pid'], 800)
        self.assertFalse(health['ready'])

    def test_corrupt_manifest_does_not_hide_owned_process(self):
        pc.generate_config([PROXY], [USER], SETTINGS)
        config = pc._instance_config_path(0)
        Path(config).write_text('tampered\n')
        with patch.object(pc, '_load_processes', return_value=[{'index': 0, 'pid': 801, 'config': config}]), patch.object(pc, '_owns_process', return_value=True):
            health = pc.running_instances()
        self.assertEqual(health['running'], 1)
        self.assertTrue(health['errors'])
        self.assertFalse(health['ready'])

    def test_malformed_manifest_fails_as_health_error(self):
        for value in ([], None, {'version': 1, 'instances': [None]}):
            with self.subTest(value=value):
                pc._manifest_path().write_text(json.dumps(value))
                health = pc.running_instances()
                self.assertFalse(health['ready'])
                self.assertTrue(health['errors'])
                self.assertFalse(pc.start_3proxy()[0])

    def test_manifest_empty_listener_list_cannot_be_ready(self):
        pc.generate_config([PROXY], [USER], SETTINGS)
        manifest = pc._load_manifest()
        manifest['instances'][0]['listeners'] = []
        pc._manifest_path().write_text(json.dumps(manifest))
        record = {'index': 0, 'pid': 810, 'config': str(pc._config_location(manifest['instances'][0]))}
        with patch.object(pc, '_load_processes', return_value=[record]), patch.object(pc, '_owns_process', return_value=True), patch.object(pc, '_listener_set', return_value=set()):
            health = pc.running_instances()
        self.assertFalse(health['ready'])
        self.assertTrue(health['errors'])
        self.assertEqual(health['running'], 1)

    def test_invalid_owned_process_entries_fail_closed(self):
        pc.generate_config([PROXY], [USER], SETTINGS)
        for value in ([None], [123], [{}], [{'pid': True}]):
            with self.subTest(value=value):
                pc._process_path().write_text(json.dumps(value))
                health = pc.running_instances()
                self.assertFalse(health['ready'])
                self.assertTrue(health['errors'])
                with patch.object(pc, '_signal_owned') as signal_fn:
                    self.assertFalse(pc.stop_3proxy()[0])
                    signal_fn.assert_not_called()
                self.assertFalse(pc.start_3proxy()[0])

    def test_health_uses_live_record_not_stale_first_match(self):
        pc.generate_config([PROXY], [USER], SETTINGS)
        config = pc._instance_config_path(0)
        records = [{'index': 0, 'pid': 820, 'config': config}, {'index': 0, 'pid': 821, 'config': config}]
        with patch.object(pc, '_load_processes', return_value=records), patch.object(pc, '_owns_process', side_effect=lambda r: r['pid'] == 821), patch.object(pc, '_listener_set', return_value={('127.0.0.1', 10000)}):
            health = pc.running_instances()
        self.assertTrue(health['ready'])
        self.assertEqual(health['running'], 1)
        self.assertEqual(health['instances'][0]['pid'], 821)

    def test_duplicate_live_children_for_same_config_are_unhealthy(self):
        pc.generate_config([PROXY], [USER], SETTINGS)
        config = pc._instance_config_path(0)
        records = [{'index': 0, 'pid': 830, 'config': config}, {'index': 0, 'pid': 831, 'config': config}]
        with patch.object(pc, '_load_processes', return_value=records), patch.object(pc, '_owns_process', return_value=True), patch.object(pc, '_listener_set', return_value={('127.0.0.1', 10000)}):
            health = pc.running_instances()
        self.assertEqual(health['running'], 2)
        self.assertFalse(health['ready'])
        self.assertTrue(health['errors'])

    def test_readiness_rechecks_identity_after_socket_inventory(self):
        pc.generate_config([PROXY], [USER], SETTINGS)
        record = {'index': 0, 'pid': 835, 'config': pc._instance_config_path(0)}
        with patch.object(pc, '_load_processes', return_value=[record]), patch.object(pc, '_owns_process', side_effect=[True, False]), patch.object(pc, '_listener_set', return_value={('127.0.0.1', 10000)}):
            health = pc.running_instances()
        self.assertFalse(health['ready'])
        self.assertFalse(health['instances'][0]['ready'])
        self.assertTrue(health['errors'])

    def test_metrics_count_all_owned_generations_and_skip_unowned(self):
        records = [{'pid': 840, 'config': 'old'}, {'pid': 841, 'config': 'active'}, {'pid': 842, 'config': 'unowned'}]
        with patch.object(pc, '_load_processes', return_value=records), patch.object(pc, '_owns_process', side_effect=lambda r: r['pid'] != 842), patch.object(pc, '_read_process_metrics', side_effect=[{'rss_bytes': 2048, 'fd_count': 4}, {'rss_bytes': 4096, 'fd_count': 8}]) as read:
            metrics = pc.process_metrics()
        self.assertEqual(metrics, {'rss_bytes': 6144, 'fd_count': 12, 'process_count': 2, 'errors': []})
        self.assertEqual([call.args[0] for call in read.call_args_list], [840, 841])
        self.assertNotIn('config', metrics)

    def test_metrics_never_report_partial_totals_as_complete(self):
        records = [{'pid': 850}, {'pid': 851}]
        with patch.object(pc, '_load_processes', return_value=records), patch.object(pc, '_owns_process', return_value=True), patch.object(pc, '_read_process_metrics', side_effect=[{'rss_bytes': 2048, 'fd_count': 4}, PermissionError('secret path')]):
            metrics = pc.process_metrics()
        self.assertIsNone(metrics['rss_bytes'])
        self.assertIsNone(metrics['fd_count'])
        self.assertEqual(metrics['process_count'], 2)
        self.assertTrue(metrics['errors'])
        self.assertNotIn('secret path', json.dumps(metrics))

    def test_metrics_recheck_identity_after_reading_proc(self):
        with patch.object(pc, '_load_processes', return_value=[{'pid': 860}]), patch.object(pc, '_owns_process', side_effect=[True, False]), patch.object(pc, '_read_process_metrics', return_value={'rss_bytes': 1024, 'fd_count': 4}):
            metrics = pc.process_metrics()
        self.assertIsNone(metrics['rss_bytes'])
        self.assertIsNone(metrics['fd_count'])
        self.assertIsNone(metrics['process_count'])
        self.assertTrue(metrics['errors'])

    def test_metrics_absent_processes_are_zero_corrupt_ledger_is_unknown(self):
        self.assertEqual(pc.process_metrics(), {'rss_bytes': 0, 'fd_count': 0, 'process_count': 0, 'errors': []})
        pc._process_path().write_text('[null]')
        metrics = pc.process_metrics()
        self.assertIsNone(metrics['rss_bytes'])
        self.assertIsNone(metrics['fd_count'])
        self.assertIsNone(metrics['process_count'])
        self.assertTrue(metrics['errors'])

    def test_linux_proc_metrics_parse_rss_and_count_descriptors(self):
        root = self.directory / 'proc'
        process = root / '870'
        (process / 'fd').mkdir(parents=True)
        (process / 'status').write_text('Name:\t3proxy\nVmRSS:\t 321 kB\n')
        for fd in ('0', '1', '2', '3'):
            (process / 'fd' / fd).touch()
        with patch.object(pc, 'Path', return_value=root):
            self.assertEqual(pc._read_process_metrics(870), {'rss_bytes': 321 * 1024, 'fd_count': 4})
        (process / 'status').write_text('Name:\t3proxy\n')
        with patch.object(pc, 'Path', return_value=root), self.assertRaises(ValueError):
            pc._read_process_metrics(870)

    def test_reused_pid_is_not_owned(self):
        identity = {'pid': 123, 'start_time': '100', 'exe': os.path.realpath(pc.PROXY_BINARY),
                    'cmdline': [pc.PROXY_BINARY, '/app/data/configs/g/3proxy_0.cfg'], 'boot_id': 'boot'}
        record = dict(identity, config=identity['cmdline'][1], index=0)
        with patch.object(pc, '_read_identity', return_value={**identity, 'start_time': '101'}):
            self.assertFalse(pc._owns_process(record))
        with patch.object(pc, '_read_identity', return_value=identity):
            self.assertTrue(pc._owns_process(record))

    def test_stop_never_signals_unowned_pid(self):
        with patch.object(pc, '_load_processes', return_value=[{'pid': 123}]), patch.object(pc, '_owns_process', return_value=False), patch.object(pc, '_signal_owned') as signal_fn:
            self.assertTrue(pc.stop_3proxy()[0])
            signal_fn.assert_not_called()

    def test_stop_returns_failure_if_signal_fails(self):
        with patch.object(pc, '_load_processes', return_value=[{'pid': 123}]), patch.object(pc, '_owns_process', return_value=True), patch.object(pc, '_signal_owned', side_effect=PermissionError):
            self.assertFalse(pc.stop_3proxy()[0])

    def test_restart_requires_verified_stop(self):
        with patch.object(pc, 'stop_3proxy', return_value=(False, 'still running')), patch.object(pc, 'start_3proxy') as start:
            self.assertEqual(pc.restart_3proxy(), (False, 'still running'))
            start.assert_not_called()

    def test_start_returns_failure_on_partial_readiness(self):
        pc.generate_config([PROXY], [USER], SETTINGS)
        config = pc._instance_config_path(0)
        identity = {'pid': 500, 'start_time': '100', 'exe': os.path.realpath(pc.PROXY_BINARY),
                    'cmdline': [pc.PROXY_BINARY, config], 'boot_id': 'boot'}
        child = Mock(pid=500)
        child.poll.return_value = None
        with patch.object(pc.subprocess, 'Popen', return_value=child), patch.object(pc, '_read_identity', return_value=identity), patch.object(pc, 'running_instances', return_value={'ready': False}), patch.object(pc, 'START_TIMEOUT', 0), patch.object(pc, 'stop_3proxy', return_value=(True, 'stopped')):
            self.assertFalse(pc.start_3proxy()[0])
            child.terminate.assert_called_once()

    def test_start_owned_process_and_ready_success(self):
        pc.generate_config([PROXY], [USER], SETTINGS)
        config = pc._instance_config_path(0)
        identity = {'pid': 501, 'start_time': '100', 'exe': os.path.realpath(pc.PROXY_BINARY),
                    'cmdline': [pc.PROXY_BINARY, config], 'boot_id': 'boot'}
        child = Mock(pid=501)
        child.poll.return_value = None
        with patch.object(pc.subprocess, 'Popen', return_value=child) as spawn, patch.object(pc, '_read_identity', return_value=identity), patch.object(pc, 'running_instances', return_value={'ready': True, 'running': 1, 'expected': 1}):
            self.assertTrue(pc.start_3proxy()[0])
            self.assertNotEqual(spawn.call_args.kwargs['stderr'], pc.subprocess.PIPE)
            self.assertEqual(pc._load_processes()[0]['start_time'], '100')


if __name__ == '__main__':
    unittest.main()
