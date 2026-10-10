"""VPS watchdog contract and clock/storage tests; all Telegram/HTTP are fake."""
from email.message import Message
import importlib.util
import io
import json
from pathlib import Path
import socket
import sqlite3
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch


_path = Path(__file__).resolve().parents[1] / 'scripts' / 'external_watchdog.py'
_spec = importlib.util.spec_from_file_location('testable_external_watchdog', _path)
watchdog = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = watchdog
_spec.loader.exec_module(watchdog)
TOKEN = 'test-only-shared-token-12345678901234567890'
ENV = {'WATCHDOG_SHARED_TOKEN': TOKEN, 'TELEGRAM_BOT_TOKEN': '123456:test-only-token',
       'TELEGRAM_CHAT_ID': '-1001234567'}


class RecordingOutbox:
    def __init__(self):
        self.active = set()
        self.transitions = []
        self.calls = []
    def failure(self, key, title, detail=''):
        self.calls.append(('failure', key, title, detail))
        if key not in self.active:
            self.transitions.append(('failure', key, title, detail))
            self.active.add(key)
    def resolve(self, key, title, detail=''):
        self.calls.append(('resolve', key, title, detail))
        if key in self.active:
            self.transitions.append(('recovery', key, title, detail))
            self.active.remove(key)


class WatchdogTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = 1000.0
        self.outbox = RecordingOutbox()
        self.store = self.make_store()

    def make_store(self):
        return watchdog.WatchdogStore(self.tmp.name, timeout=180, node_name='node-one',
                                      clock=lambda: self.now, outbox=self.outbox)

    @staticmethod
    def headers(token=TOKEN, body='0', **extra):
        headers = Message()
        headers['Authorization'] = 'Bearer ' + token
        headers['Content-Length'] = body
        for key, value in extra.items():
            headers[key] = value
        return headers

    def test_first_deadline_grace_then_one_outage_transition(self):
        self.assertFalse(self.store.check()['missing'])
        self.now += 179
        self.assertFalse(self.store.check()['missing'])
        self.now += 1
        self.assertTrue(self.store.check()['missing'])
        self.assertFalse(self.store.check()['heartbeat_received'])
        self.now += 10
        self.assertTrue(self.store.check()['missing'])
        self.assertEqual([call[0] for call in self.outbox.transitions], ['failure'])
        self.assertIn('Chưa xác định', self.outbox.transitions[0][3])

    def test_heartbeat_refreshes_deadline_and_recovery_exactly_once(self):
        self.now += 180
        self.store.check()
        self.now += 15
        self.store.heartbeat()
        self.assertFalse(self.store.check()['missing'])
        self.store.heartbeat()
        self.assertEqual([call[0] for call in self.outbox.transitions], ['failure', 'recovery'])
        self.now += 179
        self.assertFalse(self.store.check()['missing'])
        self.now += 1
        self.assertTrue(self.store.check()['missing'])
        self.assertEqual([call[0] for call in self.outbox.transitions], ['failure', 'recovery', 'failure'])

    def test_initial_grace_is_not_reset_by_receiver_restart(self):
        self.now += 170
        reopened = self.make_store()
        self.assertEqual(reopened.check()['age_seconds'], 170)
        self.now += 10
        self.assertTrue(reopened.check()['missing'])

    def test_last_heartbeat_persists_and_outage_not_erased_by_restart(self):
        self.now += 30
        self.store.heartbeat()
        self.now += 179
        reopened = self.make_store()
        self.assertFalse(reopened.check()['missing'])
        self.now += 1
        self.assertTrue(reopened.check()['missing'])
        reopened = self.make_store()
        self.assertTrue(reopened.check()['missing'])
        self.assertEqual(len(self.outbox.transitions), 1)

    def test_clock_rollback_and_future_stamp_degrade_until_new_beat(self):
        self.store.heartbeat()
        self.now -= 30
        state = self.make_store().check()
        self.assertTrue(state['missing'])
        self.assertTrue(state['clock_invalid'])
        self.now += 20
        self.assertTrue(self.store.check()['clock_invalid'])
        self.store.heartbeat()
        self.assertFalse(self.store.check()['clock_invalid'])
        self.assertFalse(self.store.check()['missing'])

    def test_clock_forward_expires_deadline(self):
        self.store.heartbeat()
        self.now += 100000
        self.assertTrue(self.store.check()['missing'])

    def test_small_clock_adjustment_not_false_future_health(self):
        self.store.heartbeat()
        self.now -= 3
        state = self.store.check()
        self.assertFalse(state['missing'])
        self.assertEqual(state['age_seconds'], 0)

    def test_nonfinite_and_negative_clocks_rejected(self):
        for value in (float('nan'), float('inf'), -1, True, 'bad'):
            self.now = value
            with self.assertRaisesRegex(ValueError, 'Watchdog clock invalid'):
                self.store.heartbeat()

    def test_invalid_auth_does_not_certify_heartbeat(self):
        for token in ('wrong', '', '漢字' * 32):
            self.assertEqual(watchdog.authorize_request('/heartbeat', self.headers(token), TOKEN), 401)
        self.assertEqual(watchdog.authorize_request('/heartbeat', Message(), TOKEN), 401)
        self.assertEqual(watchdog.authorize_request('/other', self.headers(), TOKEN), 404)
        self.assertEqual(watchdog.authorize_request('/heartbeat?secret=x', self.headers(), TOKEN), 404)
        self.assertEqual(watchdog.authorize_request('/heartbeat', self.headers(), TOKEN), 204)
        self.assertFalse(self.store.check()['heartbeat_received'])

    def test_duplicate_auth_and_content_length_rejected(self):
        headers = self.headers()
        headers['Authorization'] = 'Bearer ' + TOKEN
        self.assertEqual(watchdog.authorize_request('/heartbeat', headers, TOKEN), 401)
        headers = self.headers()
        headers['Content-Length'] = '0'
        self.assertEqual(watchdog.authorize_request('/heartbeat', headers, TOKEN), 400)

    def test_body_transfer_encoding_and_invalid_lengths_rejected(self):
        for length in ('1', '1025', '9999999999999999'):
            self.assertEqual(watchdog.authorize_request('/heartbeat', self.headers(body=length), TOKEN), 413)
        for length in ('-1', 'bad', ' 0', '', '００'):
            self.assertEqual(watchdog.authorize_request('/heartbeat', self.headers(body=length), TOKEN), 400)
        self.assertEqual(watchdog.authorize_request('/heartbeat',
            self.headers(**{'Transfer-Encoding': 'chunked'}), TOKEN), 400)

    def test_http_handler_only_updates_after_auth_and_returns_generic_storage_error(self):
        handler = object.__new__(watchdog.WatchdogHandler)
        handler.server = Mock(shared_token=TOKEN, store=self.store)
        handler.respond = Mock()
        handler.path = '/heartbeat'
        handler.headers = self.headers('wrong')
        handler.do_POST()
        handler.respond.assert_called_with(401)
        self.assertFalse(self.store.check()['heartbeat_received'])
        handler.headers = self.headers()
        handler.do_POST()
        handler.respond.assert_called_with(204)
        self.assertTrue(self.store.check()['heartbeat_received'])
        handler.server.store = Mock()
        handler.server.store.heartbeat.side_effect = RuntimeError(TOKEN)
        with patch.object(watchdog.logger, 'error') as logger:
            handler.do_POST()
            handler.respond.assert_called_with(503)
            self.assertNotIn(TOKEN, str(logger.call_args))

    def test_receiver_thread_admission_bound_and_release(self):
        with patch.object(watchdog.ThreadingHTTPServer, '__init__', return_value=None):
            server = watchdog.WatchdogServer(('127.0.0.1', 8088), self.store, TOKEN)
        self.assertEqual(watchdog.MAX_CLIENTS, 16)
        for _ in range(16):
            self.assertTrue(server.slots.acquire(blocking=False))
        request = Mock()
        with patch.object(server, 'shutdown_request') as shutdown, \
             patch.object(watchdog.ThreadingHTTPServer, 'process_request') as delegate:
            server.process_request(request, ('127.0.0.1', 1234))
            shutdown.assert_called_once_with(request)
            delegate.assert_not_called()
        with patch.object(watchdog.ThreadingHTTPServer, 'process_request_thread', side_effect=RuntimeError('test')):
            with self.assertRaises(RuntimeError):
                server.process_request_thread(request, ('127.0.0.1', 1234))
        self.assertTrue(server.slots.acquire(blocking=False))

    def test_socket_deadline(self):
        with patch.object(watchdog.ThreadingHTTPServer, '__init__', return_value=None):
            server = watchdog.WatchdogServer(('127.0.0.1', 8088), self.store, TOKEN)
        request = Mock()
        with patch.object(watchdog.ThreadingHTTPServer, 'get_request', return_value=(request, ('local', 1))):
            self.assertEqual(server.get_request()[0], request)
            request.settimeout.assert_called_once_with(5)

    def test_literal_bind_selects_socket_family_before_creation_without_class_leak(self):
        for bind, family in (('127.0.0.1', socket.AF_INET),
                             ('fd7a:115c:a1e0::1234', socket.AF_INET6),
                             ('0.0.0.0', socket.AF_INET),
                             ('::', socket.AF_INET6)):
            observed = []
            def initialize(server, address, handler):
                observed.append((server.address_family, address, handler))
            with self.subTest(bind=bind), patch.object(
                    watchdog.ThreadingHTTPServer, '__init__', initialize):
                server = watchdog.WatchdogServer((bind, 8088), self.store, TOKEN)
                self.assertEqual(server.address_family, family)
                self.assertEqual(observed, [(family, (bind, 8088), watchdog.WatchdogHandler)])
        self.assertEqual(watchdog.WatchdogServer.address_family, socket.AF_INET)

    def test_ipv6_bind_sets_v6only_before_bind_and_never_uses_reverse_dns(self):
        server = object.__new__(watchdog.WatchdogServer)
        server.address_family = socket.AF_INET6
        server.socket = Mock()
        server.socket.getsockname.return_value = ('::1', 8088, 0, 0)
        order = []
        server.socket.setsockopt.side_effect = lambda *args: order.append(('option', args))
        with patch.object(watchdog.TCPServer, 'server_bind',
                          side_effect=lambda server: order.append(('bind',))) as bind, \
                patch('socket.getfqdn', side_effect=AssertionError('No reverse DNS')):
            server.server_bind()
        bind.assert_called_once_with(server)
        self.assertEqual(order, [('option', (socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)), ('bind',)])
        self.assertEqual((server.server_name, server.server_port), ('::1', 8088))

    def test_ipv4_bind_preserves_family_without_ipv6_options_or_reverse_dns(self):
        server = object.__new__(watchdog.WatchdogServer)
        server.address_family = socket.AF_INET
        server.socket = Mock()
        server.socket.getsockname.return_value = ('127.0.0.1', 8088)
        with patch.object(watchdog.TCPServer, 'server_bind') as bind, \
                patch('socket.getfqdn', side_effect=AssertionError('No reverse DNS')):
            server.server_bind()
        bind.assert_called_once_with(server)
        server.socket.setsockopt.assert_not_called()
        self.assertEqual((server.server_name, server.server_port), ('127.0.0.1', 8088))

    def test_invalid_bind_rejected_before_socket_creation_or_dns(self):
        for bind in ('localhost', 'monitor.example.com', '', '::1%lo', 'bad', None):
            with self.subTest(bind=bind), patch.object(watchdog.ThreadingHTTPServer, '__init__') as initialize, \
                    patch('socket.getaddrinfo', side_effect=AssertionError('No DNS')):
                with self.assertRaisesRegex(ValueError, 'WATCHDOG_BIND invalid'):
                    watchdog.WatchdogServer((bind, 8088), self.store, TOKEN)
                initialize.assert_not_called()

    def test_config_accepts_literal_ipv4_ipv6_and_rejects_names_scopes_offline(self):
        for bind, expected in (('127.0.0.1', '127.0.0.1'), ('0.0.0.0', '0.0.0.0'),
                               ('fd7a:115c:a1e0:0:0:0:0:1234', 'fd7a:115c:a1e0::1234'), ('::', '::')):
            with self.subTest(bind=bind), patch('socket.getaddrinfo', side_effect=AssertionError('No DNS')):
                self.assertEqual(watchdog.WatchdogConfig.from_env({**ENV, 'WATCHDOG_BIND': bind}).bind, expected)
        for bind in ('localhost', 'monitor.example.com', '::1%lo', None, ''):
            with self.subTest(bind=bind), patch('socket.getaddrinfo', side_effect=AssertionError('No DNS')):
                with self.assertRaisesRegex(ValueError, 'WATCHDOG_BIND invalid'):
                    watchdog.WatchdogConfig.from_env({**ENV, 'WATCHDOG_BIND': bind})

    def test_detector_loop_stops_and_logs_redacted_storage_failure(self):
        store = Mock(outbox=self.outbox)
        stop = Mock()
        stop.is_set.return_value = False
        stop.wait.return_value = True
        store.check.side_effect = RuntimeError(TOKEN)
        with patch.object(watchdog.logger, 'error') as logger:
            watchdog.detector_loop(store, stop, interval=5)
            self.assertNotIn(TOKEN, str(logger.call_args))
        self.assertIn('watchdog.storage', self.outbox.active)
        stop.wait.assert_called_once_with(5)

    def test_real_outbox_failure_recovery_durable_without_telegram(self):
        with patch('alerts.send_telegram_message', side_effect=AssertionError('No Telegram')):
            store = watchdog.WatchdogStore(self.tmp.name, timeout=180, clock=lambda: self.now)
            self.now += 180
            store.check()
            self.assertEqual(store.outbox.status()['active_incidents'], 1)
            self.assertEqual(store.outbox.status()['queued'], 1)
            store.heartbeat()
            self.assertEqual(store.outbox.status()['active_incidents'], 0)
            self.assertEqual(store.outbox.status()['queued'], 2)
            reopened = watchdog.WatchdogStore(self.tmp.name, timeout=180, clock=lambda: self.now)
            self.assertEqual(reopened.outbox.status()['queued'], 2)

    def test_database_contains_no_tokens_credentials_or_pool(self):
        self.store.heartbeat()
        content = self.store.path.read_bytes()
        self.assertNotIn(TOKEN.encode(), content)
        self.assertNotIn(b'123456:test-only-token', content)

    def test_config_and_check_mode_no_network_storage_and_no_secret_output(self):
        config = watchdog.WatchdogConfig.from_env(ENV)
        self.assertEqual(config.bind, '127.0.0.1')
        self.assertEqual(config.timeout, 180)
        self.assertEqual(config.check_interval, 5)
        self.assertEqual(config.settings()['telegram_bot_token'], ENV['TELEGRAM_BOT_TOKEN'])
        self.assertNotIn(TOKEN, repr(config))
        self.assertNotIn(ENV['TELEGRAM_BOT_TOKEN'], repr(config))
        stream = io.StringIO()
        with patch.dict('os.environ', ENV, clear=True), patch.object(watchdog, 'WatchdogStore', side_effect=AssertionError('No storage')), \
             patch.object(watchdog, 'WatchdogServer', side_effect=AssertionError('No server')), patch('sys.stdout', stream):
            self.assertEqual(watchdog.main(['--check']), 0)
        self.assertEqual(stream.getvalue().strip(), 'WATCHDOG_CONFIG=OK NETWORK=NONE')

    def test_once_mode_queues_only_does_not_create_server_or_send(self):
        stream = io.StringIO()
        with patch.dict('os.environ', {**ENV, 'DATA_DIR': str(Path(self.tmp.name) / 'once')}, clear=True), \
             patch.object(watchdog, 'WatchdogServer', side_effect=AssertionError('No server')), \
             patch('alerts.send_telegram_message', side_effect=AssertionError('No Telegram')), patch('sys.stdout', stream):
            self.assertEqual(watchdog.main(['--once']), 0)
        self.assertFalse(json.loads(stream.getvalue())['missing'])

    def test_bad_env_config_generic_error_not_values(self):
        for patch_env in ({'WATCHDOG_SHARED_TOKEN': 'short'}, {'WATCHDOG_SHARED_TOKEN': TOKEN + '\nbad'},
                          {'WATCHDOG_PORT': '8088.5'}, {'WATCHDOG_TIMEOUT': 'nan'},
                          {'WATCHDOG_CHECK_INTERVAL': '0'}, {'TELEGRAM_CHAT_ID': ''},
                          {'WATCHDOG_NODE_NAME': 'bad\nname'}):
            with self.subTest(patch_env=patch_env):
                with self.assertRaises(ValueError) as exc:
                    watchdog.WatchdogConfig.from_env({**ENV, **patch_env})
                self.assertNotIn(TOKEN, str(exc.exception))
        with patch.dict('os.environ', {'WATCHDOG_SHARED_TOKEN': TOKEN}, clear=True), patch.object(watchdog.logger, 'error') as logger:
            self.assertEqual(watchdog.main(['--check']), 1)
            self.assertNotIn(TOKEN, str(logger.call_args))

    def test_detector_survives_secondary_outbox_failure(self):
        store = Mock()
        stop = Mock()
        stop.is_set.return_value = False
        stop.wait.return_value = True
        store.check.side_effect = RuntimeError(TOKEN)
        store.outbox.failure.side_effect = RuntimeError(TOKEN)
        with patch.object(watchdog.logger, 'error') as logger:
            watchdog.detector_loop(store, stop, interval=5)
            self.assertNotIn(TOKEN, str(logger.call_args_list))
        stop.wait.assert_called_once_with(5)


if __name__ == '__main__':
    unittest.main()
