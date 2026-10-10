"""Offline liveness/readiness separation, actual monotonic progress and bounded RPC."""
import io
import json
import os
import socketserver
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

import app as dashboard
import rpc
from service import OperationError, ProxyService
from validation import ValidationError

TOKEN = 'offline-liveness-token-' + 'x' * 40
CONFIG = {'TESTING': True, 'SECRET_KEY': 'offline-session-' + 'y' * 40,
          'SERVICE_TOKEN': TOKEN, 'ADMIN_PASSWORD': ''}


class LivenessTests(unittest.TestCase):
    def setUp(self):
        self.service = ProxyService.__new__(ProxyService)
        self.service.stop_event = threading.Event()
        self.service.cancel_operation = threading.Event()
        self.service.operation_deadline = None
        self.service.reconciler_thread = Mock()
        self.service.reconciler_thread.is_alive.return_value = True
        self.service.last_reconciler_progress_monotonic = 1000.0
        self.service.reconciler_waiting_for_lock = False
        self.service.liveness_operation = (False, 1000.0)
        self.service.lock = threading.RLock()
        self.service.progress_lock = threading.Lock()
        self.service.progress = {'active': False, 'last_update': 0, 'verified': 0}
        self.service.store = Mock()
        self.service.store.read.side_effect = AssertionError('Liveness must not read SQLite')
        self.service.net = Mock()
        self.service.engine = Mock()
        self.service._report_resolved = Mock()
        self.service._report_failure = Mock()

    def snapshot(self, now=1010.0):
        with patch('service.time.monotonic', return_value=now):
            return self.service.dispatch('controlplane_liveness', {})

    def test_no_io_or_mutation_or_alerts_when_pool_not_ready(self):
        self.service.health_error = 'fixture pool unavailable'
        self.service.alerts_error = 'fixture outbox error'
        result = self.snapshot()
        self.assertEqual(result, {'healthy': True, 'reconciler_alive': True,
            'progress_fresh': True, 'last_reconcile_monotonic': 1000.0})
        self.service.store.read.assert_not_called()
        self.service.net.assert_not_called()
        self.service.engine.assert_not_called()
        self.service._report_resolved.assert_not_called()
        self.service._report_failure.assert_not_called()

    def test_snapshot_never_waits_for_network_or_progress_lock(self):
        held, release = threading.Event(), threading.Event()
        def hold():
            with self.service.lock, self.service.progress_lock:
                held.set()
                release.wait(3)
        thread = threading.Thread(target=hold)
        thread.start()
        self.assertTrue(held.wait(1))
        try:
            result = self.snapshot()
            self.assertTrue(result['healthy'])
        finally:
            release.set()
            thread.join(1)

    def test_hung_reconciler_expires_and_http_read_does_not_refresh(self):
        self.assertTrue(self.snapshot(1329.0)['healthy'])
        for now in (1330.0, 1331.0, 1400.0):
            self.assertFalse(self.snapshot(now)['progress_fresh'])
            self.assertEqual(self.service.last_reconciler_progress_monotonic, 1000.0)

    def test_dead_thread_and_shutdown_do_not_emit_healthy(self):
        self.service.reconciler_thread.is_alive.return_value = False
        self.assertFalse(self.snapshot()['healthy'])
        self.service.reconciler_thread.is_alive.return_value = True
        self.service.stop_event.set()
        self.assertFalse(self.snapshot()['reconciler_alive'])

    def test_not_started_reconciler_is_unhealthy(self):
        self.service.reconciler_thread = None
        self.assertFalse(self.snapshot()['healthy'])

    def test_manual_pool_stop_does_not_mean_worker_shutdown(self):
        self.service.store.read.return_value = {'manual_stop': True, 'desired_state': 'stopped'}
        self.assertTrue(self.snapshot()['healthy'])
        self.service.store.read.assert_not_called()

    def test_unrelated_checkpoint_does_not_mask_hung_reconciler(self):
        with patch('service.time.monotonic', return_value=1400.0):
            self.service._checkpoint()
        self.assertFalse(self.snapshot(1400)['healthy'])

    def test_expired_or_canceled_checkpoints_do_not_refresh_activity(self):
        self.service.reconciler_thread = threading.current_thread()
        self.service.operation_deadline = 1399
        with patch('service.time.monotonic', return_value=1400):
            for _ in range(3):
                with self.assertRaises(OperationError):
                    self.service._checkpoint()
        self.assertEqual(self.service.last_reconciler_progress_monotonic, 1000)
        self.service.operation_deadline = None
        self.service.cancel_operation.set()
        with patch('service.time.monotonic', return_value=1400):
            for check in (self.service._checkpoint, self.service._cancellation_checkpoint):
                with self.assertRaises(OperationError):
                    check()
        self.assertEqual(self.service.last_reconciler_progress_monotonic, 1000)

    def test_actual_reconciler_checkpoint_restores_liveness(self):
        self.service.reconciler_thread = threading.current_thread()
        with patch('service.time.monotonic', return_value=1400.0):
            self.service._checkpoint()
        self.assertEqual(self.service.last_reconciler_progress_monotonic, 1400.0)
        self.assertTrue(self.snapshot(1401)['healthy'])

    def test_active_build_progress_only_helps_lock_waiting_reconciler(self):
        self.service.liveness_operation = (True, 1400.0)
        self.assertFalse(self.snapshot(1410)['healthy'])
        self.service.reconciler_waiting_for_lock = True
        self.assertTrue(self.snapshot(1410)['healthy'])
        self.assertEqual(self.snapshot(1410)['last_reconcile_monotonic'], 1400.0)
        self.assertFalse(self.snapshot(1730)['healthy'])

    def test_real_operation_updates_monotonic_not_wall_clock(self):
        self.service.reconciler_waiting_for_lock = True
        self.service.liveness_operation = (True, 1000.0)
        with patch('service.time.monotonic', return_value=1400.0), patch('service.time.time', return_value=-999):
            self.service._progress_update(increment={'verified': 1})
        self.assertEqual(self.service.liveness_operation, (True, 1400.0))
        self.assertTrue(self.snapshot(1401)['healthy'])
        self.assertEqual(self.service.progress['last_update'], -999)

    def test_nonfinite_or_future_progress_is_unhealthy(self):
        for stamp in (float('nan'), float('inf'), 1011.0):
            self.service.last_reconciler_progress_monotonic = stamp
            self.assertFalse(self.snapshot()['healthy'])

    def test_liveness_rejects_mutation_params(self):
        for params in (None, [], {'reset': True}):
            with self.assertRaises(ValidationError):
                self.service.dispatch('controlplane_liveness', params)


class EndpointTests(unittest.TestCase):
    def setUp(self):
        self.worker = Mock()
        self.worker.call.return_value = {'healthy': True, 'reconciler_alive': True, 'progress_fresh': True,
                                       'last_reconcile_monotonic': 1000, 'private': TOKEN}
        self.app = dashboard.create_app(CONFIG, self.worker)
        self.client = self.app.test_client()

    def test_public_heartbeat_only_booleans_short_rpc_no_deep_health(self):
        response = self.client.get('/heartbeatz')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json, {'alive': True, 'worker_alive': True, 'progress_fresh': True})
        self.worker.call.assert_called_once_with('controlplane_liveness', timeout=2)
        self.assertNotIn(TOKEN, response.text)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')

    def test_worker_missing_or_stale_or_invalid_response_is_503(self):
        for result in (None, [], {}, {'healthy': 1, 'reconciler_alive': True, 'progress_fresh': True},
                       {'healthy': True, 'reconciler_alive': 'yes', 'progress_fresh': True},
                       {'healthy': True, 'reconciler_alive': True, 'progress_fresh': False}):
            self.worker.call.return_value = result
            self.assertEqual(self.client.get('/heartbeatz').status_code, 503)

    def test_rpc_timeout_error_redacted_and_no_fallback_to_livez(self):
        self.worker.call.side_effect = rpc.RpcError(TOKEN)
        response = self.client.get('/heartbeatz')
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.json, {'alive': True, 'worker_alive': False, 'progress_fresh': False})
        self.assertNotIn(TOKEN, response.text)
        self.worker.call.assert_called_once()

    def test_unconfigured_endpoint_does_not_probe_worker(self):
        client = dashboard.create_app({'TESTING': True}, self.worker).test_client()
        self.assertEqual(client.get('/heartbeatz').status_code, 503)
        self.worker.call.assert_not_called()

    def test_readiness_keeps_strict_503_during_pool_error(self):
        self.worker.call.return_value = {'ready': False}
        self.assertEqual(self.client.get('/readyz').status_code, 503)
        self.worker.call.assert_called_once_with('health')


class RpcTimeoutTests(unittest.TestCase):
    def setUp(self):
        context = patch.object(rpc.socket, 'AF_UNIX', getattr(rpc.socket, 'AF_UNIX', 1), create=True)
        context.start()
        self.addCleanup(context.stop)

    def fixture(self):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        stream = MagicMock()
        stream.__enter__.return_value = stream
        stream.readline.return_value = b'{"ok":true,"result":{}}\n'
        sock.makefile.return_value = stream
        return sock

    def test_heartbeat_timeout_override_does_not_change_normal_operations(self):
        sock = self.fixture()
        with patch.object(rpc.socket, 'socket', return_value=sock), patch.dict(os.environ, {'WORKER_RPC_TIMEOUT': '600'}):
            client = rpc.WorkerClient('/unused', TOKEN)
            client.call('controlplane_liveness', timeout=2)
            sock.settimeout.assert_called_with(2.0)
            client.call('generate')
            sock.settimeout.assert_called_with(600.0)

    def test_invalid_timeout_rejected_before_socket(self):
        for value in (True, False, 0, -1, float('nan'), float('inf'), {}, 'bad'):
            with patch.object(rpc.socket, 'socket') as sock, self.assertRaises(rpc.RpcError):
                rpc.WorkerClient('/unused', TOKEN).call('controlplane_liveness', timeout=value)
            sock.assert_not_called()

    def test_socket_timeout_is_redacted(self):
        sock = self.fixture()
        sock.connect.side_effect = TimeoutError(TOKEN)
        with patch.object(rpc.socket, 'socket', return_value=sock), self.assertRaises(rpc.RpcError) as caught:
            rpc.WorkerClient('/unused', TOKEN).call('controlplane_liveness', timeout=2)
        self.assertNotIn(TOKEN, str(caught.exception))


class WorkerProbeTests(unittest.TestCase):
    def setUp(self):
        with patch.object(socketserver, 'ThreadingUnixStreamServer',
                          getattr(socketserver, 'ThreadingUnixStreamServer', socketserver.ThreadingTCPServer), create=True):
            import worker
        self.worker = worker

    def test_successful_liveness_rpc_does_not_touch_alert_storage(self):
        service = Mock()
        service.dispatch.return_value = {'healthy': True}
        handler = self.worker.WorkerHandler.__new__(self.worker.WorkerHandler)
        handler.server = SimpleNamespace(service=service, token=TOKEN)
        handler.request = Mock()
        handler.rfile = io.BytesIO(json.dumps({'token': TOKEN, 'method': 'controlplane_liveness', 'params': {}}).encode() + b'\n')
        handler.wfile = io.BytesIO()
        handler.handle()
        self.assertTrue(json.loads(handler.wfile.getvalue())['ok'])
        service._report_resolved.assert_not_called()
        service._report_failure.assert_not_called()

    def test_accept_loop_does_not_wait_for_sqlite_on_success(self):
        server = self.worker.WorkerServer.__new__(self.worker.WorkerServer)
        server.slots = Mock()
        server.slots.acquire.return_value = True
        server.service = Mock()
        with patch.object(socketserver.ThreadingMixIn, 'process_request'):
            server.process_request(Mock(), '/unused')
        server.service._report_resolved.assert_not_called()


if __name__ == '__main__':
    unittest.main()
