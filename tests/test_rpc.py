"""Authenticated RPC framing tests; mocked sockets only, no real socket use."""
import json
import io
import os
import socketserver
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

import rpc

TOKEN = 'rpc-test-token-' + 'x' * 40


class RpcTests(unittest.TestCase):
    def setUp(self):
        context = patch.object(rpc.socket, 'AF_UNIX', getattr(rpc.socket, 'AF_UNIX', 1), create=True)
        context.start()
        self.addCleanup(context.stop)

    def socket_fixture(self, response):
        socket = MagicMock()
        socket.__enter__.return_value = socket
        stream = MagicMock()
        stream.__enter__.return_value = stream
        stream.readline.return_value = response
        socket.makefile.return_value = stream
        return socket, stream

    def test_authenticate_rejects_short_expected_and_wrong_token(self):
        self.assertFalse(rpc.authenticate('short', 'short'))
        self.assertFalse(rpc.authenticate('wrong-token-' + 'y' * 40, TOKEN))
        self.assertTrue(rpc.authenticate(TOKEN, TOKEN))

    def test_authenticate_invalid_types_and_unicode_are_false(self):
        for supplied in (None, 0, [], {}, '雪' * 40):
            with self.subTest(supplied=type(supplied).__name__):
                self.assertFalse(rpc.authenticate(supplied, TOKEN))
        for expected in (None, 0, [], {}):
            with self.subTest(expected=type(expected).__name__):
                self.assertFalse(rpc.authenticate(TOKEN, expected))

    def test_short_token_fails_before_opening_socket(self):
        with patch.object(rpc.socket, 'socket') as socket:
            with self.assertRaises(rpc.RpcError) as caught:
                rpc.WorkerClient('/unused', 'short').call('status')
            self.assertEqual(caught.exception.status, 503)
            socket.assert_not_called()

    def test_request_framing_auth_and_result(self):
        socket, stream = self.socket_fixture(b'{"ok":true,"result":{"ready":true}}\n')
        with patch.object(rpc.socket, 'socket', return_value=socket):
            result = rpc.WorkerClient('/unused/worker.sock', TOKEN).call('status', {'example': 1})
        self.assertEqual(result, {'ready': True})
        socket.connect.assert_called_once_with('/unused/worker.sock')
        wire = socket.sendall.call_args.args[0]
        self.assertTrue(wire.endswith(b'\n'))
        self.assertEqual(json.loads(wire), {'token': TOKEN, 'method': 'status', 'params': {'example': 1}})
        stream.readline.assert_called_once_with(rpc.MAX_MESSAGE + 1)

    def test_connection_failure_is_rpc_error(self):
        socket, _ = self.socket_fixture(b'')
        socket.connect.side_effect = OSError('socket missing')
        with patch.object(rpc.socket, 'socket', return_value=socket):
            with self.assertRaises(rpc.RpcError) as caught:
                rpc.WorkerClient('/unused', TOKEN).call('status')
        self.assertEqual(caught.exception.status, 503)
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_oversize_request_rejected_before_socket(self):
        with patch.object(rpc, 'MAX_MESSAGE', 128), patch.object(rpc.socket, 'socket') as socket:
            with self.assertRaises(rpc.RpcError) as caught:
                rpc.WorkerClient('/unused', TOKEN).call('status', {'large': 'a' * 1024})
            self.assertEqual(caught.exception.status, 413)
            socket.assert_not_called()

    def test_invalid_response_framing_and_json_are_rpc_errors(self):
        for response in (b'', b'{"ok":true}', b'not-json\n', b'[]\n', b'null\n', b'\xff\n',
                         b'{"ok":true}\n', b'{"ok":false,"status":"bad"}\n', b'{"ok":"true","result":{}}\n'):
            with self.subTest(response=response):
                socket, _ = self.socket_fixture(response)
                with patch.object(rpc.socket, 'socket', return_value=socket):
                    with self.assertRaises(rpc.RpcError) as caught:
                        rpc.WorkerClient('/unused', TOKEN).call('status')
                self.assertEqual(caught.exception.status, 503)

    def test_oversize_response_is_rejected(self):
        socket, _ = self.socket_fixture(b' ' * 1024 + b'\n')
        with patch.object(rpc, 'MAX_MESSAGE', 128), patch.object(rpc.socket, 'socket', return_value=socket):
            with self.assertRaises(rpc.RpcError) as caught:
                rpc.WorkerClient('/unused', TOKEN).call('status')
        self.assertEqual(caught.exception.status, 503)

    def test_remote_denial_preserves_status_without_auth_token(self):
        socket, _ = self.socket_fixture(b'{"ok":false,"status":401,"error":"Authentication failed"}\n')
        with patch.object(rpc.socket, 'socket', return_value=socket):
            with self.assertRaises(rpc.RpcError) as caught:
                rpc.WorkerClient('/unused', TOKEN).call('status')
        self.assertEqual(caught.exception.status, 401)
        self.assertEqual(str(caught.exception), 'Authentication failed')
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_secret_environment_and_file(self):
        with patch.dict(os.environ, {'FIXTURE_SECRET': TOKEN}, clear=True):
            self.assertEqual(rpc.read_secret('FIXTURE_SECRET'), TOKEN)
        with patch.dict(os.environ, {'FIXTURE_SECRET_FILE': '/unused/fixture'}, clear=True), patch.object(rpc.Path, 'read_text', return_value=TOKEN + '\n'):
            self.assertEqual(rpc.read_secret('FIXTURE_SECRET'), TOKEN)
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(rpc.read_secret('FIXTURE_SECRET', required=False), '')
            with self.assertRaises(RuntimeError):
                rpc.read_secret('FIXTURE_SECRET')


class WorkerHandlerTests(unittest.TestCase):
    def setUp(self):
        # The Linux server's socket is mocked; keep handler tests runnable on
        # Windows Python builds lacking Unix server constants/classes.
        with patch.object(socketserver, 'ThreadingUnixStreamServer',
                          getattr(socketserver, 'ThreadingUnixStreamServer', socketserver.ThreadingTCPServer), create=True):
            import worker
        self.worker = worker

    def request(self, message=None, raw=None, result=None, error=None, limit=None):
        service = Mock()
        if error:
            service.dispatch.side_effect = error
        else:
            service.dispatch.return_value = result if result is not None else {'ready': True}
        handler = self.worker.WorkerHandler.__new__(self.worker.WorkerHandler)
        handler.server = SimpleNamespace(service=service, token=TOKEN)
        handler.request = Mock()
        handler.rfile = io.BytesIO(raw if raw is not None else json.dumps(message).encode() + b'\n')
        handler.wfile = io.BytesIO()
        with patch.object(self.worker, 'MAX_MESSAGE', limit or rpc.MAX_MESSAGE):
            handler.handle()
        return json.loads(handler.wfile.getvalue()), service

    def test_server_unauthorized_requests_never_dispatch(self):
        for message in ({'method': 'status', 'params': {}},
                        {'token': 'wrong', 'method': 'status'},
                        {'token': '雪' * 40, 'method': 'status'}, [], None):
            with self.subTest(message_type=type(message).__name__):
                response, service = self.request(message)
                self.assertEqual(response['status'], 401)
                self.assertFalse(response['ok'])
                service.dispatch.assert_not_called()

    def test_server_authenticated_dispatch(self):
        response, service = self.request({'token': TOKEN, 'method': 'status', 'params': {'example': 1}})
        self.assertEqual(response, {'ok': True, 'result': {'ready': True}})
        service.dispatch.assert_called_once_with('status', {'example': 1})

    def test_server_framing_json_and_size_rejected(self):
        for raw in (b'not-json\n', b'\xff\n', b'{"token":"incomplete"}', b' ' * 1024 + b'\n'):
            with self.subTest(raw_type='oversize' if len(raw) > 128 else 'invalid'):
                response, service = self.request(raw=raw, limit=128)
                self.assertEqual(response['status'], 400)
                service.dispatch.assert_not_called()

    def test_server_validation_status(self):
        from validation import ValidationError
        response, _ = self.request({'token': TOKEN, 'method': 'settings'}, error=ValidationError('field invalid'))
        self.assertEqual(response, {'ok': False, 'status': 400, 'error': 'field invalid'})

    def test_server_runtime_failure_status(self):
        from service import OperationError
        response, _ = self.request({'token': TOKEN, 'method': 'start'}, error=OperationError('runtime not ready'))
        self.assertEqual(response['status'], 503)

    def test_server_unexpected_exception_is_redacted(self):
        response, _ = self.request({'token': TOKEN, 'method': 'status'}, error=RuntimeError(TOKEN))
        self.assertEqual(response['status'], 500)
        self.assertNotIn(TOKEN, json.dumps(response))

    def test_server_response_size_is_bounded(self):
        response, _ = self.request({'token': TOKEN, 'method': 'status'}, result={'large': 'a' * 2048}, limit=256)
        self.assertEqual(response['status'], 413)

    def test_service_dispatch_rejects_unknown_methods_and_nonobject_params(self):
        from service import ProxyService
        from validation import ValidationError
        service = ProxyService.__new__(ProxyService)  # No StateStore/network initialization.
        for method, params in (('__dict__', {}), ('unknown', {}), ('status', []), ('status', None)):
            with self.subTest(method=method), self.assertRaises(ValidationError):
                service.dispatch(method, params)

    def test_server_thread_start_failure_does_not_leak_request_slot(self):
        server = self.worker.WorkerServer.__new__(self.worker.WorkerServer)
        server.slots = Mock()
        server.slots.acquire.return_value = True
        with patch.object(socketserver.ThreadingMixIn, 'process_request', side_effect=RuntimeError('thread capacity exhausted')):
            with self.assertRaises(RuntimeError):
                server.process_request(Mock(), '/unused-client')
        server.slots.release.assert_called_once()


if __name__ == '__main__':
    unittest.main()
