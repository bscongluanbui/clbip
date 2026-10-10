"""Offline worker error notification contracts with in-memory RPC streams."""
import io
import json
import socketserver
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from credentials import CredentialError
from rpc import MAX_MESSAGE


TOKEN = 'alert-rpc-fixture-token-' + 'x' * 40
SECRET = 'alert-fixture-password-keep-private'


class WorkerAlertsTests(unittest.TestCase):
    def setUp(self):
        with patch.object(socketserver, 'ThreadingUnixStreamServer',
                          getattr(socketserver, 'ThreadingUnixStreamServer', socketserver.ThreadingTCPServer),
                          create=True):
            import worker
        self.worker = worker

    def request(self, *, method='status', params=None, token=TOKEN, raw=None, error=None,
                credentials=None, result=None):
        service = Mock()
        if error is None:
            service.dispatch.return_value = result if result is not None else {'ready': True}
        else:
            service.dispatch.side_effect = error
        message = {'token': token, 'method': method, 'params': {} if params is None else params}
        handler = self.worker.WorkerHandler.__new__(self.worker.WorkerHandler)
        handler.server = SimpleNamespace(service=service, token=TOKEN)
        handler.request = Mock()
        handler.rfile = io.BytesIO(json.dumps(message).encode() + b'\n' if raw is None else raw)
        handler.wfile = io.BytesIO()
        if credentials is not None:
            with patch.object(self.worker, 'credential_dispatch', side_effect=credentials):
                handler.handle()
        else:
            handler.handle()
        wire = handler.wfile.getvalue()
        return json.loads(wire) if wire else None, service

    def report_payload(self, service):
        return json.dumps([str(call) for call in service._report_failure.call_args_list])

    def test_authentication_failure_reports_without_disclosing_supplied_token(self):
        response, service = self.request(token=SECRET)
        self.assertEqual(response['status'], 401)
        service.dispatch.assert_not_called()
        self.assertTrue(service._report_failure.called)
        self.assertNotIn(SECRET, self.report_payload(service))

    def test_invalid_json_and_missing_newline_report_generic_rpc_failure(self):
        for raw in (b'{bad-json\n', b'{"unfinished":true}', b'\xff\n'):
            with self.subTest(raw=repr(raw)):
                response, service = self.request(raw=raw)
                self.assertEqual(response['status'], 400)
                service.dispatch.assert_not_called()
                self.assertTrue(service._report_failure.called)
                self.assertIn('worker.rpc', self.report_payload(service))

    def test_oversized_request_report_does_not_include_request_body(self):
        raw = ('{"password":"' + SECRET + '"' + ' ' * MAX_MESSAGE).encode() + b'\n'
        response, service = self.request(raw=raw)
        self.assertEqual(response['status'], 400)
        self.assertTrue(service._report_failure.called)
        self.assertNotIn(SECRET, self.report_payload(service))

    def test_dashboard_credential_failure_reports_operation_without_passwords(self):
        params = {'current_password': SECRET, 'new_password': SECRET, 'confirm_password': SECRET}
        response, service = self.request(method='change_dashboard_password', params=params,
                                         credentials=CredentialError('fixture credential failure', 403))
        self.assertEqual(response['status'], 403)
        service.dispatch.assert_not_called()
        self.assertTrue(service._report_failure.called)
        self.assertNotIn(SECRET, self.report_payload(service))

    def test_unexpected_credential_error_does_not_queue_exception_secrets(self):
        response, service = self.request(method='change_dashboard_password',
                                         params={'password': SECRET}, credentials=RuntimeError(SECRET))
        self.assertEqual(response['status'], 500)
        self.assertTrue(service._report_failure.called)
        self.assertNotIn(SECRET, self.report_payload(service))
        self.assertNotIn(SECRET, json.dumps(response))

    def test_service_operation_failure_is_not_duplicated_as_rpc_incident(self):
        from service import OperationError
        response, service = self.request(method='generate', params={'password': SECRET},
                                         error=OperationError('fixture engine unavailable'))
        self.assertEqual(response['status'], 503)
        # ProxyService.dispatch is the single operation incident producer.
        service._report_failure.assert_not_called()

    def test_successful_rpc_does_not_report_failure(self):
        response, service = self.request()
        self.assertEqual(response, {'ok': True, 'result': {'ready': True}})
        service._report_failure.assert_not_called()

    def test_successful_credential_change_resolves_its_operation_incident(self):
        def changed(_server, _params):
            return {'changed': True, 'requires_login': True}

        response, service = self.request(method='change_dashboard_password', credentials=changed)
        self.assertTrue(response['ok'])
        service._report_failure.assert_not_called()
        keys = [call.args[0] for call in service._report_resolved.call_args_list]
        self.assertIn('operation:change_dashboard_password', keys)

    def test_transport_read_timeout_reports_type_not_exception_payload(self):
        service = Mock()
        handler = self.worker.WorkerHandler.__new__(self.worker.WorkerHandler)
        handler.server = SimpleNamespace(service=service, token=TOKEN)
        handler.request = Mock()
        handler.rfile = Mock()
        handler.rfile.readline.side_effect = TimeoutError(SECRET)
        handler.wfile = io.BytesIO()
        handler.handle()
        self.assertEqual(json.loads(handler.wfile.getvalue())['status'], 500)
        self.assertTrue(service._report_failure.called)
        self.assertNotIn(SECRET, self.report_payload(service))

    def test_transport_write_reset_reports_type_not_exception_payload(self):
        service = Mock()
        service.dispatch.return_value = {'ready': True}
        handler = self.worker.WorkerHandler.__new__(self.worker.WorkerHandler)
        handler.server = SimpleNamespace(service=service, token=TOKEN)
        handler.request = Mock()
        handler.rfile = io.BytesIO(json.dumps({'token': TOKEN, 'method': 'status'}).encode() + b'\n')
        handler.wfile = Mock()
        handler.wfile.write.side_effect = ConnectionResetError(SECRET)
        handler.handle()
        self.assertTrue(service._report_failure.called)
        self.assertNotIn(SECRET, self.report_payload(service))
        recovered = [call.args[0] for call in service._report_resolved.call_args_list]
        self.assertNotIn('worker.rpc', recovered)

    def test_response_overflow_reports_failure_without_response_content(self):
        response, service = self.request(result={'secret': SECRET, 'padding': 'x' * MAX_MESSAGE})
        self.assertEqual(response['status'], 413)
        self.assertTrue(service._report_failure.called)
        self.assertNotIn(SECRET, self.report_payload(service))
        recovered = [call.args[0] for call in service._report_resolved.call_args_list]
        self.assertNotIn('worker.rpc', recovered)

    def test_rpc_alert_store_failure_does_not_destroy_error_response(self):
        service = Mock()
        service._report_failure.side_effect = OSError('fixture notification store unavailable')
        handler = self.worker.WorkerHandler.__new__(self.worker.WorkerHandler)
        handler.server = SimpleNamespace(service=service, token=TOKEN)
        handler.request = Mock()
        handler.rfile = io.BytesIO(b'invalid-json\n')
        handler.wfile = io.BytesIO()
        handler.handle()
        response = json.loads(handler.wfile.getvalue())
        self.assertEqual(response['status'], 400)


if __name__ == '__main__':
    unittest.main()
