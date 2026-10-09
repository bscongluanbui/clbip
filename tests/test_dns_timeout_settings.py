"""Typed DNS setting compatibility plus offline checks of the failover fixture."""
import copy
import importlib.util
import json
from pathlib import Path
import shutil
import struct
import unittest
import uuid
from unittest.mock import patch

from state_store import StateStore
from validation import DEFAULT_SETTINGS, ValidationError, settings_patch

SPEC = importlib.util.spec_from_file_location(
    'dns_failover_integration_fixture', Path(__file__).with_name('integration_dns_failover.py'))
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class DnsTimeoutSettingsTests(unittest.TestCase):
    def test_new_install_and_old_settings_keep_fifteen_second_default(self):
        self.assertEqual(DEFAULT_SETTINGS['timeout_dns'], 15)
        old = {key: value for key, value in DEFAULT_SETTINGS.items() if key != 'timeout_dns'}
        original = copy.deepcopy(old)
        result = settings_patch({}, old)
        self.assertEqual(result['timeout_dns'], 15)
        self.assertEqual(old, original)
        self.assertEqual({key: value for key, value in result.items() if key != 'timeout_dns'}, old)

    def test_valid_setting_keeps_other_fields_and_preserves_inputs(self):
        previous = {**DEFAULT_SETTINGS, 'timeout_connect': 17, 'timeout_idle': 400, 'thread_limit': 6044}
        original = copy.deepcopy(previous)
        for timeout in (1, 3, 5, 15, 30):
            data = {'timeout_dns': timeout}
            with self.subTest(timeout=timeout):
                result = settings_patch(data, previous)
                self.assertEqual(result['timeout_dns'], timeout)
                self.assertEqual({key: value for key, value in result.items() if key != 'timeout_dns'},
                                 {key: value for key, value in previous.items() if key != 'timeout_dns'})
                self.assertEqual(previous, original)
                self.assertEqual(data, {'timeout_dns': timeout})

    def test_dns_timeout_is_strict_integer_one_to_thirty(self):
        for invalid in (0, 31, -1, True, False, '3', '5', 3.0, None, [], {}, '3\nnserver 127.0.0.1'):
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                settings_patch({'timeout_dns': invalid})

    def test_invalid_persisted_timeout_is_rejected_not_replaced(self):
        previous = {**DEFAULT_SETTINGS, 'timeout_dns': '5'}
        with self.assertRaises(ValidationError):
            settings_patch({}, previous)
        self.assertEqual(previous['timeout_dns'], '5')

    def test_old_sqlite_state_reads_default_without_rewriting_pool_or_db(self):
        directory = Path(__file__).resolve().parent / ('.tmp_dns_setting_' + uuid.uuid4().hex)
        directory.mkdir()
        try:
            store = StateStore(directory)
            state = store.read()
            state['settings'].pop('timeout_dns')
            state['settings']['thread_limit'] = 6044
            state['proxies'] = [{'ipv6': '2001:db8::10', 'port': 10000, 'protocol': 'http'}]
            with store.connection() as connection:
                connection.execute('UPDATE state SET body=? WHERE id=1', (json.dumps(state),))
            original = copy.deepcopy(state)
            read = store.read()
            self.assertEqual(read['settings']['timeout_dns'], 15)
            self.assertEqual(read['settings']['thread_limit'], 6044)
            self.assertEqual(read['proxies'][0]['port'], 10000)
            with store.connection() as connection:
                persisted = json.loads(connection.execute('SELECT body FROM state WHERE id=1').fetchone()[0])
            self.assertEqual(persisted, original)
            self.assertNotIn('timeout_dns', persisted['settings'])
        finally:
            assert directory.resolve().is_relative_to(Path(__file__).resolve().parent)
            shutil.rmtree(directory)

    def test_settings_validation_does_not_query_or_change_resolvers(self):
        with patch('validation.socket.getaddrinfo', side_effect=AssertionError('No DNS lookup')):
            result = settings_patch({'timeout_dns': 5})
        self.assertEqual(result['timeout_dns'], 5)


class DnsFailoverFixtureTests(unittest.TestCase):
    @staticmethod
    def query(qtype=28):
        return struct.pack('!6H', 1234, 0x0100, 1, 0, 0, 0) + b'\x07fixture\x07example\0' + struct.pack('!HH', qtype, 1)

    def test_loopback_answer_keeps_id_question_and_expected_address(self):
        for qtype, address in ((1, b'\x7f\x00\x00\x01'), (28, b'\x00' * 15 + b'\x01')):
            query = self.query(qtype)
            with self.subTest(qtype=qtype):
                answer = fixture.loopback_dns_answer(query)
                self.assertEqual(struct.unpack('!6H', answer[:12]), (1234, 0x8180, 1, 1, 0, 0))
                self.assertEqual(answer[12:len(query)], query[12:])
                self.assertTrue(answer.endswith(address))

    def test_malformed_dns_queries_do_not_produce_answers(self):
        valid = self.query()
        cases = [b'', valid[:16], valid[:-1], valid + b'extra', self.query(15),
                 valid[:12] + b'\xc0\x0c' + valid[-4:],
                 valid[:12] + b'\x40' + valid[13:],
                 valid[:4] + struct.pack('!H', 2) + valid[6:],
                 valid[:2] + b'\x81\x00' + valid[4:]]
        for query in cases:
            with self.subTest(query=query):
                self.assertIsNone(fixture.loopback_dns_answer(query))

    def test_failover_config_changes_only_dns_timeout_slot(self):
        for timeout in (3, 5):
            config = fixture.engine_config(timeout, 13001, 13002, 19096)
            self.assertIn(f'timeouts 1 5 30 60 10 10 {timeout} 60 2 5', config)
            self.assertIn('nserver 127.0.0.1:13001\nnserver 127.0.0.1:13002', config)
            self.assertIn('nscache6 65536', config)
        for invalid in (True, '3', 0, 31, 3.0):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                fixture.engine_config(invalid, 13001, 13002, 19096)

    def test_nonisolated_main_rejects_before_sockets_or_processes(self):
        with patch.object(fixture.sys, 'platform', 'linux'), \
                patch.dict(fixture.os.environ, {'IPV6_INTEGRATION_ISOLATED': '0'}), \
                patch.object(fixture.socket, 'socket', side_effect=AssertionError('No sockets')), \
                patch.object(fixture.subprocess, 'Popen', side_effect=AssertionError('No process')), \
                patch.object(fixture.subprocess, 'check_output', side_effect=AssertionError('No network inventory')):
            with self.assertRaises(ValueError):
                fixture.main(['--run'])


if __name__ == '__main__':
    unittest.main()
