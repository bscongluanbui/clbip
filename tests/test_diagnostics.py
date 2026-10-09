"""Deterministic diagnostics tests: no DNS, Internet, or NIC mutations."""
import copy
import errno
import ipaddress
import json
import socket
import struct
import threading
import time
import unittest
from unittest.mock import Mock, patch

import diagnostics as d


DOMAIN, IDENT = 'www.bing.com', 1234


def name(value):
    return b''.join(bytes([len(x)]) + x.encode('ascii') for x in value.split('.')) + b'\0'


QUESTION = name(DOMAIN) + struct.pack('!HH', 28, 1)


def record(kind=28, data=None, owner=b'\xc0\x0c', ttl=123, rrclass=1):
    if data is None:
        data = ipaddress.IPv6Address('2606:4700:4700::1111').packed
    return owner + struct.pack('!HHIH', kind, rrclass, ttl, len(data)) + data


def response(answers=None, *, ident=IDENT, flags=0x8180, question=QUESTION,
             qcount=1, authority=(), additional=()):
    answers = [record()] if answers is None else answers
    return struct.pack('!6H', ident, flags, qcount, len(answers), len(authority), len(additional)) + \
        question + b''.join(answers) + b''.join(authority) + b''.join(additional)


class FakeSocket:
    def __init__(self, received=(), error=None):
        self.received = list(received)
        self.error = error
        self.connected, self.timeouts, self.sent = [], [], []
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        self.closed = True

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def connect(self, address):
        self.connected.append(address)

    def send(self, data):
        self.sent.append(data)
        return len(data)

    def sendall(self, data):
        self.sent.append(data)

    def recv(self, maximum):
        if self.error is not None:
            raise self.error
        if not self.received:
            return b''
        data = self.received.pop(0)
        if len(data) > maximum:
            self.received.insert(0, data[maximum:])
        return data[:maximum]


class DiagnosticInputTests(unittest.TestCase):
    def test_url_hostname_idna_and_query_redaction_without_system_resolution(self):
        with patch.object(d.socket, 'getaddrinfo', side_effect=AssertionError('No system resolver')):
            self.assertEqual(d.normalize_domain('https://WWW.BING.COM/path?token=SECRET'), DOMAIN)
            self.assertEqual(d.normalize_domain('BÜCHER.example.'), 'xn--bcher-kva.example')
            self.assertEqual(d.normalize_domain('a.example'), 'a.example')

    def test_hostname_rejects_credentials_controls_bad_labels_and_invalid_url(self):
        for invalid in ('https://USER:SECRET@www.bing.com', 'https://www.bing.com:8443',
                        'https://www.bing.com/#secret', 'http://www.bing.com', '',
                        'a..com', 'a.com..', 'a/com', '-a.com', 'a-.com', 'a' * 64 + '.com',
                        'a.example\nsecret', ' a.example', 'a@example.com', 'a_b.example',
                        'a.' * 127 + 'ab', None, 1):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                d.normalize_domain(invalid)

    def test_numeric_resolver_forms_and_family(self):
        with patch.object(d.socket, 'getaddrinfo', side_effect=AssertionError('No host lookup')):
            self.assertEqual(d.parse_resolver('1.1.1.1'), ('1.1.1.1', 53, socket.AF_INET))
            self.assertEqual(d.parse_resolver('127.0.0.1:5353'), ('127.0.0.1', 5353, socket.AF_INET))
            self.assertEqual(d.parse_resolver('2606:4700:4700::1111'),
                             ('2606:4700:4700::1111', 53, socket.AF_INET6))
            self.assertEqual(d.parse_resolver('[::1]:5353'), ('::1', 5353, socket.AF_INET6))

    def test_invalid_resolver_never_causes_socket_or_hostname_resolution(self):
        for invalid in ('dns.google', '1.1.1.1:0', '1.1.1.1:65536', '1.1.1.1:-1',
                        '1.1.1.1:+53', '1.1.1.1: 53', '[1.1.1.1]:53', '[::1]:wrong',
                        '[::1', 'fe80::1%eth0', '0.0.0.0', '::', 'ff02::1', None):
            with self.subTest(invalid=invalid), \
                    patch.object(d.socket, 'socket', side_effect=AssertionError('No socket')), \
                    self.assertRaises(ValueError):
                d.probe_dns('https://www.bing.com', [invalid])

    def test_limits_rejected_before_socket_and_timeout_is_clamped(self):
        with patch.object(d, 'query_resolver', return_value={'success': True, 'outcome': 'ok', 'elapsed_ms': 1}) as q:
            self.assertEqual(d.probe_dns('https://www.bing.com', ['1.1.1.1'], timeout=0)['timeout_seconds'], 1)
            self.assertEqual(d.probe_dns('https://www.bing.com', ['1.1.1.1'], timeout=100)['timeout_seconds'], 5)
            self.assertEqual([call.args[2] for call in q.call_args_list], [1, 1, 5, 5])
        with patch.object(d.socket, 'socket', side_effect=AssertionError('No socket')):
            for resolvers in ('1.1.1.1', [], ['1.1.1.1'] * 4, {}):
                with self.subTest(resolvers=resolvers), self.assertRaises(ValueError):
                    d.probe_dns('https://www.bing.com', resolvers)
            for timeout in (True, None, '3', float('nan'), float('inf')):
                with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                    d.probe_dns('https://www.bing.com', ['1.1.1.1'], timeout=timeout)
            for rounds in (True, 1, 3, '2'):
                with self.subTest(rounds=rounds), self.assertRaises(ValueError):
                    d.probe_dns('https://www.bing.com', ['1.1.1.1'], rounds=rounds)
            with self.assertRaises(ValueError):
                d.probe_dns('https://1.1.1.1', ['1.1.1.1'])


class DNSPacketTests(unittest.TestCase):
    def test_decodes_actual_aaaa_addresses_ttls_and_global_flag(self):
        packet = response([record(ttl=89), record(data=ipaddress.IPv6Address('fd00::1').packed, ttl=7)])
        report = d.parse_dns_response(packet, IDENT, DOMAIN)
        self.assertEqual(report['rcode'], 0)
        self.assertFalse(report['truncated'])
        self.assertEqual(report['answers'], [
            {'name': DOMAIN, 'address': '2606:4700:4700::1111', 'ttl': 89, 'is_global': True},
            {'name': DOMAIN, 'address': 'fd00::1', 'ttl': 7, 'is_global': False}])

    def test_cname_chain_decoded_and_unrelated_answer_not_a_positive(self):
        packet = response([record(5, name('alias.bing.com'), ttl=71),
                           record(owner=name('alias.bing.com'), ttl=44),
                           record(owner=name('unrelated.example'), ttl=2)])
        result = d.parse_dns_response(packet, IDENT, DOMAIN)
        self.assertEqual(result['cnames'], [{'name': DOMAIN, 'target': 'alias.bing.com', 'ttl': 71}])
        self.assertEqual(result['answers'], [{'name': 'alias.bing.com', 'address': '2606:4700:4700::1111',
                                             'ttl': 44, 'is_global': True}])

    def test_compressed_cname_rdata_and_multiple_cname_hops(self):
        # Pointer to "bing.com" within the query, which begins after "www".
        packet = response([record(5, b'\x05alias\xc0\x10', ttl=7),
                           record(5, name('final.bing.com'), owner=name('alias.bing.com'), ttl=6),
                           record(owner=name('final.bing.com'), ttl=5)])
        result = d.parse_dns_response(packet, IDENT, DOMAIN)
        self.assertEqual([x['target'] for x in result['cnames']], ['alias.bing.com', 'final.bing.com'])
        self.assertEqual(result['answers'][0]['name'], 'final.bing.com')

    def test_rcode_counts_noaaaa_and_additional_addresses_are_not_answer_data(self):
        nxdomain = d.parse_dns_response(response([], flags=0x8183), IDENT, DOMAIN)
        self.assertEqual((nxdomain['rcode'], nxdomain['rcode_name']), (3, 'NXDOMAIN'))
        result = d.parse_dns_response(response([], additional=[record()]), IDENT, DOMAIN)
        self.assertEqual(result['answers'], [])
        self.assertEqual(d.parse_dns_response(response([]), IDENT, DOMAIN)['rcode'], 0)

    def test_extended_rcode_is_not_silently_reported_as_noerror(self):
        opt = record(41, b'', owner=b'\0', ttl=1 << 24, rrclass=4096)
        result = d.parse_dns_response(response([], additional=[opt]), IDENT, DOMAIN)
        self.assertEqual((result['rcode'], result['rcode_name']), (16, 'BADVERS'))

    def test_header_transaction_question_and_question_type_must_match(self):
        invalid = [response(ident=999), response(flags=0x0180), response(flags=0x8980),
                   response(flags=0x81c0), response(qcount=0), response(qcount=2),
                   response(question=name('other.example') + struct.pack('!HH', 28, 1)),
                   response(question=name(DOMAIN) + struct.pack('!HH', 1, 1)),
                   response(question=name(DOMAIN) + struct.pack('!HH', 28, 3)), b'x' * 11]
        for packet in invalid:
            with self.subTest(packet=packet), self.assertRaises(d.DNSPacketError):
                d.parse_dns_response(packet, IDENT, DOMAIN)

    def test_name_parser_guards_cycles_forward_pointers_label_bounds_and_ambiguous_dot(self):
        invalid_questions = [b'\xc0\x0c', b'\xc0\xff', b'\xc0\x00', b'\x40x',
                             b'\x03x', b'\x0cwww.bing.com\0', b'\x03www\x04bing\x03com']
        for question in invalid_questions:
            packet = struct.pack('!6H', IDENT, 0x8180, 1, 0, 0, 0) + question
            with self.subTest(question=question), self.assertRaises(d.DNSPacketError):
                d.parse_dns_response(packet, IDENT, DOMAIN)

    def test_cname_cycles_conflicting_aliases_and_invalid_rdata_are_rejected(self):
        cases = [[record(5, name(DOMAIN))],
                 [record(5, name('alias.bing.com')), record(5, name(DOMAIN), owner=name('alias.bing.com'))],
                 [record(5, name('a.example')), record(5, name('b.example'))],
                 [record(5, name('alias.bing.com') + b'\0')], [record(5, b'\xc0')], [record(5, b'\0')]]
        for records in cases:
            with self.subTest(records=records), self.assertRaises(d.DNSPacketError):
                d.parse_dns_response(response(records), IDENT, DOMAIN)

    def test_length_counts_trailing_bytes_aaaa_length_and_opt_positions_are_bounded(self):
        packets = [response()[:-1], response() + b'x', response([record(data=b'x' * 15)]),
                   response([record(41, b'', owner=b'\0')]),
                   response([], additional=[record(41, b'', owner=b'\0')] * 2),
                   response([], additional=[record(41, b'', owner=name('bad.example'))]),
                   struct.pack('!6H', IDENT, 0x8180, 1, 513, 0, 0) + QUESTION,
                   b'x' * 65536]
        for packet in packets:
            with self.subTest(length=len(packet)), self.assertRaises(d.DNSPacketError):
                d.parse_dns_response(packet, IDENT, DOMAIN)

    def test_truncated_rr_body_can_request_tcp_only_after_question_validation(self):
        packet = struct.pack('!6H', IDENT, 0x8380, 1, 1, 0, 0) + QUESTION + b'\xc0'
        self.assertTrue(d.parse_dns_response(packet, IDENT, DOMAIN)['truncated'])
        with self.assertRaises(d.DNSPacketError):
            d.parse_dns_response(packet, IDENT + 1, DOMAIN)


class DNSProbeTests(unittest.TestCase):
    def run_query(self, udp, *tcp, resolver='1.1.1.1', timeout=3):
        sockets = [udp, *tcp]
        with patch.object(d.socket, 'socket', side_effect=sockets) as maker, \
                patch.object(d.secrets, 'randbits', return_value=IDENT), \
                patch.object(d.socket, 'getaddrinfo', side_effect=AssertionError('No system DNS')):
            result = d.query_resolver(DOMAIN, resolver, timeout)
        return result, maker

    def test_connected_numeric_udp_dns_query_and_no_hostname_resolution(self):
        udp = FakeSocket([response()])
        result, maker = self.run_query(udp)
        self.assertTrue(result['success'])
        self.assertEqual(result['outcome'], 'ok')
        self.assertEqual(result['query_type'], 'AAAA')
        self.assertEqual(result['transport'], 'udp')
        self.assertEqual(udp.connected, [('1.1.1.1', 53)])
        self.assertEqual(udp.sent, [struct.pack('!6H', IDENT, 0x0100, 1, 0, 0, 0) + QUESTION])
        maker.assert_called_once_with(socket.AF_INET, socket.SOCK_DGRAM)
        self.assertTrue(udp.closed)

    def test_ipv6_resolver_uses_numeric_ipv6_sockaddr_and_family(self):
        udp = FakeSocket([response()])
        result, maker = self.run_query(udp, resolver='2606:4700:4700::1111')
        self.assertTrue(result['success'])
        self.assertEqual(udp.connected, [('2606:4700:4700::1111', 53, 0, 0)])
        maker.assert_called_once_with(socket.AF_INET6, socket.SOCK_DGRAM)

    def test_noaaaa_nxdomain_servfail_and_refused_are_different_outcomes(self):
        for flags, expected, code in ((0x8180, 'no_aaaa', 0), (0x8183, 'nxdomain', 3),
                                      (0x8182, 'dns_error', 2), (0x8185, 'dns_error', 5)):
            with self.subTest(code=code):
                report, _ = self.run_query(FakeSocket([response([], flags=flags)]))
                self.assertFalse(report['success'])
                self.assertEqual((report['outcome'], report['rcode']), (expected, code))

    def test_timeout_unreachable_refused_and_malformed_results_do_not_expose_exception_text(self):
        for exception, expected in ((socket.timeout('SECRET'), 'timeout'),
                                     (OSError(errno.ECONNREFUSED, 'SECRET'), 'connection_refused'),
                                     (OSError(errno.ENETUNREACH, 'SECRET'), 'unreachable'),
                                     (OSError(errno.EIO, 'SECRET'), 'network_error')):
            with self.subTest(expected=expected):
                report, _ = self.run_query(FakeSocket(error=exception))
                self.assertFalse(report['success'])
                self.assertEqual(report['outcome'], expected)
                self.assertNotIn('SECRET', json.dumps(report))
        report, _ = self.run_query(FakeSocket([response(ident=2)]))
        self.assertEqual(report['outcome'], 'invalid_response')

    def test_tc_fallback_uses_framed_tcp_and_fragmented_reads(self):
        udp = FakeSocket([response([], flags=0x8380)])
        reply = response()
        tcp = FakeSocket([struct.pack('!H', len(reply))[:1], struct.pack('!H', len(reply))[1:],
                          reply[:7], reply[7:]])
        result, maker = self.run_query(udp, tcp)
        self.assertTrue(result['success'])
        self.assertEqual((result['transport'], result['truncated']), ('tcp', True))
        self.assertEqual(tcp.connected, [('1.1.1.1', 53)])
        self.assertEqual(tcp.sent, [struct.pack('!H', len(udp.sent[0])) + udp.sent[0]])
        self.assertTrue(udp.closed and tcp.closed)
        self.assertEqual(maker.call_args_list[1].args, (socket.AF_INET, socket.SOCK_STREAM))

    def test_tcp_fallback_shares_original_deadline_not_a_second_full_timeout(self):
        udp = FakeSocket([response([], flags=0x8380)])
        reply = response()
        tcp = FakeSocket([struct.pack('!H', len(reply)), reply])
        with patch.object(d.time, 'monotonic', side_effect=[0, .1, .2, .3, 2, 2.1, 2.2, 2.3, 2.4, 2.5]), \
                patch.object(d.socket, 'socket', side_effect=[udp, tcp]), \
                patch.object(d.secrets, 'randbits', return_value=IDENT):
            result = d.query_resolver(DOMAIN, '1.1.1.1', 3)
        self.assertTrue(result['success'])
        self.assertLessEqual(max(tcp.timeouts), 1)
        self.assertGreater(min(tcp.timeouts), 0)

    def test_tcp_cannot_start_when_udp_has_exhausted_deadline(self):
        udp = FakeSocket([response([], flags=0x8380)])
        tcp = FakeSocket()
        with patch.object(d.time, 'monotonic', side_effect=[0, .1, .2, .3, 3.01, 3.02]), \
                patch.object(d.socket, 'socket', side_effect=[udp, tcp]), \
                patch.object(d.secrets, 'randbits', return_value=IDENT):
            result = d.query_resolver(DOMAIN, '1.1.1.1', 3)
        self.assertEqual(result['outcome'], 'timeout')
        self.assertEqual(tcp.connected, [])
        self.assertTrue(tcp.closed)

    def test_tcp_partial_frames_tiny_length_and_truncated_tcp_fail(self):
        udp_packet = response([], flags=0x8380)
        for chunks in ([b'\0'], [b'\0\x0b'], [struct.pack('!H', 100), b'x'],
                       [struct.pack('!H', len(udp_packet)), udp_packet]):
            with self.subTest(chunks=chunks):
                result, _ = self.run_query(FakeSocket([udp_packet]), FakeSocket(chunks))
                self.assertEqual(result['outcome'], 'invalid_response')
                self.assertFalse(result['success'])

    def test_oversized_udp_and_bad_tc_question_never_start_tcp(self):
        for packet in (b'x' * 4097, response([], flags=0x8380, ident=7)):
            with self.subTest(length=len(packet)):
                result, maker = self.run_query(FakeSocket([packet]))
                self.assertEqual(result['outcome'], 'invalid_response')
                self.assertEqual(maker.call_count, 1)

    def test_two_rounds_max_three_concurrent_workers_and_no_cache_hit_claim(self):
        active, maximum, calls = 0, 0, []
        lock = threading.Lock()
        def query(domain, resolver, timeout):
            nonlocal active, maximum
            with lock:
                calls.append((domain, resolver, timeout))
                active += 1
                maximum = max(active, maximum)
            time.sleep(.01)
            with lock:
                active -= 1
            return {'success': True, 'outcome': 'ok', 'elapsed_ms': 12, 'answers': [], 'cnames': []}
        with patch.object(d, 'query_resolver', side_effect=query):
            result = d.probe_dns('https://www.bing.com/?token=SECRET', ['1.1.1.1', '8.8.8.8', '::1'])
        self.assertEqual(len(calls), 6)
        self.assertEqual(maximum, 3)
        self.assertEqual(result['summary']['sample_count'], 6)
        self.assertEqual(result['summary']['p95_ms'], 12)
        self.assertEqual(result['query_type'], 'AAAA')
        self.assertFalse(result['cache_confirmed'])
        self.assertTrue(all(row['cache_confirmed'] is False for row in result['resolvers']))
        self.assertEqual([row['round'] for row in result['resolvers'][0]['probes']], [1, 2])
        self.assertNotIn('SECRET', json.dumps(result))


class DiagnosticHistoryTests(unittest.TestCase):
    def test_empty_window_and_limits(self):
        report = d.DiagnosticHistory().summary()
        self.assertEqual((report['sample_count'], report['scope'], report['max_samples']), (0, 'speedtest_only', 200))
        self.assertIsNone(report['p50_ms'])
        self.assertEqual(report['by_port'], [])
        for invalid in (0, -1, 201, True, '200', 1.5):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                d.DiagnosticHistory(invalid)

    def test_window_bounded_nearest_rank_and_by_port_domain(self):
        history = d.DiagnosticHistory(3)
        for i in range(4):
            history.record({'success': True, 'port': 10000 + i % 2, 'total_time': i / 10,
                            'target_host': 'a.example' if i % 2 else 'b.example'})
        report = history.summary()
        self.assertEqual((report['sample_count'], report['window_size']), (3, 3))
        self.assertEqual((report['p50_ms'], report['p95_ms'], report['p99_ms']), (200, 300, 300))
        self.assertEqual(report['by_port'][0]['port'], 10000)
        self.assertEqual(report['by_port'][1]['sample_count'], 2)
        self.assertEqual(report['by_domain'][0]['domain'], 'a.example')
        self.assertEqual(report['by_domain'][0]['sample_count'], 2)

    def test_curl_error_categories_and_http_auth_target_failures(self):
        history = d.DiagnosticHistory()
        expected = {5: 'dns', 6: 'dns', 7: 'proxy_connect', 28: 'timeout', 35: 'tls',
                    60: 'tls', 52: 'empty_response', 55: 'transport', 56: 'transport'}
        for code in expected:
            history.record({'success': False, 'port': 10000, 'curl_exit': code, 'target_host': DOMAIN})
        history.record({'success': False, 'port': 10000, 'http_connect_code': 407, 'target_host': DOMAIN})
        history.record({'success': False, 'port': 10001, 'http_code': 429, 'target_host': DOMAIN})
        report = history.summary()
        self.assertEqual(report['error_categories'], {'dns': 2, 'proxy_connect': 1, 'timeout': 1,
                                                     'tls': 2, 'empty_response': 1, 'transport': 2,
                                                     'proxy_auth': 1, 'target_http': 1})
        self.assertEqual(report['success_count'], 0)
        self.assertEqual(report['error_count'], 11)
        self.assertIsNone(report['p50_ms'])

    def test_explicit_connect_status_wins_over_curl_receive_or_generic_transport_error(self):
        for code, expected in ((407, 'proxy_auth'), (403, 'proxy_rejected'), (502, 'proxy_connect')):
            for error_type in (None, 'transport'):
                with self.subTest(code=code, error_type=error_type):
                    history = d.DiagnosticHistory()
                    history.record({'success': False, 'port': 10000, 'http_connect_code': code,
                                    'curl_exit': 56, 'error_type': error_type, 'target_host': DOMAIN})
                    self.assertEqual(history.summary()['error_categories'], {expected: 1})
        history = d.DiagnosticHistory()
        history.record({'success': False, 'port': 10000, 'http_connect_code': 200,
                        'curl_exit': 28, 'error_type': 'timeout', 'target_host': DOMAIN})
        self.assertEqual(history.summary()['error_categories'], {'timeout': 1})

    def test_history_has_no_credentials_url_paths_query_error_text_or_mutable_input(self):
        history = d.DiagnosticHistory()
        raw = {'success': False, 'port': 10001, 'latency_ms': 20,
               'target_host': 'https://www.bing.com/SECRET_PATH?token=SECRET_TOKEN',
               'error': 'SECRET_ERROR', 'error_type': 'SECRET_ERROR_TYPE',
               'username': 'SECRET_USER', 'password': 'SECRET_PASSWORD',
               'http_code': '401', 'proxy_url': 'http://USER:PASSWORD@127.0.0.1:10001'}
        before = copy.deepcopy(raw)
        history.record(raw)
        self.assertEqual(raw, before)
        raw['port'], raw['target_host'] = 12345, 'changed.example'
        report = history.summary()
        self.assertNotIn('SECRET', json.dumps(report))
        self.assertNotIn('PASSWORD', json.dumps(report))
        self.assertEqual(report['by_domain'][0]['domain'], DOMAIN)
        self.assertEqual(report['by_port'][0]['port'], 10001)
        self.assertEqual(report['error_categories'], {'target_http': 1})

    def test_invalid_latency_port_domain_and_false_truthy_success_do_not_poison_summary(self):
        history = d.DiagnosticHistory()
        for latency in (True, -1, float('nan'), float('inf'), '1'):
            history.record({'success': 'true', 'port': True, 'latency_ms': latency,
                            'target_host': 'USER:PASSWORD@www.bing.com', 'error_type': 'SECRET'})
        report = history.summary()
        self.assertEqual(report['success_count'], 0)
        self.assertEqual(report['error_count'], 5)
        self.assertEqual(report['latency_sample_count'], 0)
        self.assertEqual(report['by_port'], [])
        self.assertEqual(report['by_domain'][0]['domain'], 'unknown')
        self.assertNotIn('SECRET', json.dumps(report))
        with self.assertRaises(ValueError):
            history.record('invalid')

    def test_record_and_summary_thread_safe_and_output_is_detached(self):
        history = d.DiagnosticHistory(200)
        def record_many(port):
            for _ in range(100):
                history.record({'success': True, 'port': port, 'target_host': DOMAIN, 'latency_ms': port})
                history.summary()
        threads = [threading.Thread(target=record_many, args=(10000 + i,)) for i in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        report = history.summary()
        self.assertEqual(report['sample_count'], 200)
        self.assertEqual(report['success_count'], 200)
        report['by_domain'][0]['domain'] = 'changed'
        report['error_categories']['secret'] = 1
        self.assertEqual(history.summary()['by_domain'][0]['domain'], DOMAIN)
        self.assertEqual(history.summary()['error_categories'], {})


if __name__ == '__main__':
    unittest.main()
