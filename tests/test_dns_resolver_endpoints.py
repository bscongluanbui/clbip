"""Numeric resolver rendering: 3proxy must not parse an IPv6 hextet as a port."""
import copy
import ipaddress
import unittest
from unittest.mock import patch

import proxy_config as pc


USER = {'username': 'fixture', 'password': 'fixture_only_123'}
PROXY = {'ipv6': '2001:db8::10', 'port': 10000, 'protocol': 'http'}
SETTINGS = {'auth_type': 'userpass', 'log_enabled': False}


def render(**settings):
    with patch.object(pc, 'DATA_DIR', '/app/data'), \
            patch.object(pc.socket, 'getaddrinfo', side_effect=AssertionError('DNS forbidden')), \
            patch.object(pc.subprocess, 'Popen', side_effect=AssertionError('Process forbidden')):
        return pc._generate_single_config([PROXY], [USER], {**SETTINGS, **settings})


def dns_lines(config):
    return [line for line in config.splitlines() if line.startswith('nserver ')]


class DnsEndpointTests(unittest.TestCase):
    def test_ipv4_defaults_unchanged(self):
        self.assertEqual(dns_lines(render()), [
            'nserver 127.0.0.1', 'nserver 8.8.8.8', 'nserver 1.1.1.1'])

    def test_ipv4_ports_canonical_and_unchanged(self):
        self.assertEqual(dns_lines(render(
            dns1='127.0.0.1:5353', dns2='8.8.8.8:53', dns3='1.1.1.1:00053')),
            ['nserver 127.0.0.1:5353', 'nserver 8.8.8.8:53', 'nserver 1.1.1.1:53'])

    def test_ipv6_resolver_brackets_all_dns_slots(self):
        values = ['2606:4700:4700::1111', '2606:4700:4700::1001', '2001:4860:4860::8888']
        self.assertEqual(dns_lines(render(**dict(zip(('dns1', 'dns2', 'dns3'), values)))),
                         [f'nserver [{value}]' for value in values])

    def test_ipv6_expanded_mixedcase_is_canonical(self):
        self.assertEqual(dns_lines(render(
            dns1='2606:4700:4700:0000:0000:0000:0000:ABCD'))[0],
            'nserver [2606:4700:4700::abcd]')

    def test_last_hextet_is_not_a_resolver_port(self):
        for value in ('2001:db8::53', '2001:db8::5353', '2001:db8::1:53', '2001:db8::6553'):
            with self.subTest(value=value):
                self.assertEqual(dns_lines(render(dns1=value))[0], f'nserver [{value}]')

    def test_loopback_and_ipv4mapped_dns_are_still_numeric(self):
        for value in ('::1', '::ffff:192.0.2.1'):
            with self.subTest(value=value):
                self.assertEqual(dns_lines(render(dns1=value))[0],
                                 f'nserver [{ipaddress.IPv6Address(value)}]')

    def test_malformed_dns_stays_rejected(self):
        for value in ('fe80::1%eth0', '[2606:4700:4700::1111]',
                      '[2606:4700:4700::1111]:53',
                      '2606:4700:4700::1111\nnserver 1.1.1.1', 'resolver.example',
                      '127.0.0.1:0', '127.0.0.1:65536'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                render(dns1=value)

    def test_ipv6_external_source_format_unchanged(self):
        config = render(dns1='2606:4700:4700::1111')
        self.assertIn('external 2001:db8::10\n', config)
        self.assertIn('proxy -6 -p10000\n', config)
        self.assertNotIn('external [', config)

    def test_renderer_does_not_mutate_inputs(self):
        proxies = [dict(PROXY)]
        users = [dict(USER)]
        settings = {**SETTINGS, 'dns1': '2606:4700:4700::1111'}
        before = copy.deepcopy((proxies, users, settings))
        pc._generate_single_config(proxies, users, settings)
        self.assertEqual((proxies, users, settings), before)

    def test_only_nserver_lines_change_for_ipv6(self):
        settings = {'dns1': '2606:4700:4700::1111', 'dns2': '1.1.1.1:5353',
                    'dns3': '2001:4860:4860::8888'}
        with patch.object(pc, '_nserver_endpoint', side_effect=lambda value: value):
            before = render(**settings)
        after = render(**settings)
        self.assertNotEqual(dns_lines(before), dns_lines(after))
        self.assertEqual([line for line in before.splitlines() if not line.startswith('nserver ')],
                         [line for line in after.splitlines() if not line.startswith('nserver ')])


if __name__ == '__main__':
    unittest.main()
