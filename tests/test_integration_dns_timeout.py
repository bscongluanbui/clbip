"""Offline isolation gates for the real-engine DNS/client-abort regression."""
import copy
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location(
    'dns_timeout_integration_fixture', Path(__file__).with_name('integration_dns_timeout.py'))
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class DnsTimeoutFixtureTests(unittest.TestCase):
    @staticmethod
    def default_tunnel(name):
        kind, zero = ('sit', '0.0.0.0') if name == 'sit0' else ('ip6tnl', '::')
        return {'ifname': name, 'flags': ['NOARP'], 'operstate': 'DOWN', 'address': zero,
                'linkinfo': {'info_kind': kind, 'info_data': {'local': zero, 'remote': 'any'}}}

    @classmethod
    def tunnel_inventory(cls, names=('sit0', 'ip6tnl0')):
        links = [{'ifname': 'lo', 'flags': ['LOOPBACK', 'UP']}]
        links.extend(cls.default_tunnel(name) for name in names)
        addresses = [{'ifname': 'lo', 'addr_info': [{'family': 'inet', 'local': '127.0.0.1'},
                                                  {'family': 'inet6', 'local': '::1'}]}]
        addresses.extend({'ifname': name, 'addr_info': []} for name in names)
        return links, addresses

    def test_linux_explicit_optin_and_only_loopback_are_required(self):
        links = [{'ifname': 'lo', 'flags': ['LOOPBACK', 'UP']}]
        original = copy.deepcopy(links)
        with patch('socket.socket', side_effect=AssertionError('No socket in isolation gate')), \
                patch('subprocess.Popen', side_effect=AssertionError('No process in isolation gate')):
            self.assertIsNone(fixture.require_isolated_namespace('linux', '1', links))
        self.assertEqual(links, original)

    def test_nonlinux_is_rejected_without_sockets_or_processes(self):
        for platform in ('win32', 'darwin', 'linux2', '', None):
            with self.subTest(platform=platform), \
                    patch('socket.socket', side_effect=AssertionError('No socket')), \
                    patch('subprocess.Popen', side_effect=AssertionError('No process')):
                with self.assertRaises(ValueError):
                    fixture.require_isolated_namespace(platform, '1', [{'ifname': 'lo'}])

    def test_implicit_or_truthy_optin_is_not_accepted(self):
        for optin in (None, '', '0', 'true', 'yes', 1, True):
            with self.subTest(optin=optin):
                with self.assertRaises(ValueError):
                    fixture.require_isolated_namespace('linux', optin, [{'ifname': 'lo'}])

    def test_host_lan_wifi_docker_or_vpn_interfaces_are_rejected(self):
        for interface in ('eth0', 'en0', 'wlan0', 'docker0', 'tailscale0', 'vethfixture'):
            with self.subTest(interface=interface):
                with self.assertRaises(ValueError):
                    fixture.require_isolated_namespace('linux', '1', [{'ifname': 'lo'}, {'ifname': interface}])

    def test_missing_loopback_and_malformed_inventory_are_rejected(self):
        for links in (None, {}, 'lo', [], [None], ['lo'], [{}], [{'ifname': None}],
                      [{'ifname': ''}], [{'ifname': 'lo'}, {}], [{'ifname': 'eth0'}]):
            with self.subTest(links=links):
                with self.assertRaises(ValueError):
                    fixture.require_isolated_namespace('linux', '1', links)

    def test_default_inactive_kernel_tunnels_are_accepted_without_network_calls(self):
        for names in (('sit0',), ('ip6tnl0',), ('sit0', 'ip6tnl0')):
            links, addresses = self.tunnel_inventory(names)
            original_links, original_addresses = copy.deepcopy(links), copy.deepcopy(addresses)
            with self.subTest(names=names), \
                    patch('socket.socket', side_effect=AssertionError('No socket')), \
                    patch('subprocess.Popen', side_effect=AssertionError('No process')):
                self.assertIsNone(fixture.require_isolated_namespace('linux', '1', links, addresses))
            self.assertEqual(links, original_links)
            self.assertEqual(addresses, original_addresses)

    def test_tunnel_endpoints_accept_only_any_or_own_family_zero(self):
        for name, zero in (('sit0', '0.0.0.0'), ('ip6tnl0', '::')):
            for local, remote in (('any', 'any'), (zero, zero), ('any', zero)):
                links, addresses = self.tunnel_inventory((name,))
                links[1]['linkinfo']['info_data'].update(local=local, remote=remote)
                with self.subTest(name=name, local=local, remote=remote):
                    self.assertIsNone(fixture.require_isolated_namespace('linux', '1', links, addresses))

    def test_active_tunnel_flags_or_operstate_are_rejected(self):
        for flags, state in ((['NOARP', 'UP'], 'DOWN'), (['NOARP', 'LOWER_UP'], 'DOWN'),
                             (['NOARP'], 'UP'), (['NOARP'], 'UNKNOWN'), (['NOARP'], None)):
            links, addresses = self.tunnel_inventory()
            links[1].update(flags=flags, operstate=state)
            with self.subTest(flags=flags, state=state):
                with self.assertRaises(ValueError):
                    fixture.require_isolated_namespace('linux', '1', links, addresses)

    def test_malformed_or_missing_noarp_tunnel_flags_are_rejected(self):
        for flags in (None, 'NOARP', {}, [], ['BROADCAST'], [None, 'NOARP'], [True, 'NOARP']):
            links, addresses = self.tunnel_inventory()
            links[1]['flags'] = flags
            with self.subTest(flags=flags):
                with self.assertRaises(ValueError):
                    fixture.require_isolated_namespace('linux', '1', links, addresses)

    def test_configured_or_wrong_family_tunnel_endpoints_are_rejected(self):
        for name, invalid in (('sit0', '192.0.2.1'), ('sit0', '::'), ('ip6tnl0', '2001:db8::1'),
                              ('ip6tnl0', '0.0.0.0'), ('sit0', None), ('ip6tnl0', '')):
            for endpoint in ('local', 'remote'):
                links, addresses = self.tunnel_inventory((name,))
                links[1]['linkinfo']['info_data'][endpoint] = invalid
                with self.subTest(name=name, endpoint=endpoint, invalid=invalid):
                    with self.assertRaises(ValueError):
                        fixture.require_isolated_namespace('linux', '1', links, addresses)

    def test_missing_tunnel_endpoint_or_wrong_kind_is_rejected(self):
        for mutation in ('no_info', 'no_kind', 'wrong_kind', 'no_data', 'no_local', 'no_remote'):
            links, addresses = self.tunnel_inventory()
            tunnel = links[1]
            if mutation == 'no_info':
                tunnel.pop('linkinfo')
            elif mutation == 'no_kind':
                tunnel['linkinfo'].pop('info_kind')
            elif mutation == 'wrong_kind':
                tunnel['linkinfo']['info_kind'] = 'veth'
            elif mutation == 'no_data':
                tunnel['linkinfo'].pop('info_data')
            else:
                tunnel['linkinfo']['info_data'].pop(mutation[3:])
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    fixture.require_isolated_namespace('linux', '1', links, addresses)

    def test_real_or_missing_tunnel_link_address_is_rejected(self):
        for name, invalid in (('sit0', '192.0.2.1'), ('sit0', '::'), ('ip6tnl0', '2001:db8::1'),
                              ('ip6tnl0', '0.0.0.0'), ('sit0', None), ('ip6tnl0', '')):
            links, addresses = self.tunnel_inventory((name,))
            links[1]['address'] = invalid
            with self.subTest(name=name, invalid=invalid):
                with self.assertRaises(ValueError):
                    fixture.require_isolated_namespace('linux', '1', links, addresses)

    def test_tunnel_address_inventory_is_mandatory_complete_and_exact(self):
        links, addresses = self.tunnel_inventory()
        for invalid in (None, [], {}, 'unknown', addresses[:1], addresses + [{'ifname': 'eth0', 'addr_info': []}],
                        [None], [{'ifname': 'lo'}, {'ifname': 'sit0'}, {'ifname': 'ip6tnl0'}]):
            with self.subTest(addresses=invalid):
                with self.assertRaises(ValueError):
                    fixture.require_isolated_namespace('linux', '1', links, invalid)

    def test_any_assigned_ipv4_or_ipv6_tunnel_address_is_rejected(self):
        for info in ([{'family': 'inet', 'local': '192.0.2.1'}],
                     [{'family': 'inet6', 'local': '2001:db8::1'}],
                     [{'family': 'inet6', 'local': 'fe80::1'}], None, {}, ''):
            links, addresses = self.tunnel_inventory()
            addresses[1]['addr_info'] = info
            with self.subTest(addr_info=info):
                with self.assertRaises(ValueError):
                    fixture.require_isolated_namespace('linux', '1', links, addresses)

    def test_renamed_or_real_interface_is_not_an_allowed_default_tunnel(self):
        for name in ('sit1', 'ip6tnl1', 'eth0', 'wlan0', 'veth0', 'dummy0'):
            links, addresses = self.tunnel_inventory(('sit0',))
            links[1]['ifname'] = addresses[1]['ifname'] = name
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    fixture.require_isolated_namespace('linux', '1', links, addresses)

    def test_process_metrics_use_real_threads_field_and_fd_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '42' / 'fd').mkdir(parents=True)
            (root / '42' / 'status').write_text('Name:\t3proxy\nThreads:\t4\n', encoding='ascii')
            for descriptor in ('0', '1', '2', '9'):
                (root / '42' / 'fd' / descriptor).write_text('', encoding='ascii')
            with patch('subprocess.Popen', side_effect=AssertionError('Read /proc, do not start process')):
                self.assertEqual(fixture.parse_process_metrics(42, proc_root=root), {'threads': 4, 'fd_count': 4})

    def test_missing_process_or_fd_is_not_a_fake_zero(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(OSError):
                fixture.parse_process_metrics(42, proc_root=root)
            (root / '42').mkdir()
            (root / '42' / 'status').write_text('Threads:\t4\n', encoding='ascii')
            with self.assertRaises(OSError):
                fixture.parse_process_metrics(42, proc_root=root)

    def test_missing_or_invalid_thread_count_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '42' / 'fd').mkdir(parents=True)
            for status in ('Name:\t3proxy\n', 'Threads:\tabc\n', 'Threads:\t-1\n',
                           'Threads:\t0\n', 'Threads:\t1.5\n'):
                with self.subTest(status=status):
                    (root / '42' / 'status').write_text(status, encoding='ascii')
                    with self.assertRaises(ValueError):
                        fixture.parse_process_metrics(42, proc_root=root)


if __name__ == '__main__':
    unittest.main()
