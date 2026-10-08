#!/usr/bin/env python3
"""Read-only localhost UI preview using simulated data, with no real worker."""
from __future__ import annotations

import argparse
import copy
import os
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
DEMO_PASSWORD = 'ReadOnly_Preview_Demo_2026!'


class PreviewClient:
    """A strict offline read-method allowlist; no system/network backend import."""
    def __init__(self):
        now = time.time()
        base = {'address': '2001:db8:abcd:1200::8', 'prefix_len': 64, 'interface': 'eth0'}
        self.settings = {'subnet': '2001:db8:abcd:1200::', 'prefix_len': 64, 'interface': 'eth0',
                         'start_port': 10000, 'protocol': 'dual', 'auth_type': 'userpass',
                         'allowed_ips': [], 'listener_ipv4': '0.0.0.0', 'public_proxy': False,
                         'dns1': '1.1.1.1', 'dns2': '8.8.8.8', 'max_connections': 64,
                         'timeout_connect': 10, 'timeout_idle': 300, 'rotation_enabled': False,
                         'rotation_interval': 10, 'auto_start': True, 'startup_rebuild_enabled': True,
                         'startup_proxy_count': 100, 'source_change_confirmations': 2, 'source_poll_interval': 5,
                         'topology_mode': 'lan', 'routed_prefix': '', 'probe_url': 'https://api64.ipify.org',
                         'telegram_bot_token_configured': False, 'telegram_chat_id': '',
                         'telegram_allowed_user_ids': []}
        self.proxies = [{'id': index+1, 'ipv6': f'2001:db8:abcd:1200::{256+index:x}',
                         'interface': 'eth0', 'prefix_len': 64, 'address_prefix_len': 128,
                         'subnet': self.settings['subnet'], 'port': 10000+index,
                         'socks_port': 20000+index, 'protocol': 'dual', 'status': 'active',
                         'username': 'demo', 'created_at': 'DEMO'} for index in range(100)]
        progress = {'stage': 'complete', 'total': 100, 'added': 100, 'ready': 100, 'verified': 100,
                    'active': False, 'failed': False, 'elapsed_seconds': 22, 'last_update': now,
                    'last_error': '', 'address': ''}
        self.responses = {
            'settings': self.settings,
            'users': {'users': [{'username': 'demo', 'created_at': 'DEMO'}]},
            'status': {'proxy_running': True, 'total_proxies': 100, 'total_users': 1,
                       'desired_state': 'running', 'desired_running': True, 'revision': 4,
                       'interface': 'eth0', 'subnet': self.settings['subnet'], 'protocol': 'dual',
                       'auth_type': 'userpass', 'rotation_enabled': False, 'rotation_interval': 10,
                       'last_error': '', 'operation_pending': False, 'uncertain_addresses': [],
                       'progress': progress, 'current_source': base, 'source_verified': True,
                       'source_observed_at': now, 'source_error': '',
                       'dashboard_hosts': ['192.168.1.20', '100.98.10.20'],
                       'proxy_hosts': ['192.168.1.20', '100.98.10.20'],
                       'startup_recovery': {'enabled': True, 'state': 'ready', 'phase': 'done',
                                            'message': 'DEMO: 100 proxy mô phỏng đã sẵn sàng',
                                            'target_count': 100, 'base_ipv6': base['address'],
                                            'base_interface': 'eth0', 'completed_at': now}},
            'proxies': {'proxies': self.proxies, 'total': 100, 'running': True, 'instances': 1,
                        'running_instances': 1, 'desired_state': 'running', 'desired_running': True},
            'health': {'ready': True, 'desired_state': 'running', 'errors': [],
                       'instances_total': 1, 'instances_running': [{'pid': 12345, 'memory_kb': 16384}],
                       'processes': {'ready': True, 'expected': 1, 'running': 1},
                       'tcp': {'established': 8, 'time_wait': 12}, 'system': {'uptime_minutes': 42}},
            'interfaces': {'interfaces': ['eth0', 'wlan0', 'tailscale0'], 'details': [
                {'device': 'eth0', 'name': 'Ethernet (demo)', 'kind': 'ethernet', 'active': True,
                 'pool_capable': True, 'ipv4': ['192.168.1.20'], 'ipv6': [base], 'reason': ''},
                {'device': 'wlan0', 'name': 'Wi-Fi (demo)', 'kind': 'wifi', 'active': False,
                 'pool_capable': False, 'ipv4': [], 'ipv6': [], 'reason': 'Card chưa kết nối (demo).'},
                {'device': 'tailscale0', 'name': 'Tailscale (demo)', 'kind': 'tailscale', 'active': True,
                 'pool_capable': False, 'ipv4': ['100.98.10.20'], 'ipv6': [],
                 'reason': 'IPv6 overlay không phải prefix global để tạo pool (demo).'}]},
            'subnets': {'interface': 'eth0', 'subnets': [{'subnet': self.settings['subnet'],
                        'prefix_len': 64, 'full': self.settings['subnet']+'/64',
                        'source_address': base['address'], 'verified': True}]},
            'addresses': {'addresses': [{**base, 'scope': 'global', 'ready': True, 'flags': []}]},
            'logs': {'logs': 'DEMO ONLY: pool simulation complete; no real worker was connected.'},
            'events': {'events': [{'time': now, 'action': 'preview', 'detail': 'DEMO: read-only UI'}]},
        }

    def call(self, method, params=None):
        if method not in self.responses:
            from rpc import RpcError
            raise RpcError('Bản preview chỉ đọc: thao tác điều khiển và export đã tắt.', 403)
        return copy.deepcopy(self.responses[method])


def create_preview_app(port=17070):
    sys.path.insert(0, str(ROOT)) if str(ROOT) not in sys.path else None
    # app has a module-level default app; do not let its initial import inherit
    # production credential-file paths. Explicit preview credentials stay in RAM.
    protected = {key: value for key, value in os.environ.items()
                 if any(word in key for word in ('SECRET', 'PASSWORD', 'SERVICE_TOKEN', 'CREDENTIAL'))}
    try:
        for key in protected:
            os.environ.pop(key, None)
        from app import create_app
        return create_app({'SECRET_KEY': secrets.token_hex(32), 'SERVICE_TOKEN': secrets.token_hex(32),
                           'ADMIN_PASSWORD': DEMO_PASSWORD, 'PREVIEW': True,
                           'GUI_PORT': port, 'GUI_BIND': '127.0.0.1',
                           'SESSION_COOKIE_SECURE': False,
                           'TRUSTED_HOSTS': ['127.0.0.1', 'localhost', '[::1]']}, client=PreviewClient())
    finally:
        os.environ.update(protected)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', type=int, default=17070)
    args = parser.parse_args(argv)
    if not 1024 <= args.port <= 65535:
        parser.error('--port must be in 1024..65535')
    app = create_preview_app(args.port)
    print(f'DEMO_READ_ONLY=http://127.0.0.1:{args.port}', flush=True)
    print(f'DEMO_PASSWORD={DEMO_PASSWORD}', flush=True)
    app.run(host='127.0.0.1', port=args.port, debug=False, use_reloader=False)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
