"""Opt-in real 3proxy test in a network-none private Docker namespace only.

Requires IPV6_INTEGRATION_ISOLATED=1 and --run. Never run against host networking.
No Internet traffic: all source/destination sockets and aliases belong to lo.
"""
import argparse
import http.server
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.parse_args(argv)
    if sys.platform != 'linux' or os.getenv('IPV6_INTEGRATION_ISOLATED') != '1':
        raise SystemExit('Isolated Linux container opt-in required')
    snapshot = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show']))
    if {row['ifname'] for row in snapshot} != {'lo'}:
        raise SystemExit('Only network-none namespace with lo is accepted')
    root = Path('/app') if Path('/app/proxy_config.py').is_file() else Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    import proxy_config as engine
    from validation import DEFAULT_SETTINGS
    source, target = 'fd00:1::2', 'fd00:1::1'
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    created = []
    server = unrelated = None
    checks = []
    class Server(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = str(ipaddress.IPv6Address(self.client_address[0])).encode()
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *args):
            pass
    def check(name, condition):
        if not condition:
            raise AssertionError(name)
        checks.append(name)
    try:
        for address in (target, source):
            subprocess.run(['ip', '-6', 'addr', 'add', address + '/128', 'dev', 'lo', 'nodad', 'noprefixroute'], check=True)
            created.append(address)
        server = Server((target, 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = f'http://[{target}]:{server.server_port}/'
        settings = {**DEFAULT_SETTINGS, 'allow_private_destinations': True, 'log_enabled': False}
        users = [{'username': 'integration', 'password': 'Integration_Only_42!'}]
        proxies = [{'ipv6': source, 'port': 19001, 'protocol': 'http'},
                   {'ipv6': source, 'port': 19002, 'socks_port': 19003, 'protocol': 'dual'}]
        engine.PROXIES_PER_INSTANCE = 1
        unrelated = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)'])
        def request(protocol, port, password='Integration_Only_42!'):
            config = 'proxy-user = ' + json.dumps('integration:' + password) + '\n'
            return subprocess.run(['curl', '--disable', '--config', '-', '--silent', '--fail', '--noproxy', '',
                                   '--connect-timeout', '2', '--max-time', '5', '--proxy',
                                   f'{protocol}://127.0.0.1:{port}', '--url', url],
                                  input=config, text=True, capture_output=True, timeout=7)
        engine.save_config(engine.generate_config(proxies, users, settings))
        ok, message = engine.start_3proxy()
        check('multi_instance_readiness', ok and engine.running_instances()['running'] == 2)
        for protocol, port in [('http', 19001), ('http', 19002), ('socks5h', 19003)]:
            response = request(protocol, port)
            check('source_' + protocol + '_' + str(port), response.returncode == 0 and response.stdout.strip() == source)
        check('wrong_credential_denied', request('http', 19001, 'Wrong_42!').returncode != 0)
        metrics = engine.process_metrics()
        check('owned_rss_fd', metrics['process_count'] == 2 and metrics['rss_bytes'] > 0 and metrics['fd_count'] > 0)
        settings['allow_private_destinations'] = False
        engine.save_config(engine.generate_config(proxies, users, settings))
        check('restart', engine.restart_3proxy()[0])
        check('destination_acl_denied', request('http', 19001).returncode != 0)
        settings['allow_private_destinations'] = True
        users[0]['password'] = 'Revoked_New_42!'
        engine.save_config(engine.generate_config(proxies, users, settings))
        check('credential_apply', engine.restart_3proxy()[0])
        check('old_credential_revoked', request('http', 19001).returncode != 0)
        check('new_credential_works', request('http', 19001, 'Revoked_New_42!').stdout.strip() == source)
        engine.save_config(engine.generate_config([], users, settings))
        observed = engine.running_instances()
        check('empty_manifest_does_not_hide_owned', observed['running'] == 2 and not observed['ready'])
        check('observed_stop', engine.stop_3proxy()[0] and engine.running_instances()['running'] == 0)
        check('unrelated_process_untouched', unrelated.poll() is None)
        print(f'LINUX_ENGINE_CHECKS={len(checks)} PASS={len(checks)} FAIL=0 INTERNET_CALLS=0 HOST_NIC_CHANGES=0')
        return 0
    finally:
        engine.stop_3proxy()
        if unrelated is not None:
            unrelated.terminate()
            unrelated.wait(timeout=5)
        if server is not None:
            server.shutdown()
            server.server_close()
        for address in created:
            subprocess.run(['ip', '-6', 'addr', 'del', address + '/128', 'dev', 'lo'], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    raise SystemExit(main())
