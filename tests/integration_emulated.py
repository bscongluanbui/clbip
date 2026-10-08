"""Opt-in 3proxy protocol acceptance in a network-none QEMU container.

Production process ownership is deliberately not exercised or changed here:
user-mode emulation can expose the emulator in /proc/<child>/exe. Every process
terminated by this fixture is its own tracked foreground Popen child. Native
architecture jobs still run integration_linux.py for production ownership.
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
import tempfile
import threading
import time


def require_emulated_opt_in(platform, opt_in):
    if platform != 'linux' or opt_in != '1':
        raise ValueError('Emulated Linux container opt-in required')


def require_isolated_namespace(platform, opt_in, links):
    require_emulated_opt_in(platform, opt_in)
    if (not isinstance(links, list) or not all(isinstance(row, dict) for row in links)
            or {row.get('ifname') for row in links} != {'lo'}):
        raise ValueError('Only network-none namespace with lo is accepted')


def stop_tracked_child(process):
    """Signal only the exact Popen child retained by this isolated fixture."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def curl_arguments(protocol, port, url):
    if protocol not in {'http', 'socks5h'}:
        raise ValueError('Unsupported test proxy protocol')
    return ['curl', '--disable', '--config', '-', '--silent', '--fail', '--noproxy', '',
            '--connect-timeout', '5', '--max-time', '20', '--proxy',
            f'{protocol}://127.0.0.1:{port}', '--url', url]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.parse_args(argv)
    # Check opt-in before even reading networking state; reject host networking
    # before any mutation or process creation.
    require_emulated_opt_in(sys.platform, os.getenv('IPV6_INTEGRATION_EMULATED'))
    links = json.loads(subprocess.check_output(['ip', '-j', 'link', 'show']))
    require_isolated_namespace(sys.platform, os.getenv('IPV6_INTEGRATION_EMULATED'), links)
    root = Path('/app') if Path('/app/proxy_config.py').is_file() else Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    import proxy_config as engine
    from validation import DEFAULT_SETTINGS

    source, target = 'fd00:2::2', 'fd00:2::1'
    created, children, checks = [], [], []
    server = unrelated = None
    server_thread = None
    settings = {**DEFAULT_SETTINGS, 'allow_private_destinations': True, 'log_enabled': False}
    users = [{'username': 'integration', 'password': 'Integration_Only_42!'}]
    groups = [[{'ipv6': source, 'port': 19001, 'protocol': 'http'}],
              [{'ipv6': source, 'port': 19002, 'socks_port': 19003, 'protocol': 'dual'}]]

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

    def stop_proxies():
        for child in children:
            stop_tracked_child(child)
        children.clear()

    try:
        subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
        for address in (target, source):
            subprocess.run(['ip', '-6', 'addr', 'add', address + '/128', 'dev', 'lo', 'nodad', 'noprefixroute'], check=True)
            created.append(address)
        server = Server((target, 0), Handler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()
        url = f'http://[{target}]:{server.server_port}/'
        unrelated = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(600)'])

        def request(protocol, port, password='Integration_Only_42!'):
            config = 'proxy-user = ' + json.dumps('integration:' + password) + '\n'
            return subprocess.run(curl_arguments(protocol, port, url), input=config,
                                  text=True, capture_output=True, timeout=25)

        with tempfile.TemporaryDirectory(prefix='emulated-engine-') as temporary:
            directory = Path(temporary)

            def start_proxies():
                # Generate normal validated foreground config, but do not write
                # the production config/process ledger or invoke its lifecycle.
                stop_proxies()
                for index, group in enumerate(groups):
                    path = directory / f'{index}.cfg'
                    path.write_text(engine._generate_single_config(group, users, settings, index, len(groups)))
                    children.append(subprocess.Popen([engine.PROXY_BINARY, str(path)],
                                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                                     stderr=subprocess.DEVNULL, close_fds=True))
                deadline = time.monotonic() + 45
                while True:
                    if any(child.poll() is not None for child in children):
                        raise RuntimeError('Tracked foreground 3proxy exited during emulated startup')
                    ready = True
                    for port in (19001, 19002, 19003):
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=0.5):
                                pass
                        except OSError:
                            ready = False
                    if ready:
                        return
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Emulated 3proxy listeners did not become ready')
                    time.sleep(0.2)

            start_proxies()
            check('direct_foreground_instances_and_listeners', len(children) == 2 and all(child.poll() is None for child in children))
            for protocol, port in [('http', 19001), ('http', 19002), ('socks5h', 19003)]:
                response = request(protocol, port)
                check('source_' + protocol + '_' + str(port), response.returncode == 0 and response.stdout.strip() == source)
            for protocol, port in [('http', 19001), ('socks5h', 19003)]:
                check('wrong_credential_' + protocol, request(protocol, port, 'Wrong_42!').returncode != 0)
            settings['allow_private_destinations'] = False
            start_proxies()
            for protocol, port in [('http', 19001), ('socks5h', 19003)]:
                check('destination_acl_' + protocol, request(protocol, port).returncode != 0)
            settings['allow_private_destinations'] = True
            users[0]['password'] = 'Revoked_New_42!'
            start_proxies()
            for protocol, port in [('http', 19001), ('socks5h', 19003)]:
                check('old_credential_revoked_' + protocol, request(protocol, port).returncode != 0)
                response = request(protocol, port, 'Revoked_New_42!')
                check('new_credential_source_' + protocol, response.returncode == 0 and response.stdout.strip() == source)
            stopped = list(children)
            stop_proxies()
            check('tracked_children_stopped', all(child.poll() is not None for child in stopped))
            check('unrelated_child_untouched', unrelated.poll() is None)
    finally:
        stop_proxies()
        if unrelated is not None:
            stop_tracked_child(unrelated)
        if server is not None:
            server.shutdown()
            server.server_close()
        if server_thread is not None:
            server_thread.join(timeout=5)
        for address in reversed(created):
            subprocess.run(['ip', '-6', 'addr', 'del', address + '/128', 'dev', 'lo'], check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f'EMULATED_ENGINE_CHECKS={len(checks)} PASS={len(checks)} FAIL=0 '
          'PRODUCTION_OWNERSHIP=NOT_VALIDATED INTERNET_CALLS=0 HOST_NIC_CHANGES=0')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
