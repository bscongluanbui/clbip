"""Real DNS-timeout and abandoned-client regression in network-none Docker only.

The loopback UDP resolver receives queries and deliberately never responds.
3proxy 0.9.5 multiplied milliseconds a second time in sockrecvfrom(), retaining
threads and client sockets for hours. The released 0.9.6 includes release-branch
fix 6e55af7f4865aa6f6deda7d8366d19ff687c5477 (master db618f780ba0449316a462421ade04bd9e23dc1c).
No Internet or production ledger access.
Works with native Linux or QEMU: only its own foreground Popen child is stopped.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time


def require_isolated_namespace(platform, opt_in, links, addresses=None):
    if platform != 'linux' or opt_in != '1':
        raise ValueError('Isolated Linux container opt-in required')
    if not isinstance(links, list) or not all(isinstance(row, dict) for row in links):
        raise ValueError('Only network-none namespace with lo is accepted')
    names = [row.get('ifname') for row in links]
    if (not all(isinstance(name, str) for name in names) or len(set(names)) != len(names)
            or 'lo' not in names or set(names) - {'lo', 'sit0', 'ip6tnl0'}):
        raise ValueError('Only network-none namespace with lo is accepted')
    tunnels = [row for row in links if row['ifname'] != 'lo']
    if not tunnels:
        return
    # Some kernels create these two default tunnel devices even with --network
    # none. Accept only their verified inactive/unconfigured forms, not usable
    # tunnels or a host NIC. The experiment itself still binds/mutates only lo.
    if (not isinstance(addresses, list) or not all(isinstance(row, dict) for row in addresses)
            or len(addresses) != len(links)
            or not all(isinstance(row.get('ifname'), str) for row in addresses)
            or {row.get('ifname') for row in addresses} != set(names)):
        raise ValueError('Default tunnel address observations required')
    by_name = {row['ifname']: row for row in addresses}
    for row in tunnels:
        kind, zero = ('sit', '0.0.0.0') if row['ifname'] == 'sit0' else ('ip6tnl', '::')
        flags = row.get('flags')
        linkinfo = row.get('linkinfo')
        data = linkinfo.get('info_data') if isinstance(linkinfo, dict) else None
        if (not isinstance(flags, list) or not all(isinstance(flag, str) for flag in flags)
                or 'NOARP' not in flags or {'UP', 'LOWER_UP'} & set(flags)
                or row.get('operstate') != 'DOWN' or row.get('address') != zero
                or not isinstance(linkinfo, dict) or linkinfo.get('info_kind') != kind
                or not isinstance(data, dict) or data.get('local') not in ('any', zero)
                or data.get('remote') not in ('any', zero)
                or by_name[row['ifname']].get('addr_info') != []):
            raise ValueError('Only inactive unconfigured kernel default tunnels are accepted')


def parse_process_metrics(pid, proc_root=Path('/proc')):
    directory = Path(proc_root) / str(pid)
    threads = None
    for line in (directory / 'status').read_text().splitlines():
        if line.startswith('Threads:'):
            value = line.split(':', 1)[1].strip()
            if not value.isdecimal() or int(value) < 1:
                raise ValueError('Invalid observed Threads value')
            threads = int(value)
    if threads is None:
        raise ValueError('Threads observation missing')
    return {'threads': threads, 'fd_count': len(list((directory / 'fd').iterdir()))}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.parse_args(argv)
    # Reject ordinary hosts before even reading network state or opening sockets.
    if sys.platform != 'linux' or os.getenv('IPV6_INTEGRATION_ISOLATED') != '1':
        raise ValueError('Isolated Linux container opt-in required')
    links = json.loads(subprocess.check_output(['ip', '-j', '-d', 'link', 'show']))
    addresses = json.loads(subprocess.check_output(['ip', '-j', 'addr', 'show']))
    require_isolated_namespace(sys.platform, os.getenv('IPV6_INTEGRATION_ISOLATED'), links, addresses)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
    binary = os.environ.get('PROXY_BINARY', '/usr/local/bin/3proxy')
    process = None
    clients = []
    checks = []
    measurements = []
    resolver_stop = threading.Event()
    resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    resolver.bind(('127.0.0.1', 0))
    resolver.settimeout(0.1)
    queries = []

    def silent_resolver():
        while not resolver_stop.is_set():
            try:
                packet, _ = resolver.recvfrom(4096)
                queries.append(packet)
                # Consume the query without replying: no ICMP or outside traffic.
            except socket.timeout:
                continue
            except OSError:
                break

    resolver_thread = threading.Thread(target=silent_resolver, daemon=True)
    resolver_thread.start()

    class Server(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'loopback-proxy-ready'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = Server(('::1', 0), Handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    def check(name, condition, details=None):
        if not condition:
            raise AssertionError(name + (': ' + json.dumps(details, sort_keys=True) if details else ''))
        checks.append(name)

    def wait_until(predicate, timeout, label):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process is not None and process.poll() is not None:
                raise AssertionError('Tracked engine exited during ' + label)
            if predicate():
                return
            time.sleep(0.05)
        raise AssertionError('Deadline exceeded: ' + label)

    def request_headers(request, timeout=7):
        started = time.monotonic()
        with socket.create_connection(('127.0.0.1', 19095), timeout=2) as client:
            client.settimeout(timeout)
            client.sendall(request)
            response = b''
            while b'\r\n\r\n' not in response and len(response) < 65536:
                data = client.recv(4096)
                if not data:
                    break
                response += data
        return response, time.monotonic() - started

    def metrics_settled(baseline):
        observed = parse_process_metrics(process.pid)
        return all(observed[key] <= baseline[key] for key in baseline)

    try:
        with tempfile.TemporaryDirectory(prefix='dns-timeout-regression-') as temporary:
            path = Path(temporary) / 'engine.cfg'
            # One resolver and one-second DNS timeout: each failure is bounded.
            # Private destinations are deliberately allowed in this isolated fixture.
            path.write_text('\n'.join([
                f'nserver 127.0.0.1:{resolver.getsockname()[1]}',
                'nscache 65536', 'nscache6 65536',
                'timeouts 1 1 1 1 10 10 1 1 2 1',
                'log /dev/null', 'maxconn 64', 'auth iponly', 'allow *',
                'external ::1', 'internal 127.0.0.1', 'proxy -6 -p19095', '',
            ]), encoding='utf-8')
            process = subprocess.Popen([binary, str(path)], stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)

            def ready():
                try:
                    with socket.create_connection(('127.0.0.1', 19095), timeout=0.2):
                        return True
                except OSError:
                    return False

            wait_until(ready, 20, 'listener readiness')
            response, elapsed = request_headers(
                f'GET http://[::1]:{server.server_port}/ HTTP/1.0\r\nHost: [::1]\r\n\r\n'.encode())
            check('real_loopback_http_success', b' 200 ' in response.split(b'\r\n', 1)[0])
            time.sleep(0.25)
            baseline = parse_process_metrics(process.pid)
            # Confirm stable idle counters before the failure/cleanup experiment.
            wait_until(lambda: metrics_settled(baseline), 3, 'idle baseline')
            baseline = parse_process_metrics(process.pid)
            for index in range(2):
                response, elapsed = request_headers(
                    f'CONNECT silent-{index}.example:443 HTTP/1.0\r\nHost: silent-{index}.example\r\n\r\n'.encode())
                measurements.append({'case': 'dns_timeout', 'elapsed_seconds': round(elapsed, 3),
                                     'response': response.split(b'\r\n', 1)[0].decode('ascii', 'replace')})
                check('dns_failure_bounded_' + str(index), elapsed < 10 and
                      b' 502 ' in response.split(b'\r\n', 1)[0], measurements[-1])
                wait_until(lambda: metrics_settled(baseline), 5, 'DNS timeout thread/FD cleanup')
            check('silent_resolver_received_queries', len(queries) >= 2)

            before_queries = len(queries)
            for index in range(6):
                client = socket.create_connection(('127.0.0.1', 19095), timeout=2)
                clients.append(client)
                client.sendall(
                    f'CONNECT abandoned-{index}.example:443 HTTP/1.0\r\nHost: abandoned-{index}.example\r\n\r\n'.encode())
            # Close only after observing all six requests entered resolver waits.
            wait_until(lambda: len(queries) >= before_queries + 6, 5, 'abandoned clients enter DNS')
            started = time.monotonic()
            for client in clients:
                client.shutdown(socket.SHUT_RDWR)
                client.close()
            clients.clear()
            wait_until(lambda: metrics_settled(baseline), 8, 'closed-client threads/FD return to baseline')
            observed = parse_process_metrics(process.pid)
            measurements.append({'case': 'six_closed_clients', 'baseline': baseline, 'observed': observed,
                                 'elapsed_seconds': round(time.monotonic() - started, 3)})
            check('closed_clients_release_threads_and_fds', all(observed[key] <= baseline[key] for key in baseline),
                  measurements[-1])
            check('tracked_engine_survives_errors', process.poll() is None)
    finally:
        for client in clients:
            client.close()
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        resolver_stop.set()
        resolver.close()
        resolver_thread.join(timeout=2)
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)
    print('DNS_TIMEOUT_MEASUREMENTS=' + json.dumps(measurements, sort_keys=True))
    print(f'DNS_TIMEOUT_ENGINE_CHECKS={len(checks)} PASS={len(checks)} FAIL=0 '
          'DNS_SECONDS=1 ABORTED_CLIENTS=6 INTERNET_CALLS=0 HOST_NIC_CHANGES=0')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
