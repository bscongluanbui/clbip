"""Real DNS failover/cache regression, only in an opted-in network-none container.

The first loopback UDP resolver consumes queries without replying. The second
answers with ::1. Requests go through the real foreground engine to a loopback
HTTP server. No external DNS, Internet calls, production ledger or host NICs.
Run with the same isolation/capability flags as integration_dns_timeout.py.
"""
import argparse
import http.server
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

from integration_dns_timeout import parse_process_metrics, require_isolated_namespace


def loopback_dns_answer(packet):
    """Answer the fixture's single IN A/AAAA question; reject malformed queries."""
    if len(packet) < 17:
        return None
    _, flags, questions, answers, authorities, additional = struct.unpack('!6H', packet[:12])
    if flags & 0x8000 or questions != 1 or answers or authorities or additional:
        return None
    offset = 12
    while True:
        if offset >= len(packet):
            return None
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if length > 63 or offset + length > len(packet):
            return None
        offset += length
    if offset + 4 != len(packet):
        return None
    qtype, qclass = struct.unpack('!HH', packet[offset:offset + 4])
    if qclass != 1 or qtype not in (1, 28):
        return None
    address = socket.inet_pton(socket.AF_INET6, '::1') if qtype == 28 else socket.inet_aton('127.0.0.1')
    header = packet[:2] + struct.pack('!5H', 0x8180, 1, 1, 0, 0)
    answer = b'\xc0\x0c' + struct.pack('!HHIH', qtype, 1, 30, len(address)) + address
    return header + packet[12:] + answer


def engine_config(dns_seconds, primary_port, secondary_port, proxy_port):
    if isinstance(dns_seconds, bool) or not isinstance(dns_seconds, int) or not 1 <= dns_seconds <= 30:
        raise ValueError('DNS timeout must be an integer in 1..30')
    return '\n'.join([
        f'nserver 127.0.0.1:{primary_port}', f'nserver 127.0.0.1:{secondary_port}',
        'nscache 65536', 'nscache6 65536',
        f'timeouts 1 5 30 60 10 10 {dns_seconds} 60 2 5',
        'log /dev/null', 'maxconn 64', 'auth iponly', 'allow *',
        'external ::1', 'internal 127.0.0.1', f'proxy -6 -p{proxy_port}', '',
    ])


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.parse_args(argv)
    # Validate explicit namespace opt-in before opening sockets or starting child processes.
    if sys.platform != 'linux' or os.getenv('IPV6_INTEGRATION_ISOLATED') != '1':
        raise ValueError('Isolated Linux container opt-in required')
    links = json.loads(subprocess.check_output(['ip', '-j', '-d', 'link', 'show']))
    addresses = json.loads(subprocess.check_output(['ip', '-j', 'addr', 'show']))
    require_isolated_namespace(sys.platform, os.getenv('IPV6_INTEGRATION_ISOLATED'), links, addresses)
    subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)

    binary = os.environ.get('PROXY_BINARY', '/usr/local/bin/3proxy')
    observations = {'primary': [], 'secondary': []}
    observation_lock = threading.Lock()
    stop = threading.Event()
    sockets, resolver_threads = [], []
    checks, measurements = [], []
    process = None
    server = None
    server_thread = None

    def check(name, condition, details=None):
        if not condition:
            raise AssertionError(name + (': ' + json.dumps(details, sort_keys=True) if details else ''))
        checks.append(name)

    def counts():
        with observation_lock:
            return {name: len(rows) for name, rows in observations.items()}

    def resolver_loop(resolver, name):
        while not stop.is_set():
            try:
                packet, peer = resolver.recvfrom(4096)
                with observation_lock:
                    observations[name].append({'at': time.monotonic(), 'query': packet})
                if name == 'secondary':
                    answer = loopback_dns_answer(packet)
                    if answer is not None:
                        resolver.sendto(answer, peer)
            except socket.timeout:
                continue
            except OSError:
                break

    def wait_until(predicate, timeout, label):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process is not None and process.poll() is not None:
                raise AssertionError('Tracked engine exited during ' + label)
            if predicate():
                return
            time.sleep(0.05)
        raise AssertionError('Deadline exceeded: ' + label)

    def stop_engine():
        nonlocal process
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        process = None

    class Server(http.server.ThreadingHTTPServer):
        address_family = socket.AF_INET6
        daemon_threads = True

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'local-dns-failover-ok'
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Connection', 'close')
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    def request(hostname, proxy_port, timeout):
        started = time.monotonic()
        with socket.create_connection(('127.0.0.1', proxy_port), timeout=2) as client:
            client.settimeout(timeout)
            client.sendall(
                f'GET http://{hostname}:{server.server_port}/ HTTP/1.0\r\nHost: {hostname}\r\n\r\n'.encode('ascii'))
            response = b''
            while len(response) < 65536:
                data = client.recv(4096)
                if not data:
                    break
                response += data
        return response, time.monotonic() - started

    try:
        for name in ('primary', 'secondary'):
            resolver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sockets.append(resolver)
            resolver.bind(('127.0.0.1', 0))
            resolver.settimeout(0.1)
            thread = threading.Thread(target=resolver_loop, args=(resolver, name), daemon=True)
            resolver_threads.append(thread)
            thread.start()
        server = Server(('::1', 0), Handler)
        server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        server_thread.start()

        with tempfile.TemporaryDirectory(prefix='dns-failover-regression-') as temporary:
            for index, dns_seconds in enumerate((3, 5)):
                proxy_port = 19096 + index
                path = Path(temporary) / f'engine-{dns_seconds}.cfg'
                path.write_text(engine_config(dns_seconds, sockets[0].getsockname()[1],
                                              sockets[1].getsockname()[1], proxy_port), encoding='utf-8')
                process = subprocess.Popen([binary, str(path)], stdin=subprocess.DEVNULL,
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, close_fds=True)

                def ready():
                    try:
                        with socket.create_connection(('127.0.0.1', proxy_port), timeout=0.2):
                            return True
                    except OSError:
                        return False

                wait_until(ready, 20, 'listener readiness')
                time.sleep(0.2)
                baseline = parse_process_metrics(process.pid)
                hostname = f'failover-{dns_seconds}.example'
                before = counts()
                response, elapsed = request(hostname, proxy_port, dns_seconds + 6)
                after = counts()
                measurement = {'case': 'primary_silent_secondary_live', 'dns_seconds': dns_seconds,
                               'elapsed_seconds': round(elapsed, 3),
                               'response': response.split(b'\r\n', 1)[0].decode('ascii', 'replace'),
                               'primary_queries': after['primary'] - before['primary'],
                               'secondary_queries': after['secondary'] - before['secondary']}
                measurements.append(measurement)
                check(f'failover_http_success_{dns_seconds}', b' 200 ' in response.split(b'\r\n', 1)[0]
                      and response.endswith(b'local-dns-failover-ok'), measurement)
                check(f'failover_waits_configured_timeout_{dns_seconds}', dns_seconds * 0.8 <= elapsed < dns_seconds + 5,
                      measurement)
                check(f'both_resolvers_observed_{dns_seconds}', measurement['primary_queries'] == 1
                      and measurement['secondary_queries'] == 1, measurement)

                response, elapsed = request(hostname, proxy_port, 3)
                cached_counts = counts()
                cached = {'case': 'cached_repeat', 'dns_seconds': dns_seconds,
                          'elapsed_seconds': round(elapsed, 3), 'resolver_counts_unchanged': cached_counts == after}
                measurements.append(cached)
                check(f'cached_repeat_success_{dns_seconds}', b' 200 ' in response.split(b'\r\n', 1)[0]
                      and response.endswith(b'local-dns-failover-ok'), cached)
                check(f'cached_repeat_avoids_dns_wait_{dns_seconds}', cached_counts == after, cached)

                def settled():
                    observed = parse_process_metrics(process.pid)
                    return all(observed[key] <= baseline[key] for key in baseline)

                wait_until(settled, 5, 'failover thread/FD cleanup')
                observed = parse_process_metrics(process.pid)
                check(f'failover_releases_threads_and_fds_{dns_seconds}',
                      all(observed[key] <= baseline[key] for key in baseline),
                      {'baseline': baseline, 'observed': observed})
                measurements.append({'case': 'cleanup', 'dns_seconds': dns_seconds,
                                     'baseline': baseline, 'observed': observed})
                stop_engine()
    finally:
        stop_engine()
        stop.set()
        for resolver in sockets:
            resolver.close()
        for thread in resolver_threads:
            thread.join(timeout=2)
        if server is not None:
            server.shutdown()
            server.server_close()
        if server_thread is not None:
            server_thread.join(timeout=2)

    print('DNS_FAILOVER_MEASUREMENTS=' + json.dumps(measurements, sort_keys=True))
    print(f'DNS_FAILOVER_ENGINE_CHECKS={len(checks)} PASS={len(checks)} FAIL=0 '
          'DNS_SECONDS=3,5 PRIMARY_SILENT=1 SECONDARY_LIVE=1 INTERNET_CALLS=0 HOST_NIC_CHANGES=0')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
