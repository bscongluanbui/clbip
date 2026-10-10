#!/usr/bin/env python3
"""Read-only host heartbeat for an existing dashboard/worker installation.

This agent does not touch Docker, network addresses, or the proxy pool. A fresh
positive /heartbeatz response is required for each beat. A live worker with fresh
progress may have an unready pool during a rebuild without losing its heartbeat.
An explicitly configured /readyz target retains strict legacy readiness checks.
Neither observation proves every destination or proxy port is working.

Run with a systemd EnvironmentFile; Python never parses or sources that file.
--check validates configuration without making any HTTP request.
"""
import argparse
import ipaddress
import json
import logging
import os
from pathlib import Path
import signal
import sys
import threading
import time
from urllib.parse import urlsplit

import requests

_here = Path(__file__).resolve().parent
_root = _here if (_here / 'heartbeat.py').is_file() else _here.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))
from heartbeat import HeartbeatMonitor


DEFAULT_DASHBOARD_URL = 'http://127.0.0.1:7070/heartbeatz'
MAX_BODY = 4096
PROBE_DEADLINE = 8.0
logger = logging.getLogger('host_heartbeat')
_LOCAL_NETWORKS = tuple(ipaddress.ip_network(value) for value in (
    '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
    '::1/128', 'fc00::/7'))


def validate_dashboard_url(value):
    """Permit only a local literal IP and /heartbeatz or legacy /readyz.

    No name resolution, redirects, credentials, or arbitrary HTTP paths are
    accepted. LAN/ULA addresses accommodate dashboards bound away from loopback.
    """
    error = 'LOCAL_DASHBOARD_URL invalid'
    try:
        if (not isinstance(value, str) or not value or len(value) > 256
                or not value.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in value)
                or any(c in value for c in ('\\', '?', '#', '%'))):
            raise ValueError
        parts = urlsplit(value)
        if (parts.scheme != 'http' or not parts.hostname
                or parts.username is not None or parts.password is not None
                or parts.path not in ('/heartbeatz', '/readyz') or parts.query or parts.fragment
                or parts.netloc.endswith(':')):
            raise ValueError
        if parts.port is not None and not 1 <= parts.port <= 65535:
            raise ValueError
        address = ipaddress.ip_address(parts.hostname)
        if not any(address.version == network.version and address in network
                   for network in _LOCAL_NETWORKS):
            raise ValueError
        return value
    except (ValueError, TypeError):
        raise ValueError(error) from None


class DashboardProbe:
    """Bounded read-only observation; a failed/late probe never reuses success.

    requests' read timeout is not a total deadline (a slow trickle can extend a
    streaming read). The caller consequently waits at most eight seconds for one
    daemon request. At most one request is in flight, and its late result is
    discarded rather than accepted by a later observation. A stuck request
    suppresses beats instead of creating more request threads.
    """
    def __init__(self, environ=None, *, session=None, monotonic=None,
                 logger=None, deadline=PROBE_DEADLINE):
        env = os.environ if environ is None else environ
        self._url = validate_dashboard_url(env.get('LOCAL_DASHBOARD_URL', DEFAULT_DASHBOARD_URL))
        self.mode = 'liveness' if urlsplit(self._url).path == '/heartbeatz' else 'readiness'
        self.session = session
        if session is not None:
            session.trust_env = False
        self.monotonic = monotonic or time.monotonic
        self.logger = logger or logging.getLogger('host_heartbeat')
        self.deadline = float(deadline)
        if not 0 < self.deadline <= PROBE_DEADLINE:
            raise ValueError('Dashboard probe deadline invalid')
        self.last_result = 'not_checked'
        self._lock = threading.Lock()
        self._thread = None
        self._closed = False
        self._cancel = threading.Event()

    def _record(self, result):
        previous = self.last_result
        self.last_result = result
        if previous != result:
            if result in ('ready', 'alive'):
                if previous != 'not_checked':
                    self.logger.info('Dashboard %s recovered', self.mode)
            elif result != 'stopped':
                self.logger.warning('Dashboard %s probe failed: %s', self.mode, result)

    def _request(self, done, result):
        response = None
        started = self.monotonic()
        try:
            if self._cancel.is_set():
                result['status'] = 'stopped'
                return
            response = self.session.get(self._url, timeout=(2, 5),
                allow_redirects=False, stream=True,
                headers={'Accept': 'application/json', 'User-Agent': 'clbip-host-heartbeat/1.0'})
            if response.status_code != 200:
                result['status'] = 'http_error'
                return
            length = response.headers.get('Content-Length')
            if length is not None:
                if not isinstance(length, str) or not length.isdigit() or int(length) > MAX_BODY:
                    result['status'] = 'invalid_body'
                    return
            body = bytearray()
            for chunk in response.iter_content(chunk_size=1024):
                if self._cancel.is_set():
                    result['status'] = 'stopped'
                    return
                if self.monotonic() - started >= self.deadline:
                    result['status'] = 'timeout'
                    return
                if not chunk:
                    continue
                if not isinstance(chunk, bytes) or len(body) + len(chunk) > MAX_BODY:
                    result['status'] = 'invalid_body'
                    return
                body.extend(chunk)
            if self._cancel.is_set():
                result['status'] = 'stopped'
                return
            if self.monotonic() - started >= self.deadline:
                result['status'] = 'timeout'
                return
            def reject_constant(_):
                raise ValueError
            payload = json.loads(body.decode('utf-8'), parse_constant=reject_constant)
            if self.mode == 'readiness':
                if not isinstance(payload, dict) or payload.get('ready') is not True:
                    result['status'] = 'not_ready'
                    return
                status = 'ready'
            else:
                flags = ('alive', 'worker_alive', 'progress_fresh')
                if (not isinstance(payload, dict)
                        or any(type(payload.get(flag)) is not bool for flag in flags)):
                    result['status'] = 'invalid_liveness'
                    return
                for flag, failure in (('alive', 'dashboard_not_alive'),
                                      ('worker_alive', 'worker_not_alive'),
                                      ('progress_fresh', 'progress_stale')):
                    if payload[flag] is not True:
                        result['status'] = failure
                        return
                status = 'alive'
            result['stamp'] = self.monotonic()
            result['status'] = status
        except Exception:
            # Exception messages can contain configured URLs. No values escape.
            result['status'] = 'probe_failed'
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
            done.set()

    def snapshot(self):
        unhealthy = {'healthy': False, 'last_reconcile_monotonic': 0.0}
        with self._lock:
            if self._closed:
                self._record('stopped')
                return unhealthy
            if self._thread is not None and self._thread.is_alive():
                self._record('probe_in_flight')
                return unhealthy
            if self.session is None:
                self.session = requests.Session()
                self.session.trust_env = False
            done, result = threading.Event(), {}
            thread = threading.Thread(target=self._request, args=(done, result),
                                      name='host-health-probe', daemon=True)
            self._thread = thread
            thread.start()
        if not done.wait(self.deadline):
            self._record('timeout')
            return unhealthy
        with self._lock:
            if self._closed:
                self._record('stopped')
                return unhealthy
            if self._thread is thread:
                self._thread = None
        status = result.get('status', 'probe_failed')
        self._record(status)
        if status in ('ready', 'alive'):
            return {'healthy': True, 'last_reconcile_monotonic': result['stamp']}
        return unhealthy

    def close(self):
        with self._lock:
            self._closed = True
            self._cancel.set()
        if self.session is not None:
            try:
                self.session.close()
            except Exception:
                pass


def main(argv=None, *, environ=None, stop_event=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true', help='Validate config; make no HTTP requests')
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    env = os.environ if environ is None else environ
    probe = None
    monitor = None
    handlers = {}
    try:
        probe = DashboardProbe(env)
        monitor = HeartbeatMonitor(env)
        if not monitor.enabled or monitor.config_error:
            raise ValueError('Heartbeat configuration invalid')
        if args.check:
            print('HOST_HEARTBEAT_CONFIG=OK NETWORK=NONE')
            return 0
        stop = stop_event if stop_event is not None else threading.Event()
        def shutdown(_signum, _frame):
            stop.set()
        for signum in (signal.SIGTERM, signal.SIGINT):
            handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, shutdown)
        monitor.run(stop, probe.snapshot)
        return 0
    except (ValueError, OSError):
        logger.error('Host heartbeat initialization failed; verify configuration')
        return 2
    finally:
        for signum, handler in handlers.items():
            signal.signal(signum, handler)
        if probe is not None:
            probe.close()
        if monitor is not None and monitor.session is not None:
            try:
                monitor.session.close()
            except Exception:
                pass


if __name__ == '__main__':
    raise SystemExit(main())
