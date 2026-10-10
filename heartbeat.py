"""Optional outward dead-man's-switch heartbeat; never a network reconciler.

The URL is a secret. Only freshly healthy service observations are sent, and no
service data is included. A monitor outside the server's network detects missing
beats, including power loss and a total loss of Internet connectivity.
"""
import ipaddress
import logging
import math
import os
from pathlib import Path
import re
import stat
import threading
import time
from urllib.parse import urlsplit, urlunsplit

import requests


DEFAULT_INTERVAL = 60
DEFAULT_TIMEOUT = 5
DEFAULT_STALE_AFTER = 330
MAX_URL_LENGTH = 2048
MAX_ATTEMPTS = 3
MAX_CYCLE_SECONDS = 25.0
RETRY_BACKOFF_SECONDS = (1.0, 2.0)


def _number(value, default, minimum, maximum, name):
    if value in (None, ''):
        return float(default)
    try:
        result = float(value)
        if not math.isfinite(result) or not minimum <= result <= maximum:
            raise ValueError
    except (ValueError, TypeError, OverflowError):
        raise ValueError(f'{name} invalid') from None
    return result


def validate_heartbeat_url(value, *, allow_http=False):
    """Accept an explicitly configured HTTPS base ping URL, never log its value.

    Private/self-hosted HTTPS endpoints are allowed: the operator owns this
    environment configuration. Monitoring full LAN outages requires a monitor
    outside that LAN. Query strings and ambiguous escaped paths are rejected;
    this implementation does not synthesize /start, /fail or exit-code URLs.
    """
    error = 'HEARTBEAT_URL invalid'
    if not isinstance(value, str) or not value or len(value) > MAX_URL_LENGTH:
        raise ValueError(error)
    if (not value.isascii() or any(ord(c) <= 32 or ord(c) == 127 for c in value)
            or '\\' in value):
        raise ValueError(error)
    try:
        parts = urlsplit(value)
        if (parts.scheme not in ({'https', 'http'} if allow_http else {'https'})
                or not parts.hostname or parts.username is not None
                or parts.password is not None or parts.query or parts.fragment):
            raise ValueError
        if parts.port is not None and not 1 <= parts.port <= 65535:
            raise ValueError
        host = parts.hostname
        if '%' in host or parts.netloc.endswith(':'):
            raise ValueError
        try:
            ipaddress.ip_address(host)
        except ValueError:
            if len(host) > 253 or not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?',
                                                      label) for label in host.split('.')):
                raise ValueError
        if parts.scheme == 'http':
            try:
                address = ipaddress.ip_address(host)
                overlay = any(address in net for net in (ipaddress.ip_network('100.64.0.0/10'),
                                                       ipaddress.ip_network('fd7a:115c:a1e0::/48')))
            except ValueError:
                overlay = host.lower().endswith('.ts.net')
            if not overlay:
                raise ValueError
        path = parts.path.rstrip('/')
        if (not path or not re.fullmatch(r'/[A-Za-z0-9._~/-]+', path)
                or any(segment in ('', '.', '..') for segment in path[1:].split('/'))
                or path.split('/')[-1].lower() in {'start', 'fail'}):
            raise ValueError
        return urlunsplit((parts.scheme, parts.netloc, path, '', ''))
    except (ValueError, TypeError):
        raise ValueError(error) from None


class HeartbeatMonitor:
    """One daemon thread owned by the worker, disabled unless configured.

    health_provider must be a cheap, non-mutating snapshot callable returning
    {'healthy': bool, 'last_reconcile_monotonic': float}. It must not advance the
    timestamp merely because this monitor asks for it. Fresh reconcile progress
    can advance it during an intentionally long pool build.
    """
    def __init__(self, environ=None, *, session=None, monotonic=None, logger=None):
        environ = os.environ if environ is None else environ
        self.monotonic = monotonic or time.monotonic
        self.logger = logger or logging.getLogger(__name__)
        self._url = ''
        self._token = ''
        self.session = None
        self.config_error = ''
        self.interval = float(DEFAULT_INTERVAL)
        self.timeout = float(DEFAULT_TIMEOUT)
        self.stale_after = float(DEFAULT_STALE_AFTER)
        self.last_result = 'disabled'
        self.last_success_monotonic = None
        self.attempts = 0
        self.successes = 0
        self.retries = 0
        self.cycles = 0
        self.last_http_status = None
        self._logged_state = None
        try:
            value = environ.get('HEARTBEAT_URL', '')
            filename = environ.get('HEARTBEAT_URL_FILE', '')
            if filename:
                try:
                    path = Path(filename)
                    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
                        raise ValueError
                    with path.open(encoding='utf-8') as handle:
                        value = handle.read(MAX_URL_LENGTH + 1).strip()
                except (OSError, ValueError, UnicodeError):
                    raise ValueError('HEARTBEAT_URL_FILE unreadable') from None
            # An unset URL causes no network/session construction, even if
            # unused optional numeric settings contain invalid values.
            if not value:
                return
            allow_http = environ.get('HEARTBEAT_ALLOW_HTTP', '') == '1'
            self._url = validate_heartbeat_url(value, allow_http=allow_http)
            self._token = read_optional_secret(environ, 'HEARTBEAT_TOKEN')
            if self._token and (not 32 <= len(self._token) <= 512
                                or not self._token.isascii()
                                or any(ord(c) <= 32 or ord(c) == 127 for c in self._token)):
                raise ValueError('HEARTBEAT_TOKEN invalid')
            self.interval = _number(environ.get('HEARTBEAT_INTERVAL'), DEFAULT_INTERVAL,
                                    10, 3600, 'HEARTBEAT_INTERVAL')
            self.timeout = _number(environ.get('HEARTBEAT_TIMEOUT'), DEFAULT_TIMEOUT,
                                   1, 30, 'HEARTBEAT_TIMEOUT')
            self.stale_after = _number(environ.get('HEARTBEAT_STALE_AFTER'),
                                      max(self.interval * 2, DEFAULT_STALE_AFTER),
                                      self.interval, 7200, 'HEARTBEAT_STALE_AFTER')
        except ValueError as exc:
            self._url = ''
            self._token = ''
            self.config_error = str(exc)
            self.last_result = 'config_error'
            self.logger.error('Heartbeat disabled: %s', self.config_error)
            return
        self.session = session if session is not None else requests.Session()
        self.session.trust_env = False
        self.last_result = 'not_sent'

    @property
    def enabled(self):
        return bool(self._url)

    def status(self):
        """Return operational evidence without URLs, file names, or service data."""
        return {'enabled': self.enabled, 'config_error': self.config_error,
                'interval_seconds': self.interval, 'timeout_seconds': self.timeout,
                'stale_after_seconds': self.stale_after, 'last_result': self.last_result,
                'attempts': self.attempts, 'successes': self.successes,
                'retries': self.retries, 'cycles': self.cycles,
                'max_attempts_per_cycle': MAX_ATTEMPTS,
                'cycle_budget_seconds': MAX_CYCLE_SECONDS,
                'last_http_status': self.last_http_status,
                'last_success_monotonic': self.last_success_monotonic}

    def _result(self, value):
        """Log state transitions only; never include endpoint/provider exceptions."""
        self.last_result = value
        state = (value, self.last_http_status)
        if state != self._logged_state:
            self.logger.info('Heartbeat state=%s http_status=%s',
                             value, self.last_http_status)
            self._logged_state = state
        return value

    def _health_result(self, health_provider):
        try:
            observation = health_provider()
            if not isinstance(observation, dict) or observation.get('healthy') is not True:
                return 'unhealthy'
            stamp = observation.get('last_reconcile_monotonic')
            now = self.monotonic()
            if (isinstance(stamp, bool) or not isinstance(stamp, (float, int))
                    or not math.isfinite(stamp) or stamp < 0 or stamp > now):
                return 'health_unavailable'
            if now - stamp > self.stale_after:
                return 'stale'
        except Exception:
            # A failed snapshot never reuses an earlier healthy observation.
            return 'health_unavailable'
        return None

    def emit_once(self, health_provider, stop_event=None):
        if not self.enabled:
            return self.last_result
        self.cycles += 1
        self.last_http_status = None
        stopper = stop_event if stop_event is not None else threading.Event()
        deadline = self.monotonic() + MAX_CYCLE_SECONDS
        for attempt in range(MAX_ATTEMPTS):
            if stopper.is_set():
                return self._result('stopped')
            reason = self._health_result(health_provider)
            if reason is not None:
                return self._result(reason)
            # A provider can trigger shutdown while taking its snapshot.
            if stopper.is_set():
                return self._result('stopped')
            remaining = deadline - self.monotonic()
            if remaining <= 0:
                return self._result('cycle_budget_exhausted')
            self.attempts += 1
            if attempt:
                self.retries += 1
            response = None
            retryable = False
            self.last_http_status = None
            try:
                headers = {'User-Agent': 'clbip-heartbeat/1.0'}
                if self._token:
                    headers['Authorization'] = 'Bearer ' + self._token
                # Requests scalar timeouts bound connect and read independently.
                # Leave half the remaining retry-cycle allowance for each phase.
                # DNS resolution and trickle headers are not a total deadline;
                # prefer a literal Tailscale IP for the watchdog endpoint.
                timeout = min(self.timeout, remaining / 2.0)
                response = self.session.post(self._url, data=b'', timeout=timeout,
                                             allow_redirects=False, stream=True,
                                             headers=headers)
                code = response.status_code
                if isinstance(code, bool) or not isinstance(code, int):
                    self._result('transport_error')
                else:
                    self.last_http_status = code
                    if 200 <= code < 300:
                        self.successes += 1
                        self.last_success_monotonic = self.monotonic()
                        return self._result('sent')
                    retryable = code in (408, 429) or 500 <= code < 600
                    self._result('http_error')
            except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
                # Exception strings commonly contain the endpoint and token.
                retryable = True
                self._result('transport_error')
            except Exception:
                # Invalid requests/programming errors are not transient transport
                # failures. Preserve a sanitized failure but do not repeat them.
                self._result('transport_error')
            finally:
                if response is not None:
                    try:
                        response.close()
                    except Exception:
                        pass
            if not retryable or attempt == MAX_ATTEMPTS - 1:
                break
            remaining = deadline - self.monotonic()
            delay = RETRY_BACKOFF_SECONDS[attempt]
            if remaining <= delay:
                break
            if stopper.wait(delay):
                return self._result('stopped')
        return self.last_result

    def run(self, stop_event, health_provider):
        if not self.enabled:
            return
        # Fixed monotonic tick deadlines prevent slow network requests from
        # adding a complete interval to every beat and drifting toward alarm.
        next_tick = self.monotonic()
        try:
            while not stop_event.is_set():
                self.emit_once(health_provider, stop_event=stop_event)
                if stop_event.is_set():
                    break
                next_tick += self.interval
                now = self.monotonic()
                if next_tick <= now:
                    # Never replay missed ticks or busy-loop after an overrun.
                    missed = math.floor((now - next_tick) / self.interval) + 1
                    next_tick += missed * self.interval
                if stop_event.wait(max(0.0, next_tick - now)):
                    break
        finally:
            try:
                self.session.close()
            except Exception:
                pass


def read_optional_secret(environ, name):
    """Bounded file-over-env secret loading; messages contain names, not paths."""
    filename = environ.get(name + '_FILE', '')
    if not filename:
        return str(environ.get(name, '')).strip()
    try:
        path = Path(filename)
        if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode):
            raise ValueError
        with path.open(encoding='utf-8') as stream:
            result = stream.read(4097).strip()
        if len(result) > 4096:
            raise ValueError
        return result
    except (OSError, ValueError, UnicodeError):
        raise ValueError(f'{name}_FILE unreadable') from None
