"""Worker-owned, read-only dashboard liveness probe; never mutates network state."""
import ipaddress
import json
import os
import time

import requests


INTERVAL_SECONDS = 30
REQUEST_TIMEOUT = (2, 3)
MAX_RESPONSE_BYTES = 4096
INCIDENT_KEY = 'runtime.dashboard'


class RuntimeMonitor:
    """Probe /livez only, independently of network reconciliation.

    Initial healthy=True allows the normal dashboard startup grace. A successful
    probe proves only that the dashboard answered alive=True, not that a website
    or IPv6 proxy works. The service independently owns those health checks.
    """
    def __init__(self, service, environ=None, session=None):
        env = os.environ if environ is None else environ
        self.service = service
        self.session = None
        self.enabled = True
        self.healthy = True
        self.config_error = ''
        self._url = ''
        self.last_result = 'startup_grace'
        self.last_probe_monotonic = None
        self.interval = INTERVAL_SECONDS
        try:
            flag = str(env.get('DASHBOARD_MONITOR_ENABLED', '1')).lower()
            if flag not in {'1', 'true', 'yes', 'on', '0', 'false', 'no', 'off'}:
                raise ValueError
            self.enabled = flag in {'1', 'true', 'yes', 'on'}
            if not self.enabled:
                self.last_result = 'disabled'
                return
            raw_bind = env.get('GUI_BIND', '127.0.0.1')
            if not isinstance(raw_bind, str) or '%' in raw_bind:
                raise ValueError
            bind = ipaddress.ip_address(raw_bind)
            if bind.is_multicast:
                raise ValueError
            if bind.is_unspecified:
                bind = ipaddress.ip_address('127.0.0.1' if bind.version == 4 else '::1')
            raw_port = str(env.get('GUI_PORT', '7070'))
            if not raw_port.isascii() or not raw_port.isdigit():
                raise ValueError
            port = int(raw_port)
            if not 1 <= port <= 65535:
                raise ValueError
            host = f'[{bind}]' if bind.version == 6 else str(bind)
            self._url = f'http://{host}:{port}/livez'
        except (TypeError, ValueError, OverflowError):
            self.config_error = 'Dashboard monitor configuration invalid'
            self.healthy = False
            self.last_result = 'config_error'
            return
        self.session = session if session is not None else requests.Session()
        self.session.trust_env = False
        # No netrc, environment proxy, caller credentials or session auth.
        self.session.auth = None

    def _failure(self, detail):
        self.healthy = False
        try:
            self.service._report_failure(INCIDENT_KEY, 'Dashboard không đáp ứng', detail)
        except Exception:
            # Notification enqueue trouble must not kill monitoring.
            pass

    def _resolved(self):
        self.healthy = True
        try:
            self.service._report_resolved(INCIDENT_KEY, 'Dashboard đã phục hồi',
                                          'Kiểm tra /livez thành công; alive=true.')
        except Exception:
            pass

    def probe_once(self, stop_event=None):
        if self.config_error:
            self._failure(self.config_error)
            return self.last_result
        if not self.enabled:
            return 'disabled'
        if stop_event is not None and stop_event.is_set():
            return 'stopped'
        response = None
        self.last_probe_monotonic = time.monotonic()
        # An in-flight/hung HTTP response is not fresh success evidence. A slow
        # response must not keep the external heartbeat alive using old success.
        self.healthy = False
        try:
            self.session.cookies.clear()
            response = self.session.get(self._url, timeout=REQUEST_TIMEOUT,
                allow_redirects=False, stream=True,
                headers={'User-Agent': 'clbip-runtime-monitor/1.0'})
            if response.status_code != 200:
                self.last_result = 'http_error'
                self._failure(f'Dashboard HTTP status {int(response.status_code)}')
                return self.last_result
            body = bytearray()
            for chunk in response.iter_content(chunk_size=512):
                if stop_event is not None and stop_event.is_set():
                    return 'stopped'
                if time.monotonic() - self.last_probe_monotonic > 8:
                    self.last_result = 'timeout'
                    self._failure('Dashboard probe exceeded response deadline')
                    return self.last_result
                if chunk:
                    if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                        self.last_result = 'invalid_response'
                        self._failure('Dashboard health response exceeds limit')
                        return self.last_result
                    body.extend(chunk)
            try:
                state = json.loads(body.decode('utf-8'))
            except (UnicodeError, ValueError):
                self.last_result = 'invalid_response'
                self._failure('Dashboard health response invalid')
                return self.last_result
            if not isinstance(state, dict) or state.get('alive') is not True:
                self.last_result = 'not_alive'
                self._failure('Dashboard did not confirm alive=true')
                return self.last_result
            self.last_result = 'alive'
            self._resolved()
            return self.last_result
        except requests.Timeout:
            self.last_result = 'timeout'
            self._failure('Dashboard probe timeout')
        except requests.ConnectionError:
            self.last_result = 'connection_error'
            self._failure('Dashboard probe connection failed')
        except Exception:
            self.last_result = 'probe_error'
            self._failure('Dashboard probe failed')
        finally:
            if response is not None:
                try:
                    response.close()
                except Exception:
                    pass
            try:
                self.session.cookies.clear()
            except Exception:
                pass
        return self.last_result

    def status(self):
        return {'enabled': self.enabled, 'healthy': self.healthy,
                'last_result': self.last_result, 'config_error': self.config_error,
                'interval_seconds': self.interval,
                'last_probe_monotonic': self.last_probe_monotonic}

    def run(self, stop_event):
        try:
            if self.config_error:
                self.probe_once(stop_event)
            if not self.enabled or self.config_error:
                stop_event.wait()
                return
            # Dashboard depends only on worker startup; let it bind before the
            # first probe so healthy normal startup does not create an incident.
            if stop_event.wait(self.interval):
                return
            while not stop_event.is_set():
                self.probe_once(stop_event)
                if stop_event.wait(self.interval):
                    break
        finally:
            if self.session is not None:
                try:
                    self.session.close()
                except Exception:
                    pass
