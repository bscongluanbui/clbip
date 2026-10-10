#!/usr/bin/env python3
"""VPS dead-man's-switch receiver, separate from the monitored LAN/worker.

TLS must terminate at a reverse proxy, or HTTP must remain on Tailscale. No
network probing, commands, pool data, or Telegram bot updates are accepted.
--check validates configuration offline. --once evaluates the durable deadline
once without starting HTTP or delivering Telegram messages.
"""
import argparse
from contextlib import contextmanager
from dataclasses import dataclass, field
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import signal
import socket
from socketserver import TCPServer
import sqlite3
import sys
import threading
import time

# Also works when copied to /app/external_watchdog.py in the application image.
_here = Path(__file__).resolve().parent
_root = _here if (_here / 'alerts.py').is_file() else _here.parent
if str(_root) not in sys.path:
    sys.path.insert(0, str(_root))
from alerts import AlertOutbox
from heartbeat import read_optional_secret


MAX_CLIENTS = 16
SOCKET_TIMEOUT = 5
INCIDENT_KEY = 'watchdog.missing_heartbeat'
logger = logging.getLogger('external_watchdog')


def bounded_number(value, default, low, high, name):
    try:
        value = float(default if value in (None, '') else value)
        if not math.isfinite(value) or not low <= value <= high:
            raise ValueError
        return value
    except (ValueError, TypeError, OverflowError):
        raise ValueError(f'{name} invalid') from None


def bind_address(value):
    """Require a literal address; scoped IPv6/hostnames never trigger DNS."""
    try:
        if not isinstance(value, str) or '%' in value:
            raise ValueError
        return ipaddress.ip_address(value)
    except (ValueError, TypeError):
        raise ValueError('WATCHDOG_BIND invalid; use a literal IP address') from None


@dataclass
class WatchdogConfig:
    token: str = field(repr=False)
    telegram_token: str = field(repr=False)
    telegram_chat_id: str = field(repr=False)
    data_dir: str
    bind: str = '127.0.0.1'
    port: int = 8088
    timeout: float = 180
    check_interval: float = 5
    node_name: str = 'home-server'

    @classmethod
    def from_env(cls, environ=None):
        env = os.environ if environ is None else environ
        token = read_optional_secret(env, 'WATCHDOG_SHARED_TOKEN')
        if (not 32 <= len(token) <= 512 or not token.isascii()
                or any(ord(c) <= 32 or ord(c) == 127 for c in token)):
            raise ValueError('WATCHDOG_SHARED_TOKEN invalid')
        telegram_token = read_optional_secret(env, 'TELEGRAM_BOT_TOKEN')
        chat_id = read_optional_secret(env, 'TELEGRAM_CHAT_ID')
        if not telegram_token or not chat_id:
            raise ValueError('Telegram notification settings missing')
        port = bounded_number(env.get('WATCHDOG_PORT'), 8088, 1024, 65535, 'WATCHDOG_PORT')
        if not port.is_integer():
            raise ValueError('WATCHDOG_PORT invalid')
        node_name = env.get('WATCHDOG_NODE_NAME', 'home-server')
        if (not isinstance(node_name, str) or not 1 <= len(node_name) <= 80
                or any(ord(c) < 32 or ord(c) == 127 for c in node_name)):
            raise ValueError('WATCHDOG_NODE_NAME invalid')
        return cls(token, telegram_token, chat_id,
                   env.get('DATA_DIR', '/app/watchdog-data'),
                   str(bind_address(env.get('WATCHDOG_BIND', '127.0.0.1'))), int(port),
                   bounded_number(env.get('WATCHDOG_TIMEOUT'), 180, 30, 86400, 'WATCHDOG_TIMEOUT'),
                   bounded_number(env.get('WATCHDOG_CHECK_INTERVAL'), 5, 1, 60, 'WATCHDOG_CHECK_INTERVAL'),
                   node_name)

    def settings(self):
        return {'telegram_bot_token': self.telegram_token,
                'telegram_chat_id': self.telegram_chat_id,
                'telegram_notify': True, 'telegram_enabled': True}


class WatchdogStore:
    """One configured node, persistent last beat, independent alert outbox.

    Clock rollback/future persisted timestamps cannot certify health. A fresh
    authenticated heartbeat restores the observation. An uninitialized receiver
    gives one timeout period for the first heartbeat, also across restarts.
    """
    def __init__(self, data_dir, *, timeout=180, node_name='home-server',
                 clock=None, outbox=None):
        self.clock = clock or time.time
        self.timeout = bounded_number(timeout, 180, 30, 86400, 'WATCHDOG_TIMEOUT')
        self.node_name = str(node_name)[:80]
        self.path = Path(data_dir) / 'watchdog.sqlite3'
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.outbox = outbox if outbox is not None else AlertOutbox(data_dir, clock=self.clock)
        now = self._now()
        with self._connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS watchdog (
                id INTEGER PRIMARY KEY CHECK (id=1), started_at REAL NOT NULL,
                last_heartbeat REAL, last_clock REAL NOT NULL,
                clock_invalid INTEGER NOT NULL DEFAULT 0,
                missing INTEGER NOT NULL DEFAULT 0)''')
            db.execute('INSERT OR IGNORE INTO watchdog(id,started_at,last_clock) VALUES (1,?,?)',
                       (now, now))

    @contextmanager
    def _connect(self):
        db = sqlite3.connect(str(self.path), timeout=2)
        db.row_factory = sqlite3.Row
        try:
            db.execute('PRAGMA synchronous=FULL')
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _now(self):
        now = self.clock()
        if not isinstance(now, (float, int)) or isinstance(now, bool) or not math.isfinite(now) or now < 0:
            raise ValueError('Watchdog clock invalid')
        return float(now)

    def heartbeat(self):
        with self.lock:
            now = self._now()
            with self._connect() as db:
                db.execute('''UPDATE watchdog SET last_heartbeat=?,last_clock=?,
                    clock_invalid=0,missing=0 WHERE id=1''', (now, now))
            self.outbox.resolve(INCIDENT_KEY, f'{self.node_name}: heartbeat đã phục hồi',
                'VPS nhận heartbeat mới. Server/worker đã liên lạc được với VPS; '
                'thông báo này không chứng minh mọi website hay mọi proxy đều hoạt động.')
            self.outbox.resolve('watchdog.storage', 'Watchdog storage đã phục hồi')
            return now

    def check(self):
        with self.lock:
            now = self._now()
            with self._connect() as db:
                row = db.execute('SELECT * FROM watchdog WHERE id=1').fetchone()
                reference = row['last_heartbeat'] if row['last_heartbeat'] is not None else row['started_at']
                clock_invalid = bool(row['clock_invalid'] or row['last_clock'] > now + 5 or reference > now + 5)
                age = max(0, now - reference)
                missing = clock_invalid or age >= self.timeout
                db.execute('UPDATE watchdog SET last_clock=?,clock_invalid=?,missing=? WHERE id=1',
                           (now, int(clock_invalid), int(missing)))
            if missing:
                detail = ('VPS mất dấu heartbeat: mạng, điện, server hoặc worker có thể bị lỗi. '
                          'Chưa xác định được nguyên nhân chỉ từ heartbeat. ')
                detail += ('Đồng hồ VPS bị lùi/thời gian lưu nằm trong tương lai; '
                           'cần heartbeat mới để xác nhận.' if clock_invalid else
                           f'Không có heartbeat trong {int(age)} giây (ngưỡng {int(self.timeout)} giây).')
                self.outbox.failure(INCIDENT_KEY, f'{self.node_name}: mất heartbeat', detail)
            else:
                # Also covers a restart after beat persistence but before outbox
                # recovery acknowledgment. Deduplication belongs to AlertOutbox.
                self.outbox.resolve(INCIDENT_KEY, f'{self.node_name}: heartbeat đã phục hồi',
                                    'VPS có heartbeat còn mới trong ngưỡng giám sát.')
            return {'missing': missing, 'clock_invalid': clock_invalid,
                    'heartbeat_received': row['last_heartbeat'] is not None,
                    'age_seconds': age, 'timeout_seconds': self.timeout}


def authorize_request(path, headers, token):
    """Authenticate before touching storage. Only an empty POST is accepted."""
    if path != '/heartbeat':
        return 404
    auth_values = headers.get_all('Authorization') if hasattr(headers, 'get_all') else [headers.get('Authorization', '')]
    if not auth_values or len(auth_values) != 1:
        return 401
    auth = auth_values[0]
    if not isinstance(auth, str) or len(auth) > 520:
        return 401
    expected = ('Bearer ' + token).encode('utf-8')
    if not hmac.compare_digest(auth.encode('utf-8'), expected):
        return 401
    if headers.get('Transfer-Encoding') is not None:
        return 400
    lengths = headers.get_all('Content-Length') if hasattr(headers, 'get_all') else [headers.get('Content-Length', '0')]
    if lengths is None:
        lengths = ['0']
    if len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
        return 400
    if lengths[0] != '0':
        return 413
    return 204


class WatchdogHandler(BaseHTTPRequestHandler):
    server_version = 'Watchdog'
    sys_version = ''
    protocol_version = 'HTTP/1.1'

    def log_message(self, format, *args):
        # Request target, headers and exception text can contain credentials.
        pass

    def respond(self, code):
        self.send_response(code)
        self.send_header('Content-Length', '0')
        self.send_header('Connection', 'close')
        self.end_headers()
        self.close_connection = True

    def do_POST(self):
        code = authorize_request(self.path, self.headers, self.server.shared_token)
        if code == 204:
            try:
                self.server.store.heartbeat()
            except Exception:
                logger.error('Watchdog heartbeat storage failed')
                code = 503
        self.respond(code)

    def do_GET(self):
        self.respond(405)

    def do_PUT(self):
        self.respond(405)

    def do_DELETE(self):
        self.respond(405)


class WatchdogServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, store, token):
        self.store, self.shared_token = store, token
        self.slots = threading.BoundedSemaphore(MAX_CLIENTS)
        bind = bind_address(address[0])
        self.address_family = socket.AF_INET6 if bind.version == 6 else socket.AF_INET
        super().__init__((str(bind), address[1]), WatchdogHandler)

    def server_bind(self):
        # A specific IPv6 listener must not silently become dual-stack when
        # binding ::. Keep IPv4 reachability an explicit separate deployment.
        if self.address_family == socket.AF_INET6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        # HTTPServer.server_bind performs getfqdn(). Numeric metadata is enough
        # for this receiver, so startup never depends on reverse DNS either.
        TCPServer.server_bind(self)
        self.server_name, self.server_port = self.socket.getsockname()[:2]

    def get_request(self):
        request, address = super().get_request()
        request.settimeout(SOCKET_TIMEOUT)
        return request, address

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


def detector_loop(store, stop_event, interval=5):
    while not stop_event.is_set():
        try:
            store.check()
        except Exception:
            logger.error('Watchdog detector storage/clock failure')
            try:
                store.outbox.failure('watchdog.storage', 'Watchdog không xác nhận được trạng thái',
                                     'VPS gặp lỗi lưu trạng thái hoặc đồng hồ. Kiểm tra log VPS.')
            except Exception:
                logger.error('Watchdog could not persist storage/clock alert')
        if stop_event.wait(interval):
            break


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true', help='Validate configuration only; no HTTP/Telegram/network')
    mode.add_argument('--once', action='store_true', help='Evaluate deadline once; queue only, no HTTP/Telegram/network')
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
    try:
        config = WatchdogConfig.from_env()
        if args.check:
            print('WATCHDOG_CONFIG=OK NETWORK=NONE')
            return 0
        os.umask(0o077)
        store = WatchdogStore(config.data_dir, timeout=config.timeout, node_name=config.node_name)
        if args.once:
            print(json.dumps(store.check(), sort_keys=True))
            return 0
        server = WatchdogServer((config.bind, config.port), store, config.token)
    except Exception:
        logger.error('Watchdog initialization failed; verify configuration/storage')
        return 1
    stop_event = threading.Event()
    threads = [threading.Thread(target=detector_loop, args=(store, stop_event, config.check_interval),
                                name='watchdog-detector', daemon=True),
               threading.Thread(target=store.outbox.run, args=(config.settings, stop_event),
                                name='watchdog-telegram', daemon=True)]
    def shutdown(signum, frame):
        stop_event.set()
        threading.Thread(target=server.shutdown, daemon=True).start()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, shutdown)
    for thread in threads:
        thread.start()
    logger.info('Watchdog receiver started')
    try:
        server.serve_forever(poll_interval=.5)
    finally:
        stop_event.set()
        server.server_close()
        for thread in threads:
            thread.join(timeout=1)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
