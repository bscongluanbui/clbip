"""Private SQLite snapshots: one atomic state transaction, plus an ownership ledger."""
import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import sqlite3
import threading
import time

from validation import DEFAULT_SETTINGS


class StateStore:
    def __init__(self, data_dir):
        self.path = Path(data_dir).resolve()
        self.path.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == 'posix':
            self.path.chmod(0o700)
        self.db_path = self.path / 'state.sqlite3'
        self.lock = threading.RLock()
        with self.connection() as conn:
            conn.execute('CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)')
            if conn.execute('SELECT body FROM state WHERE id=1').fetchone() is None:
                conn.execute('INSERT INTO state VALUES (1,?)', (json.dumps(self._initial_state()),))
        if os.name == 'posix':
            self.db_path.chmod(0o600)

    @contextmanager
    def connection(self):
        conn = sqlite3.connect(str(self.db_path), timeout=30)
        try:
            conn.execute('PRAGMA journal_mode=DELETE')
            conn.execute('PRAGMA synchronous=FULL')
            with conn:
                yield conn
        finally:
            conn.close()

    def _legacy(self, name, default):
        path = self.path / name
        if not path.exists():
            return default
        try:
            value = json.loads(path.read_text(encoding='utf-8'))
        except (ValueError, OSError) as exc:
            raise ValueError(f'Legacy state {name} bị lỗi; giữ nguyên file để phục hồi') from exc
        if not isinstance(value, type(default)):
            raise ValueError(f'Legacy state {name} sai kiểu')
        if os.name == 'posix':
            path.chmod(0o600)
        return value

    def _initial_state(self):
        legacy = self._legacy('settings.json', {})
        if 'telegram_token' in legacy and 'telegram_bot_token' not in legacy:
            legacy['telegram_bot_token'] = legacy['telegram_token']
        settings = {**DEFAULT_SETTINGS, **{k: v for k, v in legacy.items() if k in DEFAULT_SETTINGS}}
        if settings.get('dns1') == '127.0.0.1':
            settings['dns1'] = DEFAULT_SETTINGS['dns1']
        # Legacy maximum was not enforced; use the documented new resource budget.
        if settings.get('max_connections', 0) > 1000:
            settings['max_connections'] = DEFAULT_SETTINGS['max_connections']
        proxies = self._legacy('proxies.json', [])
        users = self._legacy('users.json', [])
        ledger = []
        for proxy in proxies:
            import ipaddress
            proxy['ipv6'] = str(ipaddress.IPv6Address(proxy['ipv6']))
            proxy.setdefault('interface', settings['interface'])
            proxy.setdefault('prefix_len', settings['prefix_len'])
            proxy.setdefault('address_prefix_len', proxy['prefix_len'])
            proxy.setdefault('subnet', settings['subnet'])
            proxy.setdefault('topology_mode', settings['topology_mode'])
            proxy.setdefault('routed_prefix', settings['routed_prefix'])
            proxy.setdefault('status', 'stopped')
            if proxy.get('ipv6'):
                ledger.append({'address': proxy['ipv6'], 'interface': proxy['interface'],
                               'prefix_len': proxy['address_prefix_len'], 'owner': 'ipv6-manager', 'active': True})
        return {'schema': 2, 'revision': 0, 'settings': settings, 'users': users,
                'proxies': proxies, 'managed_addresses': ledger,
                'desired_state': 'running' if settings.get('auto_start') and proxies else 'stopped',
                'pending_operation': None, 'uncertain_addresses': [], 'stop_epoch': 0,
                'manual_stop': False, 'startup_recovery': None, 'rotation_due': 0, 'last_error': '',
                'last_reconcile': 0, 'prefix_state': {}, 'started_at': time.time(), 'events': [], 'operations': {}}

    def read(self):
        with self.lock, self.connection() as conn:
            row = conn.execute('SELECT body FROM state WHERE id=1').fetchone()
            state = json.loads(row[0])
            state.setdefault('uncertain_addresses', [])
            state.setdefault('stop_epoch', 0)
            # Existing explicit stopped deployments must not be auto-started by an upgrade.
            state.setdefault('manual_stop', state['desired_state'] == 'stopped' and
                             bool(state['proxies'] or state.get('stop_epoch')))
            state.setdefault('startup_recovery', None)
            state['settings'] = {**DEFAULT_SETTINGS, **state['settings']}
            for proxy in state['proxies']:
                proxy.setdefault('topology_mode', state['settings']['topology_mode'])
                proxy.setdefault('routed_prefix', state['settings']['routed_prefix'])
            return state

    def write(self, state):
        state = copy.deepcopy(state)
        with self.lock, self.connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            old = json.loads(conn.execute('SELECT body FROM state WHERE id=1').fetchone()[0])
            # A stale operation snapshot must never erase a newer emergency stop.
            if old.get('stop_epoch', 0) > state.get('stop_epoch', 0):
                state['stop_epoch'] = old['stop_epoch']
                state['desired_state'] = 'stopped'
                state['manual_stop'] = True
                if state.get('pending_operation'):
                    state['pending_operation']['before']['desired_state'] = 'stopped'
                    state['pending_operation']['before']['stop_epoch'] = old['stop_epoch']
                    state['pending_operation']['before']['manual_stop'] = True
            state['revision'] = old['revision'] + 1
            conn.execute('UPDATE state SET body=? WHERE id=1', (json.dumps(state, ensure_ascii=False),))
        return state

    def request_stop(self):
        """Persist priority stop intent without acquiring the service mutation lock."""
        with self.lock, self.connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            state = json.loads(conn.execute('SELECT body FROM state WHERE id=1').fetchone()[0])
            state['stop_epoch'] = state.get('stop_epoch', 0) + 1
            state['desired_state'] = 'stopped'
            state['manual_stop'] = True
            if state.get('pending_operation'):
                state['pending_operation']['before']['desired_state'] = 'stopped'
                state['pending_operation']['before']['stop_epoch'] = state['stop_epoch']
                state['pending_operation']['before']['manual_stop'] = True
            state['revision'] += 1
            self.event(state, 'proxy.stop', 'priority_requested')
            conn.execute('UPDATE state SET body=? WHERE id=1', (json.dumps(state, ensure_ascii=False),))
        return state

    def event(self, state, action, result, detail=''):
        state['events'] = (state.get('events', []) + [{'time': time.time(), 'action': action,
                                                   'result': result, 'detail': detail[:512]}])[-1000:]
        return state
