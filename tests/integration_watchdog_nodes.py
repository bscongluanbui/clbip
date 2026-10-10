"""Opt-in independent-node watchdog acceptance in Docker --network none.

Real loopback HTTP receivers and SQLite stores use independent fixture clocks,
heartbeat tokens, and fake Telegram recipients. No Telegram API is contacted.
Run: python /tests/integration_watchdog_nodes.py --run
"""
import argparse
from contextlib import ExitStack
import html
import importlib.util
import io
import json
import logging
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading


def load_watchdog():
    """Support the source tree and the image's /app/external_watchdog.py."""
    root = Path(__file__).resolve().parents[1]
    candidates = (root / 'scripts' / 'external_watchdog.py',
                  root / 'external_watchdog.py', Path('/app/external_watchdog.py'))
    for path in candidates:
        if not path.is_file():
            continue
        spec = importlib.util.spec_from_file_location('acceptance_watchdog_nodes', path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    raise RuntimeError('Watchdog implementation not found')


def heartbeat_timestamp(store):
    """Read the actual stored timestamp without mutating detector state."""
    db = sqlite3.connect(str(store.path))
    try:
        return db.execute('SELECT last_heartbeat FROM watchdog WHERE id=1').fetchone()[0]
    finally:
        db.close()


def require_isolated_linux():
    if sys.platform != 'linux':
        raise RuntimeError('Linux acceptance runner required')
    interfaces = {path.name for path in Path('/sys/class/net').iterdir()}
    if interfaces != {'lo'}:
        raise RuntimeError('Loopback-only network namespace required (Docker --network none)')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.parse_args(argv)
    require_isolated_linux()

    import requests
    watchdog = load_watchdog()
    tokens = {
        'a': 'acceptance-node-a-heartbeat-secret-12345678901234567890',
        'b': 'acceptance-node-b-heartbeat-secret-12345678901234567890',
    }
    settings = {
        'a': {'telegram_bot_token': '987654:node-a-fake-bot-secret-only',
              'telegram_chat_id': '-100111222333'},
        'b': {'telegram_bot_token': '987655:node-b-fake-bot-secret-only',
              'telegram_chat_id': '-100444555666'},
    }
    clocks = {'a': [1000.0], 'b': [2000.0]}
    names = {'a': 'acceptance-node-a', 'b': 'acceptance-node-b'}
    delivered = {'a': [], 'b': []}
    attempts = {'a': [], 'b': []}
    log_buffer = io.StringIO()
    handler = logging.StreamHandler(log_buffer)
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)

    def sender_for(node, *, fail=False):
        other = 'b' if node == 'a' else 'a'

        def fake_sender(message, *, settings):
            assert settings == configured_settings[node], 'Recipient crossed node boundary'
            plain = html.unescape(message)
            assert names[node] in plain, 'Message lacks its own node marker'
            assert names[other] not in plain, 'Message crossed node boundary'
            attempts[node].append(plain)
            if fail:
                # Arbitrary sender errors may contain credentials; persistence
                # and logs must retain only the generic delivery failure.
                return False, (configured_settings[node]['telegram_bot_token']
                               + ' ' + tokens[node])
            delivered[node].append(plain)
            return True, 'Acceptance fake sender only'

        return fake_sender

    configured_settings = settings
    try:
        with ExitStack() as stack:
            data_dirs = {node: Path(stack.enter_context(tempfile.TemporaryDirectory(
                prefix='watchdog-node-' + node + '-'))) for node in ('a', 'b')}
            assert data_dirs['a'] != data_dirs['b']
            stores = {node: watchdog.WatchdogStore(
                data_dirs[node], timeout=180, node_name=names[node],
                clock=lambda node=node: clocks[node][0]) for node in ('a', 'b')}
            servers = {node: watchdog.WatchdogServer(
                ('127.0.0.1', 0), stores[node], tokens[node]) for node in ('a', 'b')}
            threads = {node: threading.Thread(target=servers[node].serve_forever,
                name='acceptance-watchdog-node-' + node, daemon=True) for node in ('a', 'b')}
            session = requests.Session()
            session.trust_env = False
            urls = {node: f'http://127.0.0.1:{servers[node].server_address[1]}/heartbeat'
                    for node in ('a', 'b')}
            assert urls['a'] != urls['b']
            for thread in threads.values():
                thread.start()

            def post(node, token_node=None):
                with session.post(urls[node], data=b'',
                                  headers={'Authorization': 'Bearer ' + tokens[token_node or node]},
                                  timeout=3, allow_redirects=False) as response:
                    assert response.content == b''
                    return response.status_code

            try:
                assert post('a') == 204
                assert post('b') == 204
                for store in stores.values():
                    assert store.check()['heartbeat_received'] is True
                    assert store.check()['missing'] is False
                    assert store.outbox.status()['queued'] == 0

                before = heartbeat_timestamp(stores['b'])
                clocks['b'][0] += 10
                cross_token = post('b', 'a')
                assert cross_token == 401, cross_token
                assert heartbeat_timestamp(stores['b']) == before

                clocks['a'][0] += 180
                assert stores['a'].check()['missing'] is True
                assert stores['a'].outbox.status()['active_incidents'] == 1
                assert stores['a'].outbox.status()['queued'] == 1
                assert post('b') == 204
                assert stores['b'].check()['missing'] is False
                assert stores['b'].outbox.status()['active_incidents'] == 0
                assert stores['b'].outbox.status()['queued'] == 0

                # Receiver restart reloads both the deadline and incident queue.
                stores['a'] = watchdog.WatchdogStore(
                    data_dirs['a'], timeout=180, node_name=names['a'],
                    clock=lambda: clocks['a'][0])
                servers['a'].store = stores['a']
                assert stores['a'].check()['missing'] is True
                assert stores['a'].outbox.status()['active_incidents'] == 1
                assert stores['a'].outbox.status()['queued'] == 1
                assert post('a') == 204
                assert stores['a'].check()['missing'] is False
                assert stores['a'].outbox.status()['active_incidents'] == 0
                assert stores['a'].outbox.status()['queued'] == 2

                # A failing recipient must not consume another node's queue or
                # impose its retry delay on the other node's healthy recipient.
                clocks['b'][0] += 180
                assert stores['b'].check()['missing'] is True
                failed = stores['b'].outbox.flush_once(settings['b'],
                                                      sender=sender_for('b', fail=True))
                assert failed['attempted'] == 1 and failed['sent'] == 0
                assert failed['queued'] == 1
                status_b = stores['b'].outbox.status()
                assert status_b['delivery_failures'] == 1
                assert status_b['next_retry_at'] > clocks['b'][0]
                assert delivered['b'] == []

                # B's queued failure and retry survive its own receiver restart.
                stores['b'] = watchdog.WatchdogStore(
                    data_dirs['b'], timeout=180, node_name=names['b'],
                    clock=lambda: clocks['b'][0])
                servers['b'].store = stores['b']
                assert stores['b'].outbox.status()['queued'] == 1
                early_retry = stores['b'].outbox.flush_once(settings['b'], sender=sender_for('b'))
                assert early_retry['attempted'] == 0 and early_retry['queued'] == 1
                assert len(attempts['b']) == 1

                success_a = stores['a'].outbox.flush_once(settings['a'], sender=sender_for('a'))
                assert success_a['sent'] == 2 and success_a['queued'] == 0
                assert len(delivered['a']) == 2
                assert '\nERROR\n' in delivered['a'][0]
                assert '\nRECOVERED\n' in delivered['a'][1]
                assert stores['b'].outbox.status()['queued'] == 1
                assert stores['b'].outbox.status()['delivery_failures'] == 1

                clocks['b'][0] = status_b['next_retry_at']
                success_b = stores['b'].outbox.flush_once(settings['b'], sender=sender_for('b'))
                assert success_b['sent'] == 1 and success_b['queued'] == 0
                assert '\nERROR\n' in delivered['b'][0]
                assert post('b') == 204
                assert stores['b'].check()['missing'] is False
                recovery_b = stores['b'].outbox.flush_once(settings['b'], sender=sender_for('b'))
                assert recovery_b['sent'] == 1 and recovery_b['queued'] == 0
                assert len(delivered['b']) == 2
                assert '\nRECOVERED\n' in delivered['b'][1]
                assert stores['a'].outbox.status()['queued'] == 0
                assert len(delivered['a']) == 2

                # Neither heartbeat credentials nor either bot/recipient setting
                # belongs in persisted incidents, delivery metadata, or logs.
                secrets = list(tokens.values()) + [value for value_by_key in settings.values()
                                                    for value in value_by_key.values()]
                persisted = b''.join(path.read_bytes() for data_dir in data_dirs.values()
                                     for path in data_dir.iterdir() if path.is_file())
                observable = (log_buffer.getvalue()
                              + json.dumps({node: stores[node].outbox.status() for node in stores})
                              + '\n'.join(attempts['a'] + attempts['b']))
                for secret in secrets:
                    assert secret.encode('utf-8') not in persisted, 'Credential persisted'
                    assert secret not in observable, 'Credential exposed in logs/status/message'
            finally:
                session.close()
                for server in servers.values():
                    server.shutdown()
                    server.server_close()
                for thread in threads.values():
                    thread.join(timeout=5)
                    assert not thread.is_alive(), 'HTTP receiver did not stop'
    finally:
        root_logger.removeHandler(handler)
        handler.close()

    print('MULTI_NODE_ISOLATION=True CROSS_TOKEN=401 BOT_QUEUE_ISOLATION=True '
          'RESTART_DURABLE=True TELEGRAM=FAKE')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
