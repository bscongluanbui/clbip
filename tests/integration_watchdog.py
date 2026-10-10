"""Opt-in loopback watchdog acceptance; run in an isolated Linux container.

Uses the real HTTP receiver and SQLite persistence, a controllable fixture
clock, and an explicit fake Telegram sender. No public network is contacted.
Example: python /tests/integration_watchdog.py --run (Docker --network none).
"""
import argparse
import errno
import html
import importlib.util
from pathlib import Path
import sys
import socket
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
        spec = importlib.util.spec_from_file_location('acceptance_external_watchdog', path)
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    raise RuntimeError('Watchdog implementation not found')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.parse_args(argv)
    if sys.platform != 'linux':
        raise RuntimeError('Linux acceptance runner required')
    if {path.name for path in Path('/sys/class/net').iterdir()} != {'lo'}:
        raise RuntimeError('Loopback-only network namespace required (Docker --network none)')

    import requests
    watchdog = load_watchdog()
    token = 'offline-acceptance-shared-token-12345678901234567890'
    settings = {'telegram_bot_token': '123456:offline-acceptance-not-real',
                'telegram_chat_id': '-1001234567890'}
    now = [1000.0]
    messages = []

    def fake_sender(message, *, settings):
        assert settings['telegram_bot_token'] == '123456:offline-acceptance-not-real'
        messages.append(html.unescape(message))
        return True, 'Acceptance fake sender only'

    with tempfile.TemporaryDirectory(prefix='watchdog-acceptance-') as data_dir:
        store = watchdog.WatchdogStore(data_dir, timeout=180,
                                       node_name='acceptance-fixture', clock=lambda: now[0])
        server = watchdog.WatchdogServer(('127.0.0.1', 0), store, token)
        thread = threading.Thread(target=server.serve_forever,
                                  name='acceptance-watchdog-http', daemon=True)
        session = requests.Session()
        session.trust_env = False
        thread.start()
        url = f'http://127.0.0.1:{server.server_address[1]}/heartbeat'

        def post(*, authorized=True, body=b''):
            headers = {'Authorization': 'Bearer ' + token} if authorized else {}
            with session.post(url, headers=headers, data=body,
                              timeout=3, allow_redirects=False) as response:
                assert response.content == b''
                return response.status_code

        try:
            unauthorized = post(authorized=False)
            assert unauthorized == 401, unauthorized
            nonempty = post(body=b'not-empty')
            assert nonempty == 413, nonempty
            assert not store.check()['heartbeat_received']

            accepted = post()
            assert accepted == 204, accepted
            assert store.check()['heartbeat_received']
            assert not store.check()['missing']
            assert store.outbox.status()['queued'] == 0

            now[0] += 180
            outage = store.check()['missing']
            assert outage is True
            assert store.outbox.status()['active_incidents'] == 1
            assert store.outbox.status()['queued'] == 1

            reopened = watchdog.WatchdogStore(data_dir, timeout=180,
                node_name='acceptance-fixture', clock=lambda: now[0])
            durable = (reopened.check()['missing'] is True
                       and reopened.outbox.status()['active_incidents'] == 1
                       and reopened.outbox.status()['queued'] == 1)
            assert durable
            server.store = reopened

            assert post() == 204
            recovery = (reopened.check()['missing'] is False
                        and reopened.outbox.status()['active_incidents'] == 0
                        and reopened.outbox.status()['queued'] == 2)
            assert recovery
            delivered = reopened.outbox.flush_once(settings, sender=fake_sender)
            assert delivered['sent'] == 2, delivered
            assert delivered['queued'] == 0, delivered
            assert len(messages) == 2
            assert '\nERROR\n' in messages[0], messages[0]
            assert '\nRECOVERED\n' in messages[1], messages[1]
            assert reopened.outbox.status()['queued'] == 0
        finally:
            session.close()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            assert not thread.is_alive(), 'HTTP receiver did not stop'

    # Exercise the advertised IPv6 receiver path with the actual socket, not
    # only the generated config. IPv6-disabled kernels are reported explicitly.
    ipv6_result = 'UNAVAILABLE'
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as probe:
            probe.bind(('::1', 0))
    except OSError as exc:
        if exc.errno not in {errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT, errno.EADDRNOTAVAIL}:
            raise
    else:
        with tempfile.TemporaryDirectory(prefix='watchdog-ipv6-acceptance-') as data_dir:
            store = watchdog.WatchdogStore(data_dir, timeout=180,
                node_name='ipv6-acceptance-fixture', clock=lambda: now[0])
            server = watchdog.WatchdogServer(('::1', 0), store, token)
            assert server.address_family == socket.AF_INET6
            assert server.socket.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY) == 1
            thread = threading.Thread(target=server.serve_forever,
                name='acceptance-watchdog-ipv6-http', daemon=True)
            session = requests.Session()
            session.trust_env = False
            thread.start()
            url = f'http://[::1]:{server.server_address[1]}/heartbeat'
            try:
                with session.post(url, data=b'', headers={'Authorization': 'Bearer wrong-token'},
                                  timeout=3, allow_redirects=False) as response:
                    assert response.status_code == 401, response.status_code
                    assert response.content == b''
                assert store.check()['heartbeat_received'] is False
                with session.post(url, data=b'', headers={'Authorization': 'Bearer ' + token},
                                  timeout=3, allow_redirects=False) as response:
                    assert response.status_code == 204, response.status_code
                    assert response.content == b''
                assert store.check()['heartbeat_received'] is True
                now[0] += 10
                with session.post(url, data=b'', headers={'Authorization': 'Bearer wrong-token'},
                                  timeout=3, allow_redirects=False) as response:
                    assert response.status_code == 401, response.status_code
                assert store.check()['age_seconds'] == 10, 'Invalid token modified IPv6 heartbeat'
                ipv6_result = '204 IPV6_AUTH=401 IPV6_ONLY=True'
            finally:
                session.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                assert not thread.is_alive(), 'IPv6 HTTP receiver did not stop'

    print('WATCHDOG_HTTP=204 AUTH=401 BODY=413 OUTAGE=True '
          'RESTART_DURABLE=True RECOVERY=True TELEGRAM=FAKE IPV6_HTTP=' + ipv6_result)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
