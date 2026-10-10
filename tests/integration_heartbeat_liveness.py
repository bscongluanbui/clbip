"""Opt-in actual HTTP heartbeat-liveness acceptance, Docker --network none.

Run from the image with /tests and source-only /scripts mounted read-only.
Real ProxyService/Flask, host probe, sender, receiver and SQLite use a fixture
clock, forbidden store/NIC/engine operations, and an explicit fake Telegram
recipient. The sender session maps one fixture Tailscale URL to its actual
loopback receiver; the production URL validator remains unchanged.
"""
import argparse
from contextlib import contextmanager
import html
import importlib.util
from pathlib import Path
import sys
import tempfile
import threading
from unittest.mock import patch


def load_script(name):
    root = Path(__file__).resolve().parents[1]
    candidates = (root / 'scripts' / (name + '.py'), root / (name + '.py'),
                  Path('/scripts') / (name + '.py'), Path('/app') / (name + '.py'))
    for path in candidates:
        if path.is_file():
            spec = importlib.util.spec_from_file_location('acceptance_' + name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            return module
    raise RuntimeError('Acceptance implementation not found: ' + name)


class ForbiddenComponent:
    """Any collaborator operation invalidates this read-only acceptance."""
    def __init__(self, name):
        self.name = name
        self.calls = []

    def __getattr__(self, method):
        def forbidden(*args, **kwargs):
            self.calls.append(method)
            raise AssertionError('Unexpected collaborator IO: ' + self.name + '.' + method)
        return forbidden


class ReconcilerThreadFixture:
    alive = True

    def is_alive(self):
        return self.alive


@contextmanager
def running_http(server, name):
    thread = threading.Thread(target=server.serve_forever, name=name, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive(), 'Acceptance HTTP server did not stop'


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.parse_args(argv)
    if sys.platform != 'linux':
        raise RuntimeError('Linux acceptance runner required')
    if {path.name for path in Path('/sys/class/net').iterdir()} != {'lo'}:
        raise RuntimeError('Loopback-only network namespace required (Docker --network none)')

    source_root = Path(__file__).resolve().parents[1]
    if (source_root / 'service.py').is_file():
        sys.path.insert(0, str(source_root))
    else:
        sys.path.insert(0, '/app')
    import requests
    import app as dashboard
    from heartbeat import HeartbeatMonitor
    from service import ProxyService
    from werkzeug.serving import make_server, WSGIRequestHandler
    host = load_script('host_heartbeat')
    watchdog = load_script('external_watchdog')

    class QuietRequestHandler(WSGIRequestHandler):
        def log(self, *args, **kwargs):
            pass

    now = [1000.0]
    token = 'liveness-acceptance-shared-token-12345678901234567890'
    configured_url = 'http://100.76.59.88:8088/heartbeat'
    recipients = {'telegram_bot_token': '123456:liveness-acceptance-fake-bot-only',
                  'telegram_chat_id': '-1001234567890'}
    messages = []

    def fake_sender(message, *, settings):
        assert settings == recipients, 'Unexpected Telegram recipient'
        messages.append(html.unescape(message))
        return True, 'Acceptance fake sender only'

    with tempfile.TemporaryDirectory(prefix='heartbeat-liveness-') as data_dir:
        data = Path(data_dir)
        fake_store = ForbiddenComponent('store')
        fake_store.path = data / 'service-data'
        fake_net = ForbiddenComponent('network')
        fake_engine = ForbiddenComponent('engine')
        fake_host = ForbiddenComponent('host-control')
        fake_alerts = ForbiddenComponent('service-alerts')
        components = (fake_store, fake_net, fake_engine, fake_host, fake_alerts)
        with patch('service.time.monotonic', side_effect=lambda: now[0]):
            service = ProxyService(store=fake_store, net=fake_net,
                                   proxy=fake_engine, host_control=fake_host)
            service.alerts = fake_alerts
            service.reconciler_thread = ReconcilerThreadFixture()
            service.last_reconciler_progress_monotonic = now[0]

            class WorkerFixture:
                def __init__(self):
                    self.liveness_calls = 0
                    self.ready_calls = 0

                def call(self, method, params=None, *, timeout=None):
                    if method == 'health':
                        self.ready_calls += 1
                        return {'ready': False}
                    assert method == 'controlplane_liveness', method
                    assert params is None and timeout == 2
                    self.liveness_calls += 1
                    return service.dispatch(method, {})

            worker = WorkerFixture()
            flask_app = dashboard.create_app({
                'TESTING': True, 'SECRET_KEY': 'liveness-fixture-session-' + 'x' * 40,
                'ADMIN_PASSWORD': '', 'SERVICE_TOKEN': 'liveness-fixture-api-' + 'y' * 40,
                'DASHBOARD_PASSWORD_PATH': '', 'TRUSTED_HOSTS': ['127.0.0.1', 'localhost']},
                client=worker)
            dashboard_server = make_server('127.0.0.1', 0, flask_app, threaded=True,
                                           request_handler=QuietRequestHandler)
            store = watchdog.WatchdogStore(data / 'watchdog', timeout=180,
                node_name='liveness-acceptance', clock=lambda: now[0])
            watchdog_server = watchdog.WatchdogServer(('127.0.0.1', 0), store, token)
            dashboard_base = 'http://127.0.0.1:' + str(dashboard_server.server_port)
            receiver_url = ('http://127.0.0.1:'
                            + str(watchdog_server.server_address[1]) + '/heartbeat')

            class LoopbackHeartbeatSession(requests.Session):
                def post(self, url, **kwargs):
                    assert url == configured_url, 'Unexpected heartbeat destination'
                    return super().post(receiver_url, **kwargs)

            probe = host.DashboardProbe({'LOCAL_DASHBOARD_URL': dashboard_base + '/heartbeatz'},
                                       monotonic=lambda: now[0])
            monitor = HeartbeatMonitor({'HEARTBEAT_URL': configured_url,
                'HEARTBEAT_ALLOW_HTTP': '1', 'HEARTBEAT_TOKEN': token,
                'HEARTBEAT_INTERVAL': '60'}, session=LoopbackHeartbeatSession(),
                monotonic=lambda: now[0])
            inspect_session = requests.Session()
            inspect_session.trust_env = False
            lock_held, release_lock = threading.Event(), threading.Event()

            def hold_mutation_lock():
                with service.lock:
                    lock_held.set()
                    release_lock.wait()

            lock_thread = threading.Thread(target=hold_mutation_lock,
                                           name='acceptance-mutation-lock', daemon=True)
            lock_thread.start()
            assert lock_held.wait(3), 'Fixture did not acquire mutation lock'

            def get(path):
                with inspect_session.get(dashboard_base + path, timeout=3,
                                         allow_redirects=False) as response:
                    return response.status_code, response.json()

            def beat():
                return monitor.emit_once(probe.snapshot, threading.Event())

            try:
                with running_http(dashboard_server, 'acceptance-dashboard'), \
                        running_http(watchdog_server, 'acceptance-heartbeat-receiver'):
                    assert get('/readyz') == (503, {'ready': False})
                    assert get('/heartbeatz') == (200, {'alive': True,
                        'worker_alive': True, 'progress_fresh': True})
                    checkpoint = service.last_reconciler_progress_monotonic
                    for _ in range(3):
                        snapshot = service.controlplane_liveness()
                        assert snapshot['last_reconcile_monotonic'] == checkpoint
                    assert service.last_reconciler_progress_monotonic == checkpoint
                    assert beat() == 'sent'
                    for _ in range(6):
                        now[0] += 60
                        service.last_reconciler_progress_monotonic = now[0]
                        assert get('/readyz') == (503, {'ready': False})
                        assert beat() == 'sent'
                        assert store.check()['missing'] is False
                        assert store.outbox.status()['queued'] == 0
                    assert monitor.successes == 7
                    assert all(not component.calls for component in components)
                    assert lock_held.is_set() and not release_lock.is_set()

                    # A genuinely stuck live reconciler must expire. Polling its
                    # endpoint cannot manufacture a new progress checkpoint.
                    now[0] += 331
                    checkpoint = service.last_reconciler_progress_monotonic
                    assert get('/heartbeatz') == (503, {'alive': True,
                        'worker_alive': True, 'progress_fresh': False})
                    attempts = monitor.attempts
                    assert beat() == 'unhealthy'
                    assert monitor.attempts == attempts
                    assert service.last_reconciler_progress_monotonic == checkpoint
                    assert store.check()['missing'] is True
                    assert store.outbox.status()['active_incidents'] == 1
                    assert store.outbox.status()['queued'] == 1

                    now[0] += 1
                    service.last_reconciler_progress_monotonic = now[0]
                    assert beat() == 'sent'
                    assert store.check()['missing'] is False
                    assert store.outbox.status()['active_incidents'] == 0
                    result = store.outbox.flush_once(recipients, sender=fake_sender)
                    assert result['sent'] == 2 and result['queued'] == 0
                    assert '\nERROR\n' in messages[0]
                    assert '\nRECOVERED\n' in messages[1]

                    # Thread death fails even if its most recent checkpoint is
                    # still fresh; no cached healthy reply is resent.
                    service.reconciler_thread.alive = False
                    now[0] += 180
                    assert get('/heartbeatz') == (503, {'alive': True,
                        'worker_alive': False, 'progress_fresh': True})
                    attempts = monitor.attempts
                    assert beat() == 'unhealthy'
                    assert monitor.attempts == attempts
                    assert store.check()['missing'] is True
                    service.reconciler_thread.alive = True
                    now[0] += 1
                    service.last_reconciler_progress_monotonic = now[0]
                    assert beat() == 'sent'
                    assert store.check()['missing'] is False
                    result = store.outbox.flush_once(recipients, sender=fake_sender)
                    assert result['sent'] == 2 and result['queued'] == 0
                    assert len(messages) == 4
                    assert all(not component.calls for component in components)
                    assert worker.ready_calls == 7
                    assert worker.liveness_calls >= 10
            finally:
                release_lock.set()
                lock_thread.join(timeout=5)
                assert not lock_thread.is_alive(), 'Fixture mutation lock did not stop'
                probe.close()
                monitor.session.close()
                inspect_session.close()

    print('READINESS_HTTP=503 LIVENESS_HTTP=200 BUSY_LOCK=True FRESH_HEARTBEATS=7 '
          'NO_FALSE_ALERTS=True STALE_HTTP=503 STALE_SUPPRESSED=True '
          'HUNG_DETECTED=True DEAD_THREAD_DETECTED=True RECOVERY=True '
          'NO_STORE_NIC_ENGINE_IO=True TELEGRAM=FAKE')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
