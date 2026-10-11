"""Opt-in actual image/Gunicorn default-bind acceptance, Docker --network none.

Run inside the built image with /tests mounted read-only and /tmp writable.
Starts only fixture dashboard children; no worker, host NIC, Docker socket,
production credentials, Telegram, or external network is used.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request


def listening_addresses(port):
    result = set()
    for line in Path('/proc/net/tcp').read_text().splitlines()[1:]:
        fields = line.split()
        address, encoded_port = fields[1].split(':')
        if fields[3] == '0A' and int(encoded_port, 16) == port:
            result.add(address)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.parse_args(argv)
    if sys.platform != 'linux':
        raise RuntimeError('Linux acceptance runner required')
    if {path.name for path in Path('/sys/class/net').iterdir()} != {'lo'}:
        raise RuntimeError('Loopback-only network namespace required (Docker --network none)')
    assert os.environ.get('GUI_BIND') == '0.0.0.0', 'Built image ENV default must be 0.0.0.0'
    assert os.environ.get('GUI_PORT') == '7070', 'Built image ENV port must remain 7070'
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    cases = [('image-default', {}, False, '00000000', 7070),
             ('unset', {}, True, '00000000', 7070),
             ('empty', {'GUI_BIND': ''}, False, '00000000', 7070),
             ('loopback-override', {'GUI_BIND': '127.0.0.1'}, False, '0100007F', 7070),
             ('custom-port', {'GUI_PORT': '17070'}, False, '00000000', 17070)]
    for name, overrides, unset, expected_address, port in cases:
        assert not listening_addresses(port), 'Fixture port already in use'
        env = os.environ.copy()
        env.update({'APP_ROLE': 'dashboard', 'TELEGRAM_ENABLED': '0',
                    'SERVICE_TOKEN': 'bind-acceptance-service-token-' + 't' * 48,
                    'SECRET_KEY': 'bind-acceptance-session-secret-' + 's' * 48,
                    'ADMIN_PASSWORD': '', 'DASHBOARD_PASSWORD_PATH': '',
                    'WORKER_SOCKET': '/tmp/bind-acceptance-no-worker.sock'})
        for key in ('SERVICE_TOKEN_FILE', 'SECRET_KEY_FILE', 'ADMIN_PASSWORD_FILE', 'GUNICORN_CMD_ARGS'):
            env.pop(key, None)
        env.update(overrides)
        if unset:
            env.pop('GUI_BIND', None)
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(['/app/start.sh'], cwd='/app', env=env,
                                       stdout=output, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            try:
                deadline = time.monotonic() + 35
                while True:
                    if process.poll() is not None:
                        output.seek(0)
                        raise RuntimeError('Fixture dashboard exited: ' + output.read(8192).decode(errors='replace'))
                    try:
                        addresses = listening_addresses(port)
                        with opener.open(f'http://127.0.0.1:{port}/livez', timeout=1) as response:
                            body = json.load(response)
                            assert response.status == 200 and body.get('alive') is True
                        if addresses == {expected_address}:
                            break
                    except (OSError, ValueError):
                        pass
                    if time.monotonic() >= deadline:
                        raise RuntimeError('Fixture listener not ready: ' + name)
                    time.sleep(0.1)
                assert addresses == {expected_address}, (name, addresses)
                host = '127.0.0.1' if expected_address == '0100007F' else '0.0.0.0'
                print(f'DASHBOARD_BIND_CASE={name} LISTEN={host}:{port} HTTP_LIVEZ=200 PASS=True', flush=True)
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=40)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                        raise RuntimeError('Fixture dashboard failed to stop')
                # All descendants belong to this private process group. Reap
                # stragglers if a child outlived the entrypoint, then fail.
                if listening_addresses(port):
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    raise RuntimeError('Fixture dashboard listener was not cleaned up')
    print('DASHBOARD_BIND_CASES=5 PASS=5 FAIL=0 IMAGE_ENV=0.0.0.0:7070 HOST_NIC_CHANGES=0')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
