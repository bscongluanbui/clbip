"""Opt-in worker/dashboard Docker role and IPC acceptance using fresh volumes."""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import uuid


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.parse_args(argv)
    root = Path(__file__).resolve().parents[1]
    fixture_root = root / 'audit' / 'fix' / 'runtime-fixtures'
    fixture = fixture_root / ('roles-' + uuid.uuid4().hex)
    fixture.mkdir(parents=True, mode=0o700)
    project = 'ipv6-audit-' + uuid.uuid4().hex[:10]
    secret_paths = {}
    for name in ('service_token', 'secret_key', 'admin_password'):
        path = fixture / name
        path.write_text(secrets.token_urlsafe(48))
        path.chmod(0o444)
        secret_paths[name] = {'file': str(path)}
    credential_directory = '/var/lib/ipv6-manager-credentials'
    password_path = credential_directory + '/admin_password'
    common = {'image': os.environ.get('TEST_IMAGE', 'ipv6-proxy-manager:local'), 'network_mode': 'none', 'read_only': True,
              'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'], 'init': True,
              'tmpfs': ['/tmp:rw,noexec,nosuid,mode=1777,size=64m'], 'stop_grace_period': '45s'}
    config = {'services': {
        'worker': {**common, 'user': '0:10001', 'cap_add': ['NET_ADMIN'],
                   'environment': {'APP_ROLE': 'worker', 'SERVICE_TOKEN_FILE': '/run/secrets/service_token',
                                   'ADMIN_PASSWORD_FILE': '/run/secrets/admin_password',
                                   'DASHBOARD_PASSWORD_PATH': password_path},
                   'secrets': ['service_token', 'admin_password'],
                   'volumes': ['data:/app/data', 'runtime:/run/ipv6-manager',
                               'credentials:' + credential_directory]},
        'dashboard': {**common, 'user': '10001:10001',
                      'environment': {'APP_ROLE': 'dashboard', 'SERVICE_TOKEN_FILE': '/run/secrets/service_token',
                                      'SECRET_KEY_FILE': '/run/secrets/secret_key', 'ADMIN_PASSWORD_FILE': '/run/secrets/admin_password',
                                      'DASHBOARD_PASSWORD_PATH': password_path, 'SESSION_COOKIE_SECURE': '0'},
                      'secrets': list(secret_paths), 'volumes': ['runtime:/run/ipv6-manager:ro',
                                                               'credentials:' + credential_directory + ':ro']}},
              'volumes': {'data': {}, 'runtime': {}, 'credentials': {}}, 'secrets': secret_paths}
    compose = fixture / 'compose.json'
    compose.write_text(json.dumps(config))
    command = ['docker', 'compose', '-p', project, '-f', str(compose)]
    def run(args, check=True):
        return subprocess.run(command + args, capture_output=True, text=True, timeout=120, check=check)
    try:
        run(['up', '-d'])
        probe = '''import errno,json,os,stat,urllib.request,urllib.error
from rpc import read_secret
from pathlib import Path
base='http://127.0.0.1:7070'
urllib.request.urlopen(base+'/readyz',timeout=3).close()
try:
 urllib.request.urlopen(base+'/api/settings',timeout=3)
 raise AssertionError('unauthenticated access')
except urllib.error.HTTPError as e:
 assert e.code==401
req=urllib.request.Request(base+'/api/proxy/health',headers={'Authorization':'Bearer '+read_secret('SERVICE_TOKEN')})
health=json.load(urllib.request.urlopen(req,timeout=5))
assert health['ready'] and health['desired_state']=='stopped'
assert os.getuid()==10001 and not Path('/app/data/state.sqlite3').exists()
assert 'CapEff:\\t0000000000000000' in Path('/proc/self/status').read_text()
credential=Path(os.environ['DASHBOARD_PASSWORD_PATH'])
metadata=credential.stat()
assert (metadata.st_uid,metadata.st_gid,stat.S_IMODE(metadata.st_mode))==(0,10001,0o640)
mounts=[line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
assert any(row[4]==str(credential.parent) and 'ro' in row[5].split(',') for row in mounts)
try:
 credential.write_text('unexpected-write')
 raise AssertionError('dashboard credential volume is writable')
except OSError as e:
 assert e.errno in (errno.EROFS,errno.EACCES)
print('DASHBOARD_UID=10001 CAPEFF=0 UNAUTH=401 READY=True IPC=True DATA_ISOLATED=True')
'''
        def wait_ready():
            deadline = time.monotonic() + 60
            while True:
                result = run(['exec', '-T', 'dashboard', 'python', '-c', probe], check=False)
                if result.returncode == 0:
                    print(result.stdout.strip())
                    return
                if time.monotonic() >= deadline:
                    raise RuntimeError('Isolated dashboard/IPC did not become ready: ' + result.stderr[-1500:])
                time.sleep(1)
        wait_ready()
        verify = '''from pathlib import Path
import os,stat
from rpc import read_secret
s=Path('/proc/self/status').read_text()
assert os.getuid()==0 and 'CapEff:\\t0000000000001000' in s
credential=Path(os.environ['DASHBOARD_PASSWORD_PATH'])
metadata=credential.stat()
assert (metadata.st_uid,metadata.st_gid,stat.S_IMODE(metadata.st_mode))==(0,10001,0o640)
parent=credential.parent.stat()
assert (parent.st_uid,parent.st_gid,stat.S_IMODE(parent.st_mode))==(0,10001,0o750)
assert credential.read_text()==read_secret('ADMIN_PASSWORD')
mounts=[line.split() for line in Path('/proc/self/mountinfo').read_text().splitlines()]
assert any(row[4]==str(credential.parent) and 'rw' in row[5].split(',') for row in mounts)
print('WORKER_UID=0 CAPEFF=NET_ADMIN_ONLY CREDENTIAL_UID=0 GID=10001 MODE=640 VOLUME_RW=True')
'''
        result = run(['exec', '-T', 'worker', 'python', '-c', verify])
        print(result.stdout.strip())
        # Exercise login + CSRF + HTTP -> authenticated IPC -> atomic credential
        # replacement, rather than changing the volume behind the dashboard.
        password_probe = '''import http.cookiejar,json,os,urllib.request,urllib.error,urllib.parse
from pathlib import Path
from rpc import read_secret
base='http://127.0.0.1:7070'
opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def csrf():
 return json.load(opener.open(base+'/api/csrf',timeout=5))['csrf_token']
def login(password):
 data=urllib.parse.urlencode({'password':password,'csrf_token':csrf()}).encode()
 response=opener.open(base+'/login',data,timeout=5)
 assert response.status==200 and response.geturl()==base+'/'
 response.close()
def unauthorized(path,**kwargs):
 try:
  opener.open(urllib.request.Request(base+path,**kwargs),timeout=5)
  raise AssertionError('old login/session remains valid')
 except urllib.error.HTTPError as e:
  assert e.code==401
old=read_secret('ADMIN_PASSWORD')
new='x'
login(old)
req=urllib.request.Request(base+'/api/password',data=json.dumps({'current_password':old,'new_password':new,'confirm_password':new}).encode(),headers={'Content-Type':'application/json','X-CSRF-Token':csrf()})
result=json.load(opener.open(req,timeout=10))
assert result['success'] and result['changed'] and result['requires_login']
unauthorized('/api/settings')
assert Path(os.environ['DASHBOARD_PASSWORD_PATH']).read_text()==new
assert read_secret('ADMIN_PASSWORD')==old and old!=new
data=urllib.parse.urlencode({'password':old,'csrf_token':csrf()}).encode()
unauthorized('/login',data=data)
login(new)
assert opener.open(base+'/api/settings',timeout=5).status==200
print('CREDENTIAL_VOLUME_RO=True PASSWORD_API=True ONE_CHAR_PASSWORD=True SESSION_REVOKED=True BOOTSTRAP_UNCHANGED=True')
'''
        result = run(['exec', '-T', 'dashboard', 'python', '-c', password_probe])
        print(result.stdout.strip())
        # Both roles restart on the same *isolated* volumes. Worker bootstrap
        # must not replace a changed password with its read-only Docker secret.
        run(['restart', 'worker', 'dashboard'])
        wait_ready()
        persisted_probe = '''import http.cookiejar,json,os,stat,urllib.request,urllib.error,urllib.parse
from pathlib import Path
from rpc import read_secret
base='http://127.0.0.1:7070'
credential=Path(os.environ['DASHBOARD_PASSWORD_PATH'])
assert credential.read_text()=='x' and read_secret('ADMIN_PASSWORD')!='x'
metadata=credential.stat()
assert (metadata.st_uid,metadata.st_gid,stat.S_IMODE(metadata.st_mode))==(0,10001,0o640)
opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def login(password):
 token=json.load(opener.open(base+'/api/csrf',timeout=5))['csrf_token']
 return opener.open(base+'/login',urllib.parse.urlencode({'password':password,'csrf_token':token}).encode(),timeout=5)
try:
 login(read_secret('ADMIN_PASSWORD'))
 raise AssertionError('restart reactivated bootstrap password')
except urllib.error.HTTPError as e:
 assert e.code==401
response=login('x')
assert response.status==200 and response.geturl()==base+'/'
response.close()
assert opener.open(base+'/api/settings',timeout=5).status==200
print('RESTART_PASSWORD_PERSISTED=True BOOTSTRAP_LOGIN=401 UPDATED_LOGIN=200 CREDENTIAL_MODE=640')
'''
        result = run(['exec', '-T', 'dashboard', 'python', '-c', persisted_probe])
        print(result.stdout.strip())
        print('LINUX_ROLE_CHECKS=8 PASS=8 FAIL=0 CREDENTIAL_ACCEPTANCE=PASS HOST_NIC_CHANGES=0')
        return 0
    finally:
        cleanup = run(['down', '--volumes', '--remove-orphans'], check=False)
        if cleanup.returncode:
            raise RuntimeError('Isolated project cleanup failed')
        for path in fixture.iterdir():
            if not path.is_file() or path.is_symlink() or path.resolve().parent != fixture.resolve():
                raise RuntimeError('Unexpected fixture cleanup target')
            path.chmod(0o600)
            path.unlink()
        fixture.rmdir()


if __name__ == '__main__':
    raise SystemExit(main())
