"""Single-owner transactional network service. Only the worker imports this module."""
import copy
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import subprocess
import threading
import time
import uuid

import ipv6_manager as network
import proxy_config as engine
import network_inventory
from host_control import HostControlError
from resource_metrics import ResourceMetricsSampler
from state_store import StateStore
from validation import (DEFAULT_SETTINGS, ValidationError, boolean, credential, generation_auth, integer, interface,
                        public_settings, settings_patch, target_url)


class OperationError(RuntimeError):
    pass


ALIAS_BATCH_SIZE = 16
VERIFY_WORKERS = 8
# Only these settings are consumed by an existing pool's rendered listeners.
# Allocation/protocol defaults affect future generation, not current proxy rows.
ENGINE_SETTING_FIELDS = frozenset({'dns1', 'dns2', 'dns3', 'timeout_connect', 'timeout_idle',
                                  'log_enabled', 'max_connections', 'listener_ipv4',
                                  'auth_type', 'allow_private_destinations'})
ROTATION_SETTING_FIELDS = frozenset({'rotation_enabled', 'rotation_interval'})


def address_key(record):
    return (str(ipaddress.IPv6Address(record.get('address', record.get('ipv6')))),
            record['interface'], int(record.get('address_prefix_len', record['prefix_len'])))


class ProxyService:
    def __init__(self, data_dir=None, *, store=None, net=None, proxy=None, host_control=None):
        self.store = store or StateStore(data_dir or os.environ.get('DATA_DIR', '/app/data'))
        self.net = net or network
        self.engine = proxy or engine
        if host_control is None:
            from host_control import HostControlClient
            host_control = HostControlClient()
        self.host_control = host_control
        self.metrics_sampler = ResourceMetricsSampler()
        self.lock = threading.RLock()
        self.started_at = time.time()
        self.last_probe = 0
        self.health_error = ''
        self.stop_event = threading.Event()
        self.cancel_operation = threading.Event()
        self.stop_in_progress = threading.Event()
        self.stop_intent_lock = threading.Lock()
        self.stop_requests = 0
        self.operation_deadline = None
        # A worker restart (including a host reboot) starts one durable rebuild,
        # never one rebuild per reconciler tick or dashboard restart.
        self.startup_pending = True
        self.last_base_probe = 0
        # Readers never wait behind a build's NIC/engine mutation lock. These
        # observations are explicitly cached, not fresh health evidence.
        self.progress_lock = threading.Lock()
        self.progress_depth = 0
        self.progress_started = None
        self.progress = {'stage': 'idle', 'total': 0, 'added': 0, 'ready': 0,
                         'verified': 0, 'elapsed_seconds': 0, 'last_update': 0,
                         'active': False, 'failed': False, 'address': '', 'last_error': ''}
        self.cached_processes = {'ready': None, 'running': None, 'expected': None,
                                 'instances': [], 'observation': 'not_collected'}
        self.cached_metrics = {'observation': 'not_collected'}
        self.interface_inventory = []
        self.source_cache = {'current_source': None, 'source_observed_at': None,
                             'source_verified': False, 'source_error': '',
                             'dashboard_hosts': [], 'proxy_hosts': []}
        self.inventory_observed_at = 0
        self.source_candidates = {}

    def dispatch(self, method, params):
        methods = {'settings': self.settings, 'save_settings': self.save_settings,
                   'users': self.users, 'add_user': self.add_user, 'delete_user': self.delete_user,
                   'proxies': self.proxies, 'generate': self.generate, 'delete': self.delete,
                   'delete_all': self.delete_all, 'rotate': self.rotate, 'cleanup': self.cleanup,
                   'start': self.start, 'stop': self.stop, 'restart': self.restart,
                   'status': self.status, 'health': self.health, 'interfaces': self.interfaces,
                   'subnets': self.subnets, 'addresses': self.addresses, 'export': self.export,
                   'logs': self.logs, 'speedtest': self.speedtest, 'speedtest_batch': self.speedtest_batch,
                   'auto_optimize': self.auto_optimize, 'telegram_config': self.telegram_config,
                   'telegram_test': self.telegram_test, 'events': self.events,
                   'resolve_uncertain': self.resolve_uncertain}
        if method not in methods or not isinstance(params, dict):
            raise ValidationError('Worker method/params không hợp lệ')
        if method in {'status', 'health', 'proxies'}:
            return methods[method](params)
        if method in {'settings', 'users', 'events', 'interfaces', 'addresses', 'subnets'}:
            return methods[method](params)
        # Rebuilding can involve many DAD/egress checks. Boot status must remain
        # readable while the NIC mutation lock is held; these are SQLite-only.
        if method in {'status', 'health', 'settings', 'users', 'events', 'interfaces', 'addresses', 'subnets', 'proxies'}:
            state = self.store.read()
            if self._recovery_active(state):
                if method == 'status':
                    return self._recovery_status_snapshot(state)
                if method == 'health':
                    return self._recovery_health_snapshot(state)
                if method == 'proxies':
                    return {'proxies': [{**p, 'status': 'recovering'} for p in state['proxies']],
                            'total': len(state['proxies']), 'running': None, 'instances': None,
                            'running_instances': None, 'pid': None, 'desired_state': state['desired_state'],
                            'desired_running': state['desired_state'] == 'running'}
                return methods[method](params)
        if method == 'stop':
            if set(params) - {'_idempotency_key'}:
                raise ValidationError('Stop không nhận tham số thay đổi cấu hình')
            with self.stop_intent_lock:
                self.stop_requests += 1
                self.stop_in_progress.set()
            self.cancel_operation.set()
            try:
                self.store.request_stop()
                with self.lock:
                    return self.stop({})
            finally:
                with self.stop_intent_lock:
                    self.stop_requests -= 1
                    if not self.stop_requests:
                        self.stop_in_progress.clear()
        with self.lock:
            params = dict(params)
            state = self.store.read()
            read_methods = {'settings', 'users', 'proxies', 'status', 'health', 'interfaces', 'subnets',
                            'addresses', 'export', 'logs', 'telegram_config', 'events'}
            if method not in read_methods:
                if self.stop_in_progress.is_set():
                    raise OperationError('Emergency Stop đang xử lý')
                self.cancel_operation.clear()
            if method not in read_methods | {'stop', 'resolve_uncertain'} and (state['pending_operation'] or state['uncertain_addresses']):
                raise OperationError('Recovery/ownership review đang chờ; xem health trước khi thay đổi')
            if self._recovery_active(state) and method not in read_methods | {
                    'start', 'restart', 'stop', 'save_settings', 'add_user', 'delete_user', 'resolve_uncertain'}:
                raise OperationError('Đang phục hồi sau khởi động; chờ hoàn tất hoặc nhấn Stop')
            key = params.pop('_idempotency_key', None)
            if not key:
                return self._invoke(methods[method], params)
            if not isinstance(key, str) or len(key) > 128 or not key.isascii() or any(ord(c) < 33 for c in key):
                raise ValidationError('Idempotency-Key không hợp lệ')
            signature = hashlib.sha256(json.dumps([method, params], sort_keys=True).encode()).hexdigest()
            state = self.store.read()
            cache = state.setdefault('operations', {})
            if key in cache:
                if cache[key]['signature'] != signature:
                    raise ValidationError('Idempotency-Key đã dùng với input khác')
                if cache[key]['status'] != 'complete':
                    raise OperationError('Operation cũ chưa có kết quả xác minh; không chạy lặp')
                return copy.deepcopy(cache[key]['result'])
            # An unchanged save has no side effect to journal. Preserve the
            # state revision even when a dashboard supplies a new request key.
            if (method == 'save_settings' and
                    settings_patch(params, state['settings']) == settings_patch({}, state['settings'])):
                return self._invoke(methods[method], params)
            cache[key] = {'signature': signature, 'status': 'pending', 'time': time.time()}
            state['operations'] = dict(list(cache.items())[-100:])
            self.store.write(state)
            try:
                result = self._invoke(methods[method], params)
            except Exception:
                state = self.store.read()
                state['operations'][key]['status'] = 'failed'
                self.store.write(state)
                raise
            state = self.store.read()
            state['operations'][key].update(status='complete', result=result)
            self.store.write(state)
            return result

    def _invoke(self, function, params):
        previous = self.operation_deadline
        budget = integer(int(os.environ.get('MAX_OPERATION_SECONDS', '240')), 'MAX_OPERATION_SECONDS', 10, 600)
        self.operation_deadline = time.monotonic() + budget
        progress_methods = {'generate', 'rotate', 'delete', 'delete_all', 'cleanup',
                            'start', 'restart', 'save_settings', 'add_user', 'delete_user',
                            'auto_optimize'}
        try:
            if function.__name__ in progress_methods:
                with self._progress_operation(function.__name__.lstrip('_')):
                    return function(params)
            return function(params)
        finally:
            self.operation_deadline = previous

    @contextmanager
    def _progress_operation(self, stage, total=0):
        with self.progress_lock:
            outer = not self.progress_depth
            self.progress_depth += 1
            if outer:
                self.progress_started = time.monotonic()
                self.progress.update(stage=stage, total=total, added=0, ready=0,
                                     verified=0, elapsed_seconds=0, last_update=time.time(),
                                     active=True, failed=False, address='', last_error='')
        try:
            yield
        except Exception as exc:
            self._progress_update(stage='canceled' if self.cancel_operation.is_set() else 'failed',
                                  failed=not self.cancel_operation.is_set(), last_error=str(exc)[:512])
            raise
        finally:
            with self.progress_lock:
                self.progress_depth -= 1
                if outer:
                    if self.progress['stage'] not in {'failed', 'canceled'}:
                        self.progress['stage'] = 'complete'
                    self.progress['active'] = False
                    self.progress['address'] = ''
                    self.progress['last_update'] = time.time()
                    self.progress['elapsed_seconds'] = round(max(0, time.monotonic() - self.progress_started), 3)

    def _progress_update(self, *, increment=None, **fields):
        with self.progress_lock:
            self.progress.update(fields)
            for field, value in (increment or {}).items():
                self.progress[field] += value
            self.progress['last_update'] = time.time()

    def _progress_snapshot(self):
        with self.progress_lock:
            progress = dict(self.progress)
            if progress['active'] and self.progress_started is not None:
                progress['elapsed_seconds'] = round(max(0, time.monotonic() - self.progress_started), 3)
            return progress

    def _cache_observation(self, *, processes=None, metrics=None):
        with self.progress_lock:
            if processes is not None:
                self.cached_processes = copy.deepcopy(processes)
                self.cached_processes['observed_at'] = time.time()
            if metrics is not None:
                self.cached_metrics = copy.deepcopy(metrics)

    def _cached_observation(self):
        with self.progress_lock:
            return copy.deepcopy(self.cached_processes), copy.deepcopy(self.cached_metrics)

    def _verify_batch(self, proxies, settings):
        """Bounded checks; join every job before rollback can delete an alias."""
        abort = threading.Event()

        def checkpoint():
            self._checkpoint()
            if abort.is_set():
                raise OperationError('Batch verification canceled')

        def verify(proxy):
            checkpoint()
            if not self.net.wait_for_ipv6_ready(proxy['ipv6'], proxy['interface'], timeout=10):
                raise OperationError('IPv6 chưa ready hoặc DAD thất bại')
            checkpoint()
            self._progress_update(increment={'ready': 1}, address=proxy['ipv6'])
            probe = self.net.probe_ipv6_egress(proxy['ipv6'], proxy['interface'],
                                             target_url=settings['probe_url'],
                                             timeout=settings['probe_timeout'],
                                             expected_address=proxy['ipv6'])
            checkpoint()
            if not probe.get('success'):
                raise OperationError('IPv6 source egress probe thất bại')
            self._progress_update(increment={'verified': 1}, address=proxy['ipv6'])

        failure = None
        # Explicit shutdown(wait=True) is provided by the executor context even
        # if Stop arrives or a task fails. No verifier survives this method.
        with ThreadPoolExecutor(max_workers=VERIFY_WORKERS, thread_name_prefix='ipv6-verify') as executor:
            futures = {executor.submit(verify, proxy): proxy for proxy in proxies}
            pending = set(futures)
            while pending:
                done, pending = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
                for future in done:
                    if future.cancelled():
                        continue
                    try:
                        future.result()
                    except Exception as exc:
                        if failure is None:
                            failure = exc
                            self._progress_update(address=futures[future]['ipv6'], last_error=str(exc)[:512],
                                                  failed=not self.cancel_operation.is_set())
                        abort.set()
                try:
                    self._checkpoint()
                except Exception as exc:
                    if failure is None:
                        failure = exc
                    abort.set()
                if abort.is_set():
                    for future in pending:
                        future.cancel()
        if failure is not None:
            raise failure

    def _validate(self, state):
        state['settings'] = settings_patch({}, state['settings'])
        for user in state['users']:
            credential(user['username'], user['password'])
        if state['proxies']:
            self.engine.validate_config_inputs(state['proxies'], state['users'], state['settings'])
        elif state['settings']['auth_type'] == 'none' and not state['settings']['public_proxy']:
            raise ValidationError('Public proxy phải được bật rõ ràng')

    def _ownership(self, proxy, *, active=True):
        return {'address': str(ipaddress.IPv6Address(proxy['ipv6'])), 'interface': proxy['interface'],
                'prefix_len': proxy.get('address_prefix_len', proxy['prefix_len']), 'owner': 'ipv6-manager', 'active': active}

    def _remove_owned(self, records, *, checkpoint=None):
        removed, failed = [], []
        if records:
            stage = self._progress_snapshot()['stage']
            self._progress_update(stage='rolling_back' if stage == 'rolling_back' else 'cleaning')
        for index, record in enumerate(records):
            if checkpoint:
                checkpoint()
            if self.stop_in_progress.is_set():
                failed.extend(records[index:])
                break
            if record.get('owner') != 'ipv6-manager':
                failed.append(record)
                continue
            result = self.net.bulk_remove_ipv6([record['address']], record['interface'], record['prefix_len'])
            (removed if result and all(x.get('success') for x in result) else failed).append(record)
            self._progress_update(address=record['address'])
        return removed, failed

    def _activate(self, state):
        for proxy in state['proxies']:
            candidate = self.source_candidates.get(proxy['interface'])
            if candidate and proxy['topology_mode'] == 'lan' and state['desired_state'] == 'running':
                target = ipaddress.IPv6Network(candidate['network'], strict=False)
                allocation = ipaddress.IPv6Network(f"{proxy['subnet']}/{proxy['prefix_len']}", strict=False)
                if not allocation.subnet_of(target):
                    raise OperationError('Chờ xác nhận prefix mới trước khi kích hoạt pool cũ.')
        config = self.engine.generate_config(state['proxies'], state['users'], state['settings'])
        self.engine.save_config(config)
        if state['desired_state'] == 'running' and state['proxies']:
            ok, message = self.engine.restart_3proxy()
        else:
            ok, message = self.engine.stop_3proxy()
        if not ok:
            raise OperationError(message)
        # Refresh after the mutation, never from the dashboard's status path.
        self._cache_observation(processes=self.engine.running_instances())

    def _transaction(self, proposed, added, action):
        with self._progress_operation('validating', len(added)):
            return self._transaction_body(proposed, added, action)

    def _transaction_body(self, proposed, added, action):
        """Journal intent, then confirmed kernel creation. Never claim an EEXIST alias."""
        self._progress_update(stage='validating', total=len(added), added=0, ready=0, verified=0)
        self._validate(proposed)
        before = self.store.read()
        budget = integer(int(os.environ.get('MAX_OPERATION_SECONDS', '240')), 'MAX_OPERATION_SECONDS', 10, 600)
        self.operation_deadline = min(self.operation_deadline or float('inf'), time.monotonic() + budget)
        self._checkpoint()
        snapshot = self.engine.snapshot_configs()
        pending = copy.deepcopy(before)
        pending['pending_operation'] = {'id': uuid.uuid4().hex, 'action': action,
                                        'before': before, 'configs': snapshot,
                                        'added': [],
                                        'staged': [{**self._ownership(p), 'creation': 'planned'} for p in added]}
        self.store.write(pending)
        try:
            for batch_start in range(0, len(added), ALIAS_BATCH_SIZE):
                batch = added[batch_start:batch_start + ALIAS_BATCH_SIZE]
                self._progress_update(stage='adding')
                for index, proxy in enumerate(batch, batch_start):
                    self._checkpoint()
                    stage = pending['pending_operation']['staged'][index]
                    stage['creation'] = 'attempting'
                    self.store.write(pending)
                    def confirmed(row, proxy=proxy, stage=stage):
                        if row.get('created') is not True or row.get('address') != proxy['ipv6']:
                            raise OperationError('Kernel creation evidence không khớp')
                        record = self._ownership(proxy)
                        stage['creation'] = 'confirmed'
                        pending['pending_operation']['added'].append(record)
                        pending['managed_addresses'].append(record)
                        self.store.write(pending)
                    rows = self.net.bulk_add_ipv6([proxy['ipv6']], proxy['interface'], proxy.get('address_prefix_len', proxy['prefix_len']),
                                                  wait_ready=False, on_created=confirmed)
                    if not rows or not all(x.get('success') and x.get('created') is True for x in rows):
                        # Unknown intent is not ownership; retain exact kernel
                        # callback evidence even when a later add result fails.
                        if stage['creation'] != 'confirmed':
                            stage['creation'] = 'not_created' if rows and all(x.get('created') is False for x in rows) else 'unknown'
                            self.store.write(pending)
                        raise OperationError('Add IPv6 thất bại; giao dịch đã hủy')
                    if stage['creation'] != 'confirmed':
                        raise OperationError('Missing durable kernel creation callback')
                    self._progress_update(increment={'added': 1}, address=proxy['ipv6'])
                self._progress_update(stage='verifying')
                self._verify_batch(batch, proposed['settings'])
            self._checkpoint()
            self._progress_update(stage='activating', address='')
            self._activate(proposed)
            self._checkpoint()
            proposed['pending_operation'] = None
            proposed['last_error'] = ''
            if (action != 'settings.apply' or any(proposed['settings'][key] != before['settings'][key]
                                                 for key in ROTATION_SETTING_FIELDS)):
                proposed['rotation_due'] = (0 if action == 'settings.apply' and
                                           not proposed['settings']['rotation_enabled'] else
                                           time.time() + proposed['settings']['rotation_interval'] * 60)
            else:
                proposed['rotation_due'] = before['rotation_due']
            active = {address_key(p) for p in proposed['proxies']}
            merged = {address_key(r): copy.deepcopy(r) for r in pending['managed_addresses']}
            for p in proposed['proxies']:
                merged[address_key(p)] = self._ownership(p)
            for key, record in merged.items():
                record['active'] = key in active
            proposed['managed_addresses'] = list(merged.values())
            for p in proposed['proxies']:
                p['status'] = 'active' if proposed['desired_state'] == 'running' else 'stopped'
            recovery = proposed.get('startup_recovery')
            if recovery and recovery.get('phase') == 'done' and action == 'proxies.generate':
                recovery['completed_at'] = time.time()
            self.store.event(proposed, action, 'committed')
            committed = self.store.write(proposed)
        except Exception as exc:
            self._progress_update(stage='rolling_back', last_error=str(exc)[:512],
                                  failed=not self.cancel_operation.is_set())
            rollback_errors = []
            try:
                ok, message = self.engine.stop_3proxy()
                if not ok:
                    raise OperationError(message)
                self._cache_observation(processes=self.engine.running_instances())
                self.engine.restore_configs(snapshot)
            except Exception as rollback_exc:
                rollback_errors.append(type(rollback_exc).__name__)
            if rollback_errors:
                pending['last_error'] = 'Rollback incomplete; staged ownership journal retained'
                self.store.write(pending)
                raise OperationError('Runtime rollback chưa hoàn tất; journal/ledger giữ nguyên để recovery') from exc
            _, failed = self._remove_owned(pending['pending_operation']['added'])
            before['managed_addresses'] += [{**r, 'active': False} for r in failed]
            before['uncertain_addresses'] += self._uncertain_stages(pending['pending_operation'])
            before['last_error'] = 'Transaction rolled back' + ('; runtime recovery pending' if rollback_errors else '')
            self.store.event(before, action, 'rolled_back', type(exc).__name__)
            before = self.store.write(before)
            if (before['desired_state'] == 'running' and before['proxies'] and
                    action != 'prefix.renumber' and not self.source_candidates):
                ok, message = self.engine.start_3proxy()
                self._cache_observation(processes=self.engine.running_instances())
                if not ok:
                    before['last_error'] = 'Old runtime recovery pending'
                    self.store.write(before)
                    rollback_errors.append(message)
            raise OperationError(str(exc) + ('; cần kiểm tra runtime recovery' if rollback_errors else '')) from exc
        retired = [r for r in committed['managed_addresses'] if not r.get('active')]
        removed, failed = self._remove_owned(retired)
        removed_keys = {address_key(r) for r in removed}
        committed['managed_addresses'] = [r for r in committed['managed_addresses'] if address_key(r) not in removed_keys]
        if failed:
            committed['last_error'] = f'{len(failed)} owned IPv6 chờ cleanup retry'
        self.store.write(committed)
        try:
            self.engine.prune_configs()
        except Exception:
            pass  # A retention failure must not undo a successful runtime commit.
        self.health_error = ''
        return {'success': True, 'cleanup_pending': len(failed), 'revision': committed['revision']}

    def _checkpoint(self):
        if self.cancel_operation.is_set() or self.stop_event.is_set():
            raise OperationError('Operation canceled by Stop; rollback giữ snapshot trước')
        if self.operation_deadline is not None and time.monotonic() >= self.operation_deadline:
            raise OperationError('Operation time budget hết; rollback giữ snapshot trước')

    def _cancellation_checkpoint(self):
        if self.cancel_operation.is_set() or self.stop_event.is_set():
            raise OperationError('Operation canceled by Stop')

    def settings(self, params):
        return public_settings(self.store.read()['settings'])

    def save_settings(self, params):
        before = self.store.read()
        previous = settings_patch({}, before['settings'])
        updated = settings_patch(params, previous)
        changed_fields = {key for key in updated if updated[key] != previous[key]}
        if not changed_fields:
            return {'success': True, 'changed': False, 'restarted': False,
                    'revision': before['revision'], 'settings': public_settings(previous)}

        state = copy.deepcopy(before)
        state['settings'] = updated
        self._validate(state)
        recovering = self._recovery_active(before)
        engine_changed = bool(changed_fields & ENGINE_SETTING_FIELDS)
        if 'allowed_ips' in changed_fields and updated['auth_type'] == 'ip':
            engine_changed = True
        if changed_fields & ROTATION_SETTING_FIELDS:
            state['rotation_due'] = (time.time() + updated['rotation_interval'] * 60
                                     if updated['rotation_enabled'] else 0)
        if recovering and not updated['startup_rebuild_enabled']:
            state['startup_recovery'] = None
            state['desired_state'], state['manual_stop'] = 'stopped', True

        receipt = None
        try:
            self._checkpoint()
            if 'thread_limit' in changed_fields:
                try:
                    receipt = self.host_control.apply_limit(updated['thread_limit'])
                except HostControlError as exc:
                    raise OperationError(str(exc)) from exc
                if (not isinstance(receipt, dict) or
                        receipt.get('effective_limit') != updated['thread_limit'] or
                        'previous_limit' not in receipt):
                    raise OperationError('Host chưa xác nhận trần thread đã yêu cầu')
            self._checkpoint()
            if recovering and engine_changed:
                # Never activate stale listeners during startup recovery.
                result = self._commit_recovery_edit(state, 'settings.apply')
            elif engine_changed:
                result = self._transaction(state, [], 'settings.apply')
            else:
                # No config snapshot/write, process restart, alias cleanup or
                # pool remapping belongs to a control-only settings save.
                self.store.event(state, 'settings.apply', 'updated_without_activation',
                                 ','.join(sorted(changed_fields)))
                committed = self.store.write(state)
                result = {'success': True, 'revision': committed['revision']}
                if recovering:
                    result['queued'] = True
        except Exception:
            if isinstance(receipt, dict) and 'previous_limit' in receipt:
                # Transaction errors before commit restore the host limit too.
                # A post-commit cleanup error must not undo a committed limit.
                persisted = self.store.read()
                if persisted['settings'] != state['settings']:
                    try:
                        self.host_control.restore_limit(receipt['previous_limit'])
                    except Exception as rollback_exc:
                        raise OperationError('Khôi phục trần thread cần kiểm tra host') from rollback_exc
            raise
        result.update(changed=True, changed_fields=sorted(changed_fields),
                      engine_config_changed=engine_changed,
                      restarted=bool(engine_changed and not recovering and
                                     state['desired_state'] == 'running' and state['proxies']),
                      settings=public_settings(updated))
        if receipt is not None:
            result.update(thread_limit_applied=True, effective_thread_limit=receipt['effective_limit'])
        return result

    def users(self, params):
        return {'users': [{k: v for k, v in u.items() if k != 'password'} for u in self.store.read()['users']]}

    def add_user(self, params):
        if set(params) != {'username', 'password'}:
            raise ValidationError('User cần username và password')
        name, password = credential(params['username'], params['password'])
        state = self.store.read()
        if any(u['username'] == name for u in state['users']):
            raise ValidationError('User đã tồn tại')
        state['users'].append({'username': name, 'password': password, 'created_at': time.strftime('%Y-%m-%d %H:%M:%S')})
        result = self._commit_recovery_edit(state, 'user.add') if self._recovery_active(state) else self._transaction(state, [], 'user.add')
        return {**result, **self.users({})}

    def delete_user(self, params):
        state = self.store.read()
        state['users'] = [u for u in state['users'] if u['username'] != params.get('username')]
        result = self._commit_recovery_edit(state, 'user.delete') if self._recovery_active(state) else self._transaction(state, [], 'user.delete')
        return {**result, **self.users({})}

    def interfaces(self, params):
        rows = self._refresh_inventory(self.store.read())
        return {'interfaces': [row['device'] for row in rows], 'details': rows}

    def _inventory_ownership(self, state):
        # Readers can run while a creation callback is still in flight. Its
        # durable attempting/unknown intent is not a confirmed owner, but must
        # not be mistaken for a new system/base address in that window.
        uncertain = list(state['uncertain_addresses'])
        if state.get('pending_operation'):
            uncertain += self._uncertain_stages(state['pending_operation'])
        return state['managed_addresses'], uncertain

    def _refresh_inventory(self, state):
        """Passive local observation, independent of network mutation ownership."""
        try:
            managed, uncertain = self._inventory_ownership(state)
            rows = network_inventory.collect(self.net, managed, uncertain=uncertain)
            verified = state['prefix_state'].get(state['settings']['interface'], {})
            source = network_inventory.observed_source(rows, state['settings']['interface'],
                managed + uncertain, preferred=verified)
            try:
                proven = bool(source and verified.get('verified') is True and not state['last_error'] and
                              ipaddress.IPv6Address(verified['address']) == ipaddress.IPv6Address(source['address']))
            except (ValueError, TypeError, KeyError):
                proven = False
            hosts = network_inventory.hosts(rows)
            view = {'current_source': source, 'source_verified': proven,
                    'source_observed_at': time.time(), 'source_error': '',
                    'dashboard_hosts': hosts, 'proxy_hosts': hosts}
            with self.progress_lock:
                self.interface_inventory = copy.deepcopy(rows)
                self.source_cache = view
                self.inventory_observed_at = time.monotonic()
            return rows
        except (OSError, RuntimeError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
            with self.progress_lock:
                self.interface_inventory = []
                self.source_cache = {'current_source': None, 'source_observed_at': None,
                    'source_verified': False, 'source_error': 'Chưa đọc được thông tin card mạng.',
                    'dashboard_hosts': [], 'proxy_hosts': []}
            # A failed observation is never presented as a fresh candidate.
            return []

    def _remember_source(self, selected):
        with self.progress_lock:
            self.source_cache = {**self.source_cache, 'current_source': copy.deepcopy(selected),
                'source_verified': selected.get('verified') is True,
                'source_observed_at': time.time(), 'source_error': ''}

    def _source_snapshot(self, state):
        with self.progress_lock:
            view = copy.deepcopy(self.source_cache)
        source = view.get('current_source')
        if source and source.get('interface') != state['settings']['interface']:
            view.update(current_source=None, source_verified=False, source_observed_at=None,
                        source_error='Đang chờ quan sát IPv6 nguồn trên interface mới.')
        return view

    def addresses(self, params):
        iface = params.get('interface')
        managed, uncertain = self._inventory_ownership(self.store.read())
        records = self.net.get_ipv6_addresses(interface(iface) if iface else None, strict=True)
        return {'addresses': network_inventory.annotate_addresses(records, managed, uncertain=uncertain)}

    def subnets(self, params):
        iface = interface(params.get('interface', 'eth0'))
        state = self.store.read()
        managed, uncertain = self._inventory_ownership(state)
        verified = state['prefix_state'].get(iface, {}) if not state['last_error'] else {}
        seen = {}
        rows = network_inventory.collect(self.net, managed, uncertain=uncertain)
        records = [record for row in rows if row['device'] == iface for record in row['source_ipv6']]
        try:
            verified_address = str(ipaddress.IPv6Address(verified['address'])) if verified.get('verified') is True else None
        except (ValueError, TypeError, KeyError):
            verified_address = None
        # Preserve the verified system source when multiple SLAAC/privacy
        # addresses share a prefix; later raw inventory order is not proof.
        records.sort(key=lambda r: (str(ipaddress.IPv6Address(r['address'])) != verified_address,
                                    'temporary' in r.get('flags', []), r['address']))
        for record in records:
            addr = ipaddress.IPv6Address(record['address'])
            length = record.get('pool_prefix_len', record['prefix_len'])
            net = ipaddress.IPv6Network(f"{addr}/{length}", strict=False)
            if str(net) in seen:
                continue
            seen[str(net)] = {'subnet': str(net.network_address), 'prefix_len': net.prefixlen,
                              'full': str(net), 'source_address': str(addr),
                              'verified': verified_address == str(addr)}
        return {'subnets': list(seen.values()), 'interface': iface}

    def proxies(self, params):
        if not self.lock.acquire(blocking=False):
            return self._proxies_snapshot(self.store.read())
        try:
            state = self.store.read()
            if self._progress_snapshot()['active'] or self._recovery_active(state):
                return self._proxies_snapshot(state)
            return self._proxies_observed(state)
        finally:
            self.lock.release()

    def _proxies_snapshot(self, state):
        processes, _ = self._cached_observation()
        progress = self._progress_snapshot()
        recovering = self._recovery_active(state)
        return {'proxies': [{**p, 'status': 'recovering' if recovering else p.get('status', 'pending')}
                            for p in state['proxies']], 'total': len(state['proxies']),
                'running': processes.get('ready'), 'instances': processes.get('expected'),
                'running_instances': processes.get('running'), 'pid': None,
                'desired_state': state['desired_state'], 'desired_running': state['desired_state'] == 'running',
                'progress': progress, 'observation': 'cached_during_mutation'}

    def _proxies_observed(self, state):
        health = self.engine.running_instances()
        self._cache_observation(processes=health)
        return {'proxies': state['proxies'], 'total': len(state['proxies']),
                'running': bool(health.get('ready')), 'instances': health.get('expected', 0),
                'running_instances': health.get('running', 0), 'pid': None,
                'desired_state': state['desired_state'], 'desired_running': state['desired_state'] == 'running',
                'progress': self._progress_snapshot(), 'observation': 'live'}

    def _ports(self, existing, count, start, protocol, offset):
        used = {port for p in existing for port in (p['port'], p.get('socks_port')) if port}
        ports, candidate = [], start
        while len(ports) < count and candidate <= 65535:
            pair = [candidate] + ([candidate + offset] if protocol == 'dual' else [])
            if max(pair) <= 65535 and len(set(pair)) == len(pair) and not used.intersection(pair):
                ports.append(pair)
                used.update(pair)
            candidate += 1
        if len(ports) != count:
            raise ValidationError('Không còn đủ ports trong khoảng 1024..65535')
        return ports

    def generate(self, params):
        allowed = {'count', 'recreate', 'socks_port_offset', 'username', 'password', 'start'} | set(DEFAULT_SETTINGS)
        if set(params) - allowed:
            raise ValidationError('Generate chứa trường không hỗ trợ')
        state = self.store.read()
        patch = {k: v for k, v in params.items() if k in DEFAULT_SETTINGS}
        state['settings'], supplied_credential = generation_auth(params, settings_patch(patch, state['settings']))
        settings = state['settings']
        count = integer(params.get('count', 5), 'count', 1, int(os.environ.get('MAX_PROXY_SERVICES', '1024')))
        recreate = boolean(params.get('recreate', False), 'recreate')
        offset = integer(params.get('socks_port_offset', 10000), 'socks_port_offset', 1, 64511)
        if supplied_credential is not None:
            name, password = supplied_credential
            # Explicit combined generation updates an existing credential atomically.
            state['users'] = [u for u in state['users'] if u['username'] != name]
            state['users'].append({'username': name, 'password': password, 'created_at': time.strftime('%Y-%m-%d %H:%M:%S')})
        if not settings['subnet']:
            raise ValidationError('Cần subnet')
        existing = [] if recreate else state['proxies']
        ports = self._ports(existing, count, settings['start_port'], settings['protocol'], offset)
        # Resource/auth/config validation occurs even before querying/mutating the NIC.
        used_ids = {p['id'] for p in existing}
        def new_id():
            while True:
                value = uuid.uuid4().int & ((1 << 52)-1)
                if value not in used_ids:
                    used_ids.add(value)
                    return value
        provisional = [{'id': new_id(), 'ipv6': f'2001:db8::{i+1:x}', 'port': pair[0],
                        'protocol': settings['protocol'], 'interface': settings['interface'], 'prefix_len': settings['prefix_len'], 'address_prefix_len': 128,
                        'topology_mode': settings['topology_mode'], 'routed_prefix': settings['routed_prefix'],
                        **({'socks_port': pair[1]} if len(pair) > 1 else {})} for i, pair in enumerate(ports)]
        state['proxies'] = existing + provisional
        self._validate(state)
        preflight = self.net.topology_preflight(settings['subnet'], settings['prefix_len'], settings['interface'],
                                                topology_mode=settings['topology_mode'], routed_prefix=settings['routed_prefix'] or None)
        if not preflight.get('success'):
            raise ValidationError('Topology preflight: ' + '; '.join(preflight.get('errors', ['failed'])))
        current = self.net.get_ipv6_addresses(settings['interface'], strict=True)
        excluded = [r['address'] for r in current] + [r['address'] for r in self.store.read()['managed_addresses']]
        recovery = state.get('startup_recovery')
        if recovery and recovery.get('phase') == 'generating':
            excluded.extend(recovery.get('previous_addresses', []))
        addresses = self.net.generate_random_ipv6(settings['subnet'], settings['prefix_len'], count,
                                                  exclude_addresses=excluded)
        for p, addr in zip(provisional, addresses):
            p.update(ipv6=addr, subnet=settings['subnet'], created_at=time.strftime('%Y-%m-%d %H:%M:%S'), status='pending')
        state['desired_state'] = 'running' if boolean(params.get('start', True), 'start') else 'stopped'
        state['manual_stop'] = state['desired_state'] == 'stopped'
        recovery = state.get('startup_recovery')
        if recovery and recovery.get('phase') == 'generating':
            recovery.update(state='ready', phase='done', message='Đã tạo mới proxy từ IPv6 gốc đã xác minh',
                            completed_at=time.time())
        result = self._transaction(state, provisional, 'proxies.generate')
        return {**result, 'generated': count, 'total': len(state['proxies']), 'proxies': self.store.read()['proxies'][-count:]}

    def _replacement(self, state, selected, *, replacement_networks=None):
        excluded = {r['address'] for r in state['managed_addresses']}
        added = []
        for p in state['proxies']:
            if selected is not None and p['id'] not in selected:
                continue
            self._checkpoint()
            prefix, length = (replacement_networks or {}).get(p['interface'], (p['subnet'], p['prefix_len']))
            preflight = self.net.topology_preflight(prefix, length, p['interface'], topology_mode=p['topology_mode'],
                                                    routed_prefix=p['routed_prefix'] or None)
            if not preflight.get('success'):
                raise OperationError('Rotation topology preflight failed')
            current = self.net.get_ipv6_addresses(p['interface'], strict=True)
            excluded.update(r['address'] for r in current)
            addr = self.net.generate_random_ipv6(prefix, length, 1, exclude_addresses=excluded)[0]
            excluded.add(addr)
            p.update(ipv6=addr, subnet=prefix, prefix_len=length, address_prefix_len=128)
            added.append(p)
        return added

    def rotate(self, params):
        state = self.store.read()
        identifier = params.get('proxy_id')
        if identifier is not None and not any(p['id'] == identifier for p in state['proxies']):
            raise ValidationError('Proxy không tồn tại')
        old = {p['id']: p['ipv6'] for p in state['proxies']}
        added = self._replacement(state, None if identifier is None else {identifier})
        result = self._transaction(state, added, 'proxies.rotate')
        if identifier is not None:
            return {**result, 'proxy_id': identifier, 'old_ipv6': old[identifier], 'new_ipv6': added[0]['ipv6'], 'port': added[0]['port']}
        return {**result, 'rotated': len(added)}

    def delete(self, params):
        state = self.store.read()
        identifier = params.get('proxy_id')
        if not any(p['id'] == identifier for p in state['proxies']):
            raise ValidationError('Proxy không tồn tại')
        state['proxies'] = [p for p in state['proxies'] if p['id'] != identifier]
        if not state['proxies']:
            state['desired_state'] = 'stopped'
            state['manual_stop'] = True
        return {**self._transaction(state, [], 'proxy.delete'), 'remaining': len(state['proxies'])}

    def delete_all(self, params):
        state = self.store.read()
        state['proxies'], state['desired_state'] = [], 'stopped'
        state['manual_stop'] = True
        return self._transaction(state, [], 'proxies.delete_all')

    def cleanup(self, params):
        state = self.store.read()
        if not any(not record.get('active') for record in state['managed_addresses']):
            return {'success': True, 'removed': 0, 'failed': 0,
                    'kept': len(state['managed_addresses']), 'message': 'Đã cleanup 0 owned IPv6; 0 chờ retry'}
        with self._progress_operation('cleaning'):
            return self._cleanup(params)

    def _cleanup(self, params):
        state = self.store.read()
        records = [r for r in state['managed_addresses'] if not r.get('active')]
        removed, failed = self._remove_owned(records)
        keys = {address_key(r) for r in removed}
        state['managed_addresses'] = [r for r in state['managed_addresses'] if address_key(r) not in keys]
        self.store.write(state)
        return {'success': not failed, 'removed': len(removed), 'failed': len(failed), 'kept': len(state['managed_addresses']),
                'message': f'Đã cleanup {len(removed)} owned IPv6; {len(failed)} chờ retry'}

    def start(self, params):
        state = self.store.read()
        if state['settings']['startup_rebuild_enabled'] and (state['manual_stop'] or not state['proxies'] or
                (state.get('startup_recovery') or {}).get('phase') not in {None, 'done'}):
            return self._queue_startup_rebuild(state)
        if not state['proxies']:
            raise ValidationError('Chưa có proxy')
        self._validate(state)
        restored = self.net.restore_proxy_addresses(state['proxies'], state['settings'], probe=True, checkpoint=self._checkpoint)
        if restored.get('failed'):
            raise OperationError('Một số IPv6 chưa ready; giữ desired state trước đó')
        state['desired_state'] = 'running'
        state['manual_stop'] = False
        return {**self._transaction(state, [], 'proxy.start'), 'message': 'Đã chạy tất cả proxy instances'}

    def stop(self, params):
        state = self.store.read()
        state['desired_state'] = 'stopped'
        state['manual_stop'] = True
        if state['pending_operation']:
            state['pending_operation']['before']['desired_state'] = 'stopped'
            state['pending_operation']['before']['manual_stop'] = True
        if state.get('startup_recovery'):
            state['startup_recovery'].update(state='stopped', message='Đã dừng thủ công; nhấn Start để tiếp tục')
        self.store.event(state, 'proxy.stop', 'requested')
        self.store.write(state)
        # Emergency stop must work even with invalid migrated credentials/settings.
        ok, message = self.engine.stop_3proxy()
        state['last_error'] = '' if ok else 'Owned process stop chưa được xác minh'
        for p in state['proxies']:
            p['status'] = 'stopped' if ok else 'stopping'
        self.store.event(state, 'proxy.stop', 'applied' if ok else 'failed')
        self.store.write(state)
        if not ok:
            raise OperationError(message)
        self.health_error = ''
        self._cache_observation(processes={'ready': False, 'running': 0, 'expected': None,
                                          'instances': [], 'observation': 'stop_acknowledged'})
        return {'success': True, 'message': 'Đã dừng; reconciler giữ trạng thái stopped'}

    def restart(self, params):
        state = self.store.read()
        if state['settings']['startup_rebuild_enabled']:
            return self._queue_startup_rebuild(state)
        return self.start(params)

    def status(self, params):
        # Status is a cheap, explicitly cached observation even when idle.
        # /health remains the separate, deep current NIC/listener check.
        return self._recovery_status_snapshot(self.store.read())

    def health(self, params):
        if not self.lock.acquire(blocking=False):
            return self._recovery_health_snapshot(self.store.read())
        try:
            state = self.store.read()
            if self._progress_snapshot()['active'] or self._recovery_active(state):
                return self._recovery_health_snapshot(state)
            return self._health_observed(state)
        finally:
            self.lock.release()

    def _health_observed(self, state):
        processes = self.engine.running_instances()
        desired = state['desired_state']
        errors = [state['last_error']] if state['last_error'] else []
        if self.health_error:
            errors.append(self.health_error)
        errors.extend(processes.get('errors', []))
        if state['pending_operation']:
            errors.append('Interrupted transaction chưa recovery xong')
        if state['uncertain_addresses']:
            errors.append('Kernel creation chưa xác minh; cần ownership review')
        recovery = self._startup_status(state)
        if desired == 'running' and recovery.get('phase') not in {None, 'done'}:
            errors.append(recovery['message'])
        if desired == 'running':
            if not processes.get('ready'):
                errors.append('Expected instances/listeners chưa ready')
            # One strict NIC observation per interface replaces a subprocess
            # snapshot per alias. Never reuse this observation across requests.
            ready_addresses = {}
            for iface in {p['interface'] for p in state['proxies']}:
                usable = set()
                try:
                    for row in self.net.get_ipv6_addresses(iface, strict=True):
                        if (row['interface'] == iface and row.get('ready') is True and
                                not set(row.get('flags', [])) & {'tentative', 'dadfailed', 'deprecated'} and
                                row.get('valid_lft') != 0 and row.get('preferred_lft') != 0):
                            usable.add((str(ipaddress.IPv6Address(row['address'])), int(row['prefix_len'])))
                except (OSError, RuntimeError, ValueError, TypeError, KeyError, subprocess.SubprocessError):
                    usable = set()  # Failed/invalid snapshots cannot prove readiness.
                ready_addresses[iface] = usable
            for p in state['proxies']:
                try:
                    key = (str(ipaddress.IPv6Address(p['ipv6'])),
                           int(p.get('address_prefix_len', p['prefix_len'])))
                    ready = key in ready_addresses[p['interface']]
                except (ValueError, TypeError, KeyError):
                    ready = False
                if not ready:
                    errors.append(f"IPv6 chưa ready trên {p['interface']}")
            for iface in {p['interface'] for p in state['proxies']}:
                observed = self.net.observe_prefix_state(iface, managed_addresses=[r for r in state['managed_addresses'] if r['interface'] == iface])
                if not any(r.get('dst') in {'default', '::/0'} and r.get('type', 'unicast') == 'unicast'
                           and r.get('expires') != 0 and 'linkdown' not in r.get('flags', []) for r in observed.get('routes', [])):
                    errors.append(f'Không có IPv6 default route trên {iface}')
            groups = {(p['subnet'], p['prefix_len'], p['interface'], p['topology_mode'], p['routed_prefix']) for p in state['proxies']}
            for subnet, length, iface, mode, allocation in groups:
                topology = self.net.topology_preflight(subnet, length, iface, topology_mode=mode, routed_prefix=allocation or None)
                if not topology.get('success'):
                    errors.append(f'Topology/prefix chưa usable trên {iface}')
        elif processes.get('running'):
            errors.append('Owned proxy process vẫn chạy trong desired stopped')
        metrics = self._metrics(state)
        self._cache_observation(processes=processes, metrics=metrics)
        return {'ready': not errors, 'desired_state': desired, 'errors': errors,
                'proxy_count': len(state['proxies']), 'service_count': sum(2 if p['protocol'] == 'dual' else 1 for p in state['proxies']),
                'instances_total': processes.get('expected', 0), 'instances_running': processes.get('instances', []),
                'processes': processes, 'system': {'uptime_minutes': round((time.time()-self.started_at)/60, 1)},
                'last_reconcile': state['last_reconcile'], 'metrics': metrics,
                'uncertain_addresses': state['uncertain_addresses'], 'startup_recovery': recovery,
                'progress': self._progress_snapshot(), 'observation': 'live'}

    def _metrics(self, state):
        worker = {'rss_bytes': None, 'fd_count': None}
        try:
            status = Path('/proc/self/status').read_text()
            worker['rss_bytes'] = next(int(line.split()[1])*1024 for line in status.splitlines() if line.startswith('VmRSS:'))
            worker['fd_count'] = len(list(Path('/proc/self/fd').iterdir()))
        except (OSError, ValueError, StopIteration):
            pass
        children = {'rss_bytes': None, 'fd_count': None, 'process_count': None, 'errors': ['Observation unavailable']}
        if hasattr(self.engine, 'process_metrics'):
            children = self.engine.process_metrics()
        ndp = {'neighbor_count': 0, 'states': {}, 'interfaces': {}, 'errors': []}
        for iface in sorted({p['interface'] for p in state['proxies']}):
            try:
                entry = self.net.observe_ndp(iface)
                ndp['interfaces'][iface] = entry
                if entry.get('neighbor_count') is None:
                    raise OperationError('NDP observation unavailable')
                ndp['neighbor_count'] += entry['neighbor_count']
                for name, count in entry['states'].items():
                    ndp['states'][name] = ndp['states'].get(name, 0) + count
            except (AttributeError, OSError, ValueError, RuntimeError):
                ndp['errors'].append(f'{iface}: observation unavailable')
        if ndp['errors']:
            ndp['neighbor_count'] = None
        return {'worker': worker, 'proxy_children': children, 'ndp': ndp,
                'resources': self._resource_observation(state, children)}

    def _resource_observation(self, state, children=None):
        # The sampler reads a bounded /proc/cgroup snapshot at most every five
        # seconds. Cached status does not run engine/NIC inspection commands.
        resources = self.metrics_sampler.collect(proxies=state['proxies'], engine_metrics=children,
                                                configured_limit=state['settings'].get('thread_limit', 4096))
        controller = {'available': False, 'effective_limit': None}
        if hasattr(self.host_control, 'status'):
            try:
                controller = self.host_control.status()
            except (AttributeError, OSError, RuntimeError, ValueError):
                controller['error'] = 'Host PID controller observation unavailable'
        resources['host_control'] = controller
        return resources

    @staticmethod
    def _uncertain_stages(pending):
        return [{**r, 'operation_id': pending['id']} for r in pending.get('staged', [])
                if r.get('creation') in {'attempting', 'unknown'}]

    def resolve_uncertain(self, params):
        # Explicit acknowledgement discards only an uncertain intent; it never touches the NIC.
        if set(params) != {'operation_id', 'address', 'interface', 'acknowledge_unmanaged'} or params['acknowledge_unmanaged'] is not True:
            raise ValidationError('Cần xác nhận acknowledge_unmanaged=true và operation_id/address/interface')
        state = self.store.read()
        if state['pending_operation']:
            raise OperationError('Chờ runtime recovery trước ownership review')
        address = str(ipaddress.IPv6Address(params['address']))
        iface = interface(params['interface'])
        matching = [r for r in state['uncertain_addresses'] if r['operation_id'] == params['operation_id']
                    and r['address'] == address and r['interface'] == iface]
        if len(matching) != 1:
            raise ValidationError('Uncertain record không tồn tại hoặc không duy nhất')
        state['uncertain_addresses'].remove(matching[0])
        self.store.event(state, 'ownership.review', 'left_unmanaged')
        self.store.write(state)
        return {'success': True, 'address': address, 'interface': iface, 'nic_changed': False}

    def export(self, params):
        state = self.store.read()
        fmt = params.get('format', 'ip_port')
        protocol_filter = params.get('export_protocol', 'all')
        if fmt not in ('ip_port', 'ip_port_user_pass', 'user_pass_ip_port', 'full_url') or protocol_filter not in ('all', 'http', 'socks5'):
            raise ValidationError('Export format/protocol không hợp lệ')
        host = state['settings']['listener_ipv4']
        if host == '0.0.0.0':
            rows = self._refresh_inventory(state)
            try:
                host = network_inventory.export_host(host, rows, state['settings']['interface'])
            except ValueError as exc:
                raise ValidationError(str(exc)) from None
        user = state['users'][0] if state['users'] and state['settings']['auth_type'] == 'userpass' else None
        lines = []
        for p in state['proxies']:
            endpoints = [('http', p['port']), ('socks5', p['socks_port'])] if p['protocol'] == 'dual' else [(p['protocol'], p['port'])]
            for proto, port in endpoints:
                if protocol_filter not in ('all', proto):
                    continue
                if fmt == 'full_url':
                    from urllib.parse import quote
                    auth = f"{quote(user['username'], safe='')}:{quote(user['password'], safe='')}@" if user else ''
                    line = f'{proto}://{auth}{host}:{port}'
                elif fmt == 'ip_port_user_pass' and user:
                    line = f"{host}:{port}:{user['username']}:{user['password']}"
                elif fmt == 'user_pass_ip_port' and user:
                    line = f"{user['username']}:{user['password']}@{host}:{port}"
                else:
                    line = f'{host}:{port}'
                lines.append(line)
        return {'success': True, 'content': '\n'.join(lines), 'count': len(lines)}

    def logs(self, params):
        count = integer(params.get('lines', 100), 'lines', 1, 1000)
        import collections
        result = []
        for path in sorted((self.store.path / 'logs').glob('3proxy_*.log*'))[-32:]:
            if path.is_file() and not path.is_symlink():
                with path.open(encoding='utf-8', errors='replace') as f:
                    tail = collections.deque(f, maxlen=count)
                result.append(f'[{path.name}]\n' + ''.join(tail))
        return {'logs': '\n'.join(result)[-256000:] or 'No log file found.'}

    def _test_one(self, proxy, settings, users, url):
        proto = 'http' if proxy['protocol'] == 'dual' else proxy['protocol']
        url_proto = 'socks5h' if proto == 'socks5' else 'http'
        config = ''
        if settings['auth_type'] == 'userpass' and users:
            u = users[0]
            credential(u['username'], u['password'])
            config = f'proxy-user = "{u["username"]}:{u["password"]}"\n'
        cmd = ['curl', '--disable', '--silent', '--show-error', '--output', os.devnull, '--config', '-',
               '--proxy', f'{url_proto}://127.0.0.1:{proxy["port"]}', '--noproxy', '',
               '--proto', '=https', '--connect-timeout', str(settings['timeout_connect']),
               '--max-time', '30', '--write-out',
               '{"dns_lookup":%{time_namelookup},"tcp_connect":%{time_connect},'
               '"tls_handshake":%{time_appconnect},"total_time":%{time_total},'
               '"ttfb":%{time_starttransfer},"http_code":"%{http_code}",'
               '"speed_download":%{speed_download},"size_download":%{size_download},'
               '"remote_ip":"%{remote_ip}"}',
               '--url', url]
        # A specific LAN listener may not accept loopback; use the configured address, never a caller's host.
        if settings['listener_ipv4'] not in ('0.0.0.0', '127.0.0.1'):
            cmd[cmd.index('--proxy')+1] = f'{url_proto}://{settings["listener_ipv4"]}:{proxy["port"]}'
        try:
            result = subprocess.run(cmd, input=config, capture_output=True, text=True, timeout=35)
            data = json.loads(result.stdout) if result.stdout else {}
            if not isinstance(data, dict):
                raise ValueError('Invalid curl metrics')
            for field in ('dns_lookup', 'tcp_connect', 'tls_handshake', 'total_time', 'ttfb',
                          'speed_download', 'size_download'):
                value = float(data.get(field, 0))
                if not math.isfinite(value) or value < 0:
                    raise ValueError('Invalid curl metric')
                data[field] = value
            code = int(data.get('http_code', 0))
            data.update(success=result.returncode == 0 and 200 <= code < 400, port=proxy['port'], ipv6=proxy['ipv6'], proxy_id=proxy['id'])
            data['speed_bytes_per_second'] = data['speed_download']
            data['speed_kbps'] = round(data['speed_download']/1024, 2)  # Legacy API: KiB/s, not kbit/s.
            data['speed_mbps'] = round(data['speed_download'] * 8 / 1_000_000, 3)
            data['download_bytes'] = data['size_download']
            # With --proxy, curl's remote_ip is its immediate proxy peer, not
            # the destination nor proof of the source IPv6 used by that proxy.
            data['remote_ip'] = str(ipaddress.ip_address(data['remote_ip'])) if data.get('remote_ip') else ''
            data['proxy_peer_ip'] = data['remote_ip']
            data['remote_ip_role'] = 'proxy_peer'
            data['timing_scope'] = 'curl_via_proxy'
            from urllib.parse import urlsplit
            data['target_host'] = urlsplit(url).hostname
            data['transfer_rate_scope'] = 'sample_response'
            if not data['success']:
                data['error'] = 'Proxy transport/auth/DNS/target failed'
            return data
        except (OSError, subprocess.TimeoutExpired, ValueError, TypeError):
            return {'success': False, 'port': proxy['port'], 'proxy_id': proxy['id'], 'error': 'Proxy probe failed'}

    def speedtest(self, params):
        state = self.store.read()
        if params.get('proxy_host', '127.0.0.1') not in ('127.0.0.1', 'localhost', '::1'):
            raise ValidationError('Chỉ test proxy do manager quản lý')
        identifier, port = params.get('proxy_id'), params.get('proxy_port')
        proxy = next((p for p in state['proxies'] if (p['id'] == identifier if identifier is not None else p['port'] == port)), None)
        if not proxy:
            raise ValidationError('Proxy ID/port chưa được quản lý')
        url = target_url(params.get('target_url', 'https://www.bing.com'))
        return self._test_one(proxy, state['settings'], state['users'], url)

    def speedtest_batch(self, params):
        state = self.store.read()
        limit = integer(params.get('max_test', 10), 'max_test', 1, min(200, max(1, len(state['proxies']))))
        url = target_url(params.get('target_url', 'https://www.bing.com'))
        import concurrent.futures
        def perform(p):
            self._checkpoint()
            return self._test_one(p, state['settings'], state['users'], url)
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            results = list(pool.map(perform, state['proxies'][:limit]))
        good = [r for r in results if r['success']]
        return {'success': True, 'results': results, 'total_tested': len(results), 'total_success': len(good),
                'total_failed': len(results)-len(good), 'avg_total_time': sum(float(r.get('total_time', 0)) for r in good)/max(1, len(good)),
                'avg_ttfb': sum(float(r.get('ttfb', 0)) for r in good)/max(1, len(good)), 'target_url': url}

    def auto_optimize(self, params):
        state = self.store.read()
        if not self.engine.running_instances().get('ready'):
            raise OperationError('Proxy chưa ready; sửa transport trước khi optimize')
        bad = []
        # Two independent source-egress failures identify broken addresses, not just one slow target.
        for p in state['proxies']:
            failures = 0
            for _ in range(2):
                self._checkpoint()
                if not self.net.probe_ipv6_egress(p['ipv6'], p['interface'], target_url=state['settings']['probe_url'], expected_address=p['ipv6']).get('success'):
                    failures += 1
            if failures == 2:
                bad.append(p['id'])
        if not bad:
            return {'success': True, 'replaced': 0, 'total': len(state['proxies']), 'message': 'Tất cả source IPv6 đã qua egress probe'}
        added = self._replacement(state, set(bad))
        return {**self._transaction(state, added, 'proxies.optimize'), 'replaced': len(added), 'total': len(state['proxies']),
                'message': 'Đã thay địa chỉ lỗi qua transaction; tốc độ target không phải bằng chứng IP lỗi'}

    def telegram_config(self, params):
        settings = self.store.read()['settings']
        return {'token': settings.get('telegram_bot_token', ''), 'chat_id': settings.get('telegram_chat_id', ''),
                'allowed_user_ids': settings.get('telegram_allowed_user_ids', [])}

    def telegram_test(self, params):
        config = self.telegram_config({})
        if not config['token'] or not config['chat_id']:
            raise ValidationError('Telegram chưa được cấu hình')
        import requests
        try:
            response = requests.post(f"https://api.telegram.org/bot{config['token']}/sendMessage",
                                     json={'chat_id': config['chat_id'], 'text': 'IPv6 Proxy Manager: test notification'}, timeout=10)
            response.raise_for_status()
            if not response.json().get('ok'):
                raise OperationError('Telegram API rejected message')
        except Exception as exc:
            raise OperationError('Telegram test failed; kiểm tra cấu hình/kết nối') from exc
        return {'success': True}

    def events(self, params):
        return {'events': self.store.read()['events'][-100:]}

    def _startup_status(self, state):
        if not state['settings']['startup_rebuild_enabled']:
            return {'state': 'disabled', 'message': 'Tự tạo lại khi khởi động đang tắt'}
        if state['manual_stop']:
            return {**(state.get('startup_recovery') or {}), 'state': 'stopped',
                    'message': 'Đã dừng thủ công; nhấn Start để tiếp tục'}
        return state.get('startup_recovery') or {'state': 'ready', 'phase': 'done',
                    'target_count': state['settings']['startup_proxy_count'],
                    'message': 'Cấu hình sẽ áp dụng khi worker khởi động lại'}

    def _recovery_status_snapshot(self, state):
        settings = state['settings']
        processes, metrics = self._cached_observation()
        metrics['resources'] = self._resource_observation(state, metrics.get('proxy_children'))
        progress = self._progress_snapshot()
        observation = 'cached_during_mutation' if progress['active'] or self._recovery_active(state) else 'cached'
        return {'proxy_running': processes.get('ready'), 'proxy_pid': None, 'total_proxies': len(state['proxies']),
            'total_users': len(state['users']), 'desired_state': state['desired_state'],
            'desired_running': state['desired_state'] == 'running',
            'subnet': settings['subnet'], 'interface': settings['interface'], 'auth_type': settings['auth_type'],
            'protocol': settings['protocol'], 'rotation_enabled': settings['rotation_enabled'],
            'rotation_interval': settings['rotation_interval'], 'last_error': state['last_error'] or self.health_error,
            'revision': state['revision'], 'operation_pending': bool(state['pending_operation']),
            'uncertain_addresses': state['uncertain_addresses'], 'startup_recovery': self._startup_status(state),
            'progress': progress, 'processes': processes, 'metrics': metrics,
            'observation': observation, **self._source_snapshot(state)}

    def _recovery_health_snapshot(self, state):
        recovery = self._startup_status(state)
        processes, metrics = self._cached_observation()
        metrics['resources'] = self._resource_observation(state, metrics.get('proxy_children'))
        progress = self._progress_snapshot()
        error = state['last_error'] or (recovery.get('message') if self._recovery_active(state) else
                                       'Operation đang xử lý; health chi tiết chờ mutation hoàn tất')
        return {'ready': False, 'desired_state': state['desired_state'],
            'errors': [error], 'startup_recovery': recovery,
            'proxy_count': len(state['proxies']),
            'service_count': sum(2 if p['protocol']=='dual' else 1 for p in state['proxies']),
            'instances_total': processes.get('expected'), 'instances_running': processes.get('instances', []),
            'processes': {**processes, 'observation': 'cached_during_mutation'},
            'metrics': {**metrics, 'observation': 'cached_during_mutation'},
            'system': {'uptime_minutes': round((time.time()-self.started_at)/60,1)},
            'last_reconcile': state['last_reconcile'], 'uncertain_addresses': state['uncertain_addresses'],
            'progress': progress, 'observation': 'cached_during_mutation'}

    @staticmethod
    def _recovery_active(state):
        return (state['settings']['startup_rebuild_enabled'] and not state['manual_stop'] and
                (state.get('startup_recovery') or {}).get('phase') not in {None, 'done'})

    def _commit_recovery_edit(self, state, action):
        # Credential/settings corrections during boot must not start stale old listeners.
        state['last_error'] = ''
        self.store.event(state, action, 'updated_without_activation')
        committed = self.store.write(state)
        self.health_error = ''
        return {'success': True, 'queued': True, 'revision': committed['revision']}

    def _queue_startup_rebuild(self, state):
        state['manual_stop'], state['desired_state'] = False, 'running'
        state['startup_recovery'] = {'state': 'waiting', 'phase': 'waiting_network',
            'target_count': state['settings']['startup_proxy_count'],
            'previous_addresses': [r['address'] for r in state['managed_addresses']],
            'message': 'Đang chờ IPv6 gốc/router sẵn sàng để tạo lại proxy'}
        state['prefix_state'].pop(state['settings']['interface'], None)
        self.store.event(state, 'startup.rebuild', 'queued')
        self.store.write(state)
        self.startup_pending = False
        return {'success': True, 'queued': True, 'message': state['startup_recovery']['message']}

    def _forget_absent_uncertain(self, state):
        """A cold reboot loses NIC aliases. Absence resolves intent, not ownership."""
        snapshots = {}
        kept = []
        for record in state['uncertain_addresses']:
            self._checkpoint()
            iface = record['interface']
            if iface not in snapshots:
                snapshots[iface] = self.net.get_ipv6_addresses(iface, strict=True)
            # Any same-address presence is ambiguous, even with a different prefix length.
            if any(str(ipaddress.IPv6Address(row['address'])) ==
                   str(ipaddress.IPv6Address(record['address'])) for row in snapshots[iface]):
                kept.append(record)
        if len(kept) != len(state['uncertain_addresses']):
            state['uncertain_addresses'] = kept
            self.store.event(state, 'startup.ownership', 'absent_intents_cleared')
            return self.store.write(state)
        return state

    def _startup_plan(self, state, count):
        """Validate authentication, ports and full resource budget before deleting."""
        settings = state['settings']
        if settings['topology_mode'] != 'lan':
            raise ValidationError('Tự tìm IPv6 gốc khi khởi động yêu cầu topology LAN')
        integer(count, 'startup_proxy_count', 1, int(os.environ.get('MAX_PROXY_SERVICES', '1024')))
        ports = self._ports([], count, settings['start_port'], settings['protocol'], 10000)
        provisional = [{'id': i+1, 'ipv6': f'2001:db8::{i+1:x}', 'port': pair[0],
            'protocol': settings['protocol'], 'interface': settings['interface'],
            'prefix_len': settings['prefix_len'], 'address_prefix_len': 128,
            'topology_mode': 'lan', 'routed_prefix': '',
            **({'socks_port': pair[1]} if len(pair) > 1 else {})} for i, pair in enumerate(ports)]
        proposed = copy.deepcopy(state)
        proposed['proxies'] = provisional
        self._validate(proposed)

    def _rebuild_startup(self, state):
        with self._progress_operation('waiting_network', state['settings']['startup_proxy_count']):
            return self._rebuild_startup_body(state)

    def _rebuild_startup_body(self, state):
        """Durable delete-then-create state machine; never roll back to removed IPs."""
        recovery = state['startup_recovery']
        count = state['settings']['startup_proxy_count']
        self._progress_update(stage='waiting_network', total=count)
        self._startup_plan(state, count)
        self._checkpoint()
        ok, message = self.engine.stop_3proxy()
        if not ok:
            raise OperationError(message)
        self._cache_observation(processes=self.engine.running_instances())
        self._checkpoint()
        selected = self.net.select_current_lan_prefix(state['settings']['interface'],
            managed_addresses=state['managed_addresses'] + state['uncertain_addresses'],
            target_url=state['settings']['probe_url'], timeout=state['settings']['probe_timeout'],
            checkpoint=self._checkpoint)
        self._remember_source(selected)
        self._checkpoint()
        state = self._forget_absent_uncertain(self.store.read())
        if state['uncertain_addresses']:
            raise OperationError('IPv6 chưa rõ ownership vẫn tồn tại; đang chờ xác minh')
        recovery = state['startup_recovery']
        current = self.net.get_ipv6_addresses(selected['interface'], strict=True)
        # Read-only sampling proves there is enough room for an entirely fresh
        # set before old aliases are deleted, including narrow LAN pools.
        self.net.generate_random_ipv6(selected['subnet'], selected['prefix_len'], count,
            exclude_addresses=[r['address'] for r in current] + recovery.get('previous_addresses', []))
        self._checkpoint()
        recovery.update(state='rebuilding', phase='cleaning', target_count=count,
            base_ipv6=selected['address'], subnet=selected['subnet'], prefix_len=selected['prefix_len'],
            message='Đã xác minh IPv6 gốc; đang dọn toàn bộ IPv6 do tool tạo')
        self._progress_update(stage='cleaning', total=count)
        state['settings'].update(subnet=selected['subnet'], prefix_len=selected['prefix_len'])
        state['prefix_state'][selected['interface']] = selected
        # Stop is persisted concurrently outside self.lock. Never overwrite its intent.
        self._checkpoint()
        state['proxies'] = []
        for record in state['managed_addresses']:
            record['active'] = False
        state = self.store.write(state)
        self._checkpoint()
        # Replace even the persisted on-disk old listener config with an empty generation.
        self._activate(state)
        self._checkpoint()
        removed, failed = self._remove_owned(state['managed_addresses'], checkpoint=self._checkpoint)
        # The kernel delete acknowledgment is followed by fresh absence verification.
        snapshots = {}
        for row in removed:
            self._checkpoint()
            if row['interface'] not in snapshots:
                snapshots[row['interface']] = self.net.get_ipv6_addresses(row['interface'], strict=True)
            if any(str(ipaddress.IPv6Address(item['address'])) == row['address']
                   for item in snapshots[row['interface']]):
                failed.append(row)
        state['managed_addresses'] = failed
        state = self.store.write(state)
        self._checkpoint()
        if failed:
            raise OperationError('IPv6 cũ chưa dọn hết; giữ ledger và tự thử lại, chưa tạo proxy mới')
        self._checkpoint()
        recovery = state['startup_recovery']
        recovery.update(phase='generating', message=f'Đang tạo mới {count} proxy')
        state['last_error'] = ''
        state = self.store.write(state)
        self._checkpoint()
        # generate commits recovery=ready in the SAME snapshot as the fresh addresses.
        result = self.generate({'count': count, 'recreate': True, 'start': True})
        self.last_base_probe = self.last_probe = time.time()
        return result

    def _recover_pending(self, state):
        with self._progress_operation('rolling_back'):
            return self._recover_pending_body(state)

    def _recover_pending_body(self, state):
        pending = state['pending_operation']
        ok, message = self.engine.stop_3proxy()
        if not ok:
            raise OperationError('Pending rollback stop failed: ' + message)
        self._cache_observation(processes=self.engine.running_instances())
        self.engine.restore_configs(pending['configs'])
        _, failed = self._remove_owned(pending['added'])
        before = pending['before']
        # A later emergency Stop has precedence over the interrupted operation's snapshot.
        if state['desired_state'] == 'stopped':
            before['desired_state'] = 'stopped'
            before['manual_stop'] = state['manual_stop']
        before['managed_addresses'] += [{**r, 'active': False} for r in failed]
        before.setdefault('uncertain_addresses', []).extend(self._uncertain_stages(pending))
        before['pending_operation'] = None
        before['last_error'] = 'Recovered interrupted transaction' if failed else ''
        self.store.event(before, pending['action'], 'recovered_after_crash')
        self.store.write(before)

    def reconcile(self):
        with self.lock:
            return self._invoke(self._reconcile, {})

    def _reconcile(self, params):
        with self.lock:
            state = self.store.read()
            lan_interfaces = {p['interface'] for p in state['proxies'] if p['topology_mode'] == 'lan'}
            self.source_candidates = {iface: candidate for iface, candidate in self.source_candidates.items()
                                      if iface in lan_interfaces}
            if time.monotonic() - self.inventory_observed_at >= 15:
                self._refresh_inventory(state)
            if state['pending_operation']:
                self._recover_pending(state)
                state = self.store.read()
            if self.startup_pending:
                if state['settings']['startup_rebuild_enabled'] and not state['manual_stop']:
                    self._queue_startup_rebuild(state)
                    state = self.store.read()
                self.startup_pending = False
            if (state['settings']['startup_rebuild_enabled'] and not state['manual_stop'] and
                    (state.get('startup_recovery') or {}).get('phase') not in {None, 'done'}):
                self._rebuild_startup(state)
                self.health_error = ''
                return
            self.cleanup({})
            state = self.store.read()
            if state['desired_state'] != 'running' or not state['proxies']:
                if self.engine.running_instances().get('running'):
                    ok, message = self.engine.stop_3proxy()
                    if not ok:
                        raise OperationError(message)
                    self._cache_observation(processes=self.engine.running_instances())
                return
            if state['uncertain_addresses']:
                raise OperationError('Ownership review đang chờ; reconciler không thay đổi IPv6/runtime')
            self._validate(state)
            # Detect LAN renumbering from OS address/route events, excluding our static aliases.
            if any(p['topology_mode'] == 'lan' for p in state['proxies']) and time.time()-self.last_base_probe >= state['settings']['source_poll_interval']:
                replacements = {}
                waiting = False
                for iface in {p['interface'] for p in state['proxies'] if p['topology_mode'] == 'lan'}:
                    expected = {ipaddress.IPv6Network(f"{p['subnet']}/{p['prefix_len']}", strict=False) for p in state['proxies'] if p['interface'] == iface and p['topology_mode'] == 'lan'}
                    try:
                        selected = self.net.select_current_lan_prefix(iface,
                            managed_addresses=state['managed_addresses'] + state['uncertain_addresses'],
                            target_url=state['settings']['probe_url'], timeout=state['settings']['probe_timeout'],
                            checkpoint=self._checkpoint, prefer_networks={str(n) for n in expected})
                    except Exception:
                        # Confirmations must be consecutive successful observations.
                        self.source_candidates.pop(iface, None)
                        with self.progress_lock:
                            self.source_cache = {**self.source_cache, 'source_verified': False,
                                                 'source_error': 'IPv6 nguồn chưa được xác minh.'}
                        raise
                    self._checkpoint()
                    if iface == state['settings']['interface']:
                        self._remember_source(selected)
                    net = ipaddress.IPv6Network(f"{selected['subnet']}/{selected['prefix_len']}", strict=False)
                    state['prefix_state'][iface] = selected
                    if not all(wanted.subnet_of(net) for wanted in expected):
                        # Suspend before any other interface probe can fail, and
                        # even when a single confirmation is configured.
                        ok, message = self.engine.stop_3proxy()
                        if not ok:
                            raise OperationError(message)
                        self._cache_observation(processes=self.engine.running_instances())
                        candidate = self.source_candidates.get(iface, {})
                        count = candidate.get('count', 0) + 1 if candidate.get('network') == str(net) else 1
                        self.source_candidates[iface] = {'network': str(net), 'count': count}
                        if count < state['settings']['source_change_confirmations']:
                            waiting = True
                        else:
                            replacements[iface] = (str(net.network_address), net.prefixlen)
                    else:
                        # Privacy/SLAAC address changes inside the same usable prefix
                        # are not a reason to destroy a working pool.
                        self.source_candidates.pop(iface, None)
                self.last_base_probe = time.time()
                if waiting:
                    ok, message = self.engine.stop_3proxy()
                    if not ok:
                        raise OperationError(message)
                    self._cache_observation(processes=self.engine.running_instances())
                    state['last_error'] = 'Đang xác nhận prefix IPv6 mới qua các vòng quan sát liên tiếp.'
                    self.store.write(state)
                    # In particular do not restore or restart aliases from the old prefix.
                    return
                if replacements:
                    added = self._replacement(state, {p['id'] for p in state['proxies'] if p['interface'] in replacements and p['topology_mode'] == 'lan'}, replacement_networks=replacements)
                    if state['settings']['topology_mode'] == 'lan' and state['settings']['interface'] in replacements:
                        state['settings']['subnet'], state['settings']['prefix_len'] = replacements[state['settings']['interface']]
                    self._transaction(state, added, 'prefix.renumber')
                    state = self.store.read()
                    for iface in replacements:
                        self.source_candidates.pop(iface, None)
            elif self.source_candidates:
                # A fast/manual reconcile inside the polling interval cannot
                # prematurely restart the pool suspended for confirmation.
                return
            # Existing aliases are checked by the representative group probes
            # below, not by a full Internet scan every reconciler tick. Missing
            # aliases still require DAD and source verification when restored.
            restored = self.net.restore_proxy_addresses(state['proxies'], state['settings'],
                                                       probe=True, probe_existing=False,
                                                       checkpoint=self._checkpoint)
            if restored.get('failed'):
                self.last_base_probe = 0
                raise OperationError('IPv6 restore chưa thành công; không restart-loop')
            if restored.get('restored') or not self.engine.running_instances().get('ready'):
                self._activate(state)
            if state['settings']['rotation_enabled'] and time.time() >= state['rotation_due']:
                self.rotate({})
                state = self.store.read()
            # Periodic representative DNS/source-egress probe per interface/prefix.
            if time.time()-self.last_probe >= 60:
                groups = {}
                for p in state['proxies']:
                    groups[(p['interface'], p['subnet'], p['prefix_len'])] = p
                for p in groups.values():
                    self._checkpoint()
                    result = self.net.probe_ipv6_egress(p['ipv6'], p['interface'], target_url=state['settings']['probe_url'], expected_address=p['ipv6'])
                    if not result.get('success'):
                        self.last_base_probe = 0
                        raise OperationError('Periodic DNS/source-egress probe failed')
                self.last_probe = time.time()
            state['last_reconcile'], state['last_error'] = time.time(), ''
            self.store.write(state)
            self.health_error = ''

    def run_reconciler(self):
        failures = 0
        while not self.stop_event.is_set():
            try:
                self.reconcile()
                failures = 0
            except Exception as exc:
                failures += 1
                with self.lock:
                    self.health_error = str(exc)
                    state = self.store.read()
                    state['last_error'] = type(exc).__name__ + ': ' + str(exc)
                    recovery = state.get('startup_recovery')
                    if recovery and recovery.get('phase') not in {None, 'done'} and not state['manual_stop']:
                        recovery.update(state='waiting' if recovery['phase'] == 'waiting_network' else 'error',
                                        message=state['last_error'])
                    self.store.event(state, 'reconcile', 'failed', type(exc).__name__)
                    self.store.write(state)
            state = self.store.read()
            recovering = (state['settings']['startup_rebuild_enabled'] and not state['manual_stop'] and
                          (state.get('startup_recovery') or {}).get('phase') not in {None, 'done'})
            self.stop_event.wait(min(30, 5 * 2**min(failures, 3)) if recovering else
                                 min(300, 10 * 2**min(failures, 5)) if failures else
                                 state['settings']['source_poll_interval'])
