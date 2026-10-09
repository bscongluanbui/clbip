'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');
const source = fs.readFileSync('static/app.js', 'utf8');

function fixture(responses = []) {
    const elements = new Map(), calls = [], urls = [], intervals = [];
    let init;
    function element(id) {
        if (!elements.has(id)) elements.set(id, {
            value: '', checked: false, disabled: false, textContent: '', innerHTML: '',
            style: {}, dataset: {}, attributes: {}, children: [],
            setAttribute(name, value) { this.attributes[name] = value; },
            classList: {add() {}, remove() {}}, addEventListener() {},
            appendChild(child) { this.children.push(child); if (child.selected || !this.value) this.value = child.value; },
            append() {}, focus() {}, querySelector() { return element('child-' + id); }
        });
        return elements.get(id);
    }
    const document = {
        getElementById: element,
        addEventListener(name, callback) { if (name === 'DOMContentLoaded') init = callback; },
        querySelectorAll() { return []; },
        querySelector(selector) { return element('query-' + selector); },
        createElement() { return element('created-' + elements.size); }
    };
    const context = vm.createContext({document, console, crypto, confirm: () => true,
        window: {location: {protocol: 'http:', port: '7070', assign(url) { urls.push(url); }}},
        setInterval(callback, period) { intervals.push({callback, period}); }, setTimeout() {}, clearInterval() {},
        fetch: async (url, options) => {
            calls.push({url, options});
            const response = responses.shift();
            if (!response) throw new Error('Unexpected fetch: ' + url);
            return {ok: response.status < 400, status: response.status, json: async () => response.data};
        }
    });
    vm.runInContext(source, context);
    context.showToast = () => {};
    return {context, element, calls, urls, intervals, init: () => init()};
}

(async () => {
    const progress = fixture();
    const marker = '<img src=x onerror="alert(1)">';
    progress.context.renderBuildProgress({progress: {stage: 'verifying', total: 200, added: 32, ready: 25,
        verified: 20, elapsed_seconds: 12.8, last_update: Date.now() / 1000 - 3, active: true,
        failed: 2, address: marker, last_error: marker}});
    assert.match(progress.element('build-progress-counts').textContent, /Alias: 32\/200 · DAD: 25\/200 · Egress: 20\/200/);
    assert.equal(progress.element('build-progress-fill').style.width, '10%');
    assert.equal(progress.element('build-progress-bar').attributes['aria-valuenow'], '10');
    assert.match(progress.element('build-progress-detail').textContent, /12s/);
    assert(progress.element('build-progress-detail').textContent.includes(marker));
    assert.equal(progress.element('build-progress-detail').innerHTML, '');
    assert.equal(progress.element('build-progress-panel').dataset.active, 'true');
    progress.context.renderBuildProgress({progress: {total: 1, verified: 50, elapsed_seconds: -5}});
    assert.equal(progress.element('build-progress-fill').style.width, '100%');
    console.log('PASS: real Alias/DAD/Egress counters, bounded progressbar and text-only error/heartbeat');

    const processStatus = fixture();
    processStatus.context.renderProcessStatus({proxy_running: true, observation: 'cached_during_mutation',
        progress: {active: true}, processes: {observed_at: Date.now() / 1000 - 12}});
    assert.match(processStatus.element('child-global-status').textContent, /Đang xử lý.*cache gần nhất: Online.*12s trước.*health xác minh/);
    assert(!processStatus.element('child-global-status').textContent.includes('tất cả instances ready'));
    assert.equal(processStatus.element('child-global-status').className, 'status-dot');
    assert.equal(processStatus.element('query-#stat-running .stat-value').textContent, 'Đang xử lý');
    assert.equal(processStatus.element('global-status').attributes['aria-busy'], 'true');
    processStatus.context.renderProcessStatus({proxy_running: true, observation: 'cached',
        processes: {observed_at: Date.now() / 1000 - 30}});
    assert.match(processStatus.element('child-global-status').textContent, /Online theo cache.*30s trước.*health xác minh/);
    assert.equal(processStatus.element('query-#stat-running .stat-value').textContent, 'Online (cache)');
    assert.equal(processStatus.element('query-#stat-running .stat-value').style.color, 'var(--warning)');
    processStatus.context.renderProcessStatus({proxy_running: null, observation: 'cached',
        processes: {observed_at: marker}});
    assert.equal(processStatus.element('query-#stat-running .stat-value').textContent, 'Chưa xác minh');
    assert.equal(processStatus.element('child-global-status').innerHTML, '');
    assert(!processStatus.element('child-global-status').textContent.includes(marker));
    processStatus.context.renderProcessStatus({proxy_running: null, observation: 'live'});
    assert.equal(processStatus.element('query-#stat-running .stat-value').textContent, 'Chưa xác minh');
    processStatus.context.renderProcessStatus({proxy_running: true, observation: 'cached',
        processes: {observed_at: Date.now() / 1000 + 1000}});
    assert.match(processStatus.element('child-global-status').textContent, /chưa có thời điểm quan sát/);
    processStatus.context.renderProcessStatus({proxy_running: false, observation: 'cached_during_mutation'});
    assert.equal(processStatus.element('query-#stat-running .stat-value').textContent, 'Đang xử lý');
    processStatus.context.renderProcessStatus({proxy_running: true, observation: 'live'});
    assert.equal(processStatus.element('query-#stat-running .stat-value').textContent, 'Online');
    assert.match(processStatus.element('child-global-status').textContent, /tất cả instances ready/);
    assert.equal(processStatus.element('child-global-status').style.background, '');
    assert.equal(processStatus.element('global-status').attributes['aria-busy'], 'false');
    console.log('PASS: cached/unknown/mutation process status never claims current listener readiness; live observation retains verified status');

    const network = fixture();
    network.context.renderNetworkStatus({current_source: {address: '2001:db8:1::1', prefix_len: 64, interface: 'eth0'}, source_verified: false});
    assert.match(network.element('current-source-status').textContent, /chưa xác minh Internet/);
    network.context.renderNetworkStatus({current_source: {address: marker, interface: marker}, source_verified: true, source_error: marker});
    assert.equal(network.element('current-source-status').innerHTML, '');
    network.context.renderDashboardHosts({dashboard_hosts: ['192.168.1.3', '100.100.10.20', '192.168.1.3', marker,
        '0.0.0.0', '999.1.1.1', '224.1.1.1']});
    const html = network.element('dashboard-access-urls').innerHTML;
    assert(html.includes('LAN: http://192.168.1.3:7070/'));
    assert(html.includes('Tailscale: http://100.100.10.20:7070/'));
    assert(!html.includes(marker));
    assert.equal((html.match(/<a /g) || []).length, 2);
    assert(html.includes('rel="noopener noreferrer"'));
    console.log('PASS: source observation is not Internet proof; access URLs filter non-addresses and deduplicate');

    const inventory = fixture([{status: 200, data: {interfaces: ['eth0', 'wlan0'], details: [
        {device: 'eth0', name: 'Ethernet', kind: 'ethernet', active: true, ipv4: ['192.168.1.3'],
            ipv6: [{address: '2001:db8:1::1', prefix_len: 64}],
            source_ipv6: [{address: '2001:db8:1::1', prefix_len: 64, origin: 'system'}],
            managed_ipv6_count: 0, uncertain_ipv6_count: 0, pool_capable: true},
        {device: 'wlan0', name: 'Wi-Fi', kind: 'wifi', active: false, ipv4: [], ipv6: [], pool_capable: false, reason: marker}
    ]}}]);
    inventory.context.detectSubnets = () => {};
    await inventory.context.loadInterfaces();
    assert.match(inventory.element('interface-detail').textContent, /Ethernet \(ethernet\)/);
    assert.match(inventory.element('interface-detail').textContent, /IPv4: 192\.168\.1\.3/);
    assert.match(inventory.element('interface-detail').textContent, /2001:db8:1::1\/64/);
    assert.match(inventory.element('interface-detail').textContent, /vẫn xác minh/);
    inventory.context.onInterfaceChange('wlan0');
    assert(inventory.element('interface-detail').textContent.includes(marker));
    assert.equal(inventory.element('interface-detail').innerHTML, '');
    console.log('PASS: legacy interface names coexist with real IPv4/IPv6/connection/capability details');

    const saved = fixture([{status: 200, data: {csrf_token: 'fixture-csrf'}}, {status: 200, data: {success: true}}]);
    saved.element('source-change-confirmations').value = '3';
    saved.element('source-poll-interval').value = '5';
    await saved.context.saveSourceChangeSettings();
    assert.deepEqual(JSON.parse(saved.calls[1].options.body), {source_change_confirmations: 3, source_poll_interval: 5});
    assert.equal(saved.element('btn-save-source-change').disabled, false);
    const bad = fixture();
    for (const [confirmations, interval] of [['0', '5'], ['1.5', '5'], ['2', '1'], ['2', '301']]) {
        bad.element('source-change-confirmations').value = confirmations;
        bad.element('source-poll-interval').value = interval;
        await bad.context.saveSourceChangeSettings();
    }
    assert.equal(bad.calls.length, 0);
    console.log('PASS: typed source confirmations/poll interval validated and saved independently');

    const defaults = fixture([{status: 200, data: {auth_type: 'none'}}]);
    await defaults.context.loadSettings();
    assert.equal(defaults.element('max-conn').value, 64);
    assert.equal(defaults.element('timeout-dns').value, 15);
    assert.equal(defaults.element('thread-limit').value, 4096);
    assert.equal(defaults.element('source-change-confirmations').value, 2);
    assert.equal(defaults.element('source-poll-interval').value, 5);
    console.log('PASS: maxconn64 and source-confirmation defaults load consistently');

    const resources = fixture();
    const resourceSample = {observation: 'live', observed_at: Date.now() / 1000 - 2,
        threads: {current: 3277, limit: 4096, events_max_delta: 0},
        worker: {fd_count: 21}, engine: {fd_count: 320, rss_bytes: 10485760},
        sockets: {established: 47, close_wait: 1670, states: {'TIME-WAIT': 2}},
        host_control: {available: true, effective_limit: 4096}};
    resources.context.renderResourceStatus({metrics: {resources: resourceSample}});
    assert.equal(resources.element('health-threads').textContent, '3277 / 4096');
    assert.equal(resources.element('health-thread-utilization').textContent, '80.0%');
    assert.equal(resources.element('health-thread-denied').textContent, '+0');
    assert.equal(resources.element('health-established').textContent, 47);
    assert.equal(resources.element('health-closewait').textContent, 1670);
    assert.equal(resources.element('health-fds').textContent, 'Worker 21 · 3proxy 320');
    assert.equal(resources.element('health-memory').textContent, '10.0 MiB');
    assert.match(resources.element('resource-warning').textContent, /CẢNH BÁO.*80%/);
    assert.match(resources.element('resource-warning').textContent, /không tự restart/);
    assert.match(resources.element('resource-observation').textContent, /trực tiếp.*2s trước/);
    assert.match(resources.element('thread-limit-runtime').textContent, /4096/);
    resources.context.renderResourceStatus({metrics: {resources: {...resourceSample,
        threads: {current: 3687, limit: 4096, events_max_delta: 0}}}});
    assert.match(resources.element('resource-warning').textContent, /NGHIÊM TRỌNG.*90%/);
    assert.equal(resources.element('health-threads').style.color, 'var(--danger)');
    resources.context.renderResourceStatus({metrics: {resources: {...resourceSample,
        threads: {current: 2, limit: 4096, events_max_delta: 3}}}});
    assert.equal(resources.element('health-thread-denied').textContent, '+3');
    assert.match(resources.element('resource-warning').textContent, /NGHIÊM TRỌNG/);
    assert.equal(resources.calls.length, 0);
    console.log('PASS: worker PID/thread pressure at 80/90 percent or new denials is text-visible with no auto mutation');

    resources.context.renderResourceStatus({metrics: {resources: {observation: 'cached', cached: true,
        observed_at: Date.now() / 1000 - 10, threads: {current: 0, limit: 4096, events_max_delta: null},
        sockets: {established: 0, close_wait: 0}, host_control: {available: false, error: marker},
        alerts: [{message: marker}]}}});
    assert.equal(resources.element('health-threads').textContent, '0 / 4096');
    assert.equal(resources.element('health-established').textContent, 0);
    assert.equal(resources.element('health-thread-denied').textContent, 'Chưa có mẫu so sánh');
    assert.match(resources.element('resource-observation').textContent, /cache.*10s trước/);
    assert(resources.element('resource-warning').textContent.includes(marker));
    assert(resources.element('thread-limit-runtime').textContent.includes(marker));
    assert.equal(resources.element('resource-warning').innerHTML, '');
    assert.equal(resources.element('thread-limit-runtime').innerHTML, '');
    resources.context.renderResourceStatus({metrics: {resources: {observation: 'unavailable',
        threads: {current: 999, limit: 4096, events_max_delta: 100}, sockets: {established: 99}}}});
    assert.equal(resources.element('health-threads').textContent, '— / —');
    assert.equal(resources.element('health-established').textContent, '—');
    assert.equal(resources.element('health-closewait').textContent, '—');
    assert.equal(resources.element('health-thread-utilization').textContent, 'Chưa quan sát');
    assert.equal(resources.element('health-memory').textContent, 'Chưa quan sát');
    resources.context.renderResourceStatus({metrics: {resources: {threads: {current: '20', limit: Infinity,
        utilization_percent: marker, events_max_delta: -1}, worker: {fd_count: marker}, engine: {rss_bytes: null}}}});
    assert.equal(resources.element('health-threads').textContent, '— / —');
    assert.equal(resources.element('health-memory').textContent, 'Chưa quan sát');
    assert(!resources.element('health-thread-utilization').textContent.includes(marker));
    assert.match(resources.element('thread-limit-runtime').textContent, /Chưa có quan sát/);
    assert.equal(resources.calls.length, 0);
    console.log('PASS: resource nulls, unavailable/cached samples and untrusted errors never appear as zero or injected HTML');

    const threadSave = fixture([{status: 200, data: {csrf_token: 'fixture-csrf'}},
        {status: 200, data: {success: true, changed: true, restarted: false,
            thread_limit_applied: true, effective_thread_limit: 4096, settings: {thread_limit: 4096}}}]);
    threadSave.element('thread-limit').value = '4096';
    threadSave.element('max-conn').value = '9999';
    threadSave.element('timeout-idle').value = '600';
    await threadSave.context.saveThreadLimitSettings();
    assert.deepEqual(threadSave.calls.map(call => call.url), ['/api/csrf', '/api/settings']);
    assert.deepEqual(JSON.parse(threadSave.calls[1].options.body), {thread_limit: 4096});
    assert.match(threadSave.element('thread-limit-save-status').textContent, /xác minh.*4096.*không restart/);
    assert.equal(threadSave.element('btn-save-thread-limit').disabled, false);
    const threadBad = fixture();
    for (const value of ['', '255', '16385', '4096.5', marker, 'Infinity']) {
        threadBad.element('thread-limit').value = value;
        await threadBad.context.saveThreadLimitSettings();
    }
    assert.equal(threadBad.calls.length, 0);
    assert.match(threadBad.element('thread-limit-save-status').textContent, /256\.\.16384/);
    console.log('PASS: independent integer thread_limit patch never submits maxconn/timeouts or pool changes');

    const threadUnchanged = fixture([{status: 200, data: {csrf_token: 'fixture-csrf'}},
        {status: 200, data: {success: true, changed: false, restarted: false, settings: {thread_limit: 4096}}}]);
    threadUnchanged.element('thread-limit').value = '4096';
    threadUnchanged.context.renderResourceStatus({metrics: {resources: {observation: 'live',
        threads: {current: 1500, limit: 1829, configured_limit: 4096, requested_limit: 4096},
        host_control: {available: true, effective_limit: 1829}}}});
    const observedRuntime = threadUnchanged.element('thread-limit-runtime').textContent;
    await threadUnchanged.context.saveThreadLimitSettings();
    assert.deepEqual(threadUnchanged.calls.map(call => call.url), ['/api/csrf', '/api/settings']);
    assert.deepEqual(JSON.parse(threadUnchanged.calls[1].options.body), {thread_limit: 4096});
    assert.match(threadUnchanged.element('thread-limit-save-status').textContent, /không thay đổi.*4096.*trần thực tế xem telemetry/);
    assert(!threadUnchanged.element('thread-limit-save-status').textContent.includes('Đã lưu và xác minh'));
    assert.equal(threadUnchanged.element('health-threads').textContent, '1500 / 1829');
    assert.equal(threadUnchanged.element('thread-limit').value, '4096');
    assert.equal(threadUnchanged.element('thread-limit-runtime').textContent, observedRuntime);
    assert.equal(threadUnchanged.element('btn-save-thread-limit').disabled, false);
    assert.equal(vm.runInContext('statusNextPollAt', threadUnchanged.context), 0);
    console.log('PASS: unchanged thread save preserves observed effective limit and schedules telemetry without claiming live application');

    const threadPending = fixture([{status: 200, data: {csrf_token: 'fixture-csrf'}},
        {status: 200, data: {success: true, restarted: false, thread_limit_applied: false,
            host_control: {available: false, error: marker}}}]);
    threadPending.element('thread-limit').value = '4096';
    await threadPending.context.saveThreadLimitSettings();
    assert.match(threadPending.element('thread-limit-save-status').textContent, /chưa xác minh áp dụng runtime/);
    assert(threadPending.element('thread-limit-runtime').textContent.includes(marker));
    assert.equal(threadPending.element('thread-limit-runtime').innerHTML, '');
    const threadFailure = fixture([{status: 200, data: {csrf_token: 'fixture-csrf'}},
        {status: 409, data: {success: false, error: marker}}]);
    threadFailure.element('thread-limit').value = '256';
    await threadFailure.context.saveThreadLimitSettings();
    assert(threadFailure.element('thread-limit-save-status').textContent.includes(marker));
    assert.equal(threadFailure.element('thread-limit-save-status').innerHTML, '');
    assert.equal(threadFailure.element('btn-save-thread-limit').disabled, false);
    const threadOverlap = fixture();
    let resolveThread;
    threadOverlap.context.api = async () => await new Promise(resolve => { resolveThread = resolve; });
    threadOverlap.element('thread-limit').value = '4096';
    const savingThread = threadOverlap.context.saveThreadLimitSettings();
    assert.equal(threadOverlap.element('btn-save-thread-limit').disabled, true);
    await threadOverlap.context.saveThreadLimitSettings();
    resolveThread({success: true, restarted: false, thread_limit_applied: true, effective_thread_limit: 4096});
    await savingThread;
    assert.equal(threadOverlap.element('btn-save-thread-limit').disabled, false);
    console.log('PASS: thread save verifies actual application, surfaces host/errors as text, and blocks overlapping requests');

    const password = fixture([{status: 200, data: {csrf_token: 'fixture-csrf'}},
        {status: 200, data: {success: true, changed: true, requires_login: true}}]);
    password.element('dashboard-current-password').value = 'Current-fixture-password';
    password.element('dashboard-new-password').value = '  New-fixture-password  ';
    password.element('dashboard-confirm-password').value = '  New-fixture-password  ';
    await password.context.changeDashboardPassword();
    assert.deepEqual(password.calls.map(call => call.url), ['/api/csrf', '/api/password']);
    assert.deepEqual(JSON.parse(password.calls[1].options.body), {current_password: 'Current-fixture-password',
        new_password: '  New-fixture-password  ', confirm_password: '  New-fixture-password  '});
    assert.deepEqual(password.urls, ['/login?password_changed=1']);
    assert.equal(password.element('dashboard-new-password').value, '');
    assert.equal(password.element('btn-change-dashboard-password').disabled, false);
    console.log('PASS: dashboard password preserves exact input, clears fields and redirects without pool mutations');

    const invalidPassword = fixture();
    invalidPassword.element('dashboard-current-password').value = 'old-fixture-password';
    invalidPassword.element('dashboard-new-password').value = 'short';
    invalidPassword.element('dashboard-confirm-password').value = 'different';
    await invalidPassword.context.changeDashboardPassword();
    assert.equal(invalidPassword.calls.length, 0);
    const failedPassword = fixture([{status: 200, data: {csrf_token: 'fixture-csrf'}},
        {status: 403, data: {success: false, error: marker}}]);
    failedPassword.element('dashboard-current-password').value = 'old-fixture-password';
    failedPassword.element('dashboard-new-password').value = 'new-fixture-password';
    failedPassword.element('dashboard-confirm-password').value = 'new-fixture-password';
    await failedPassword.context.changeDashboardPassword();
    assert.equal(failedPassword.urls.length, 0);
    assert(failedPassword.element('dashboard-password-status').textContent.includes(marker));
    assert.equal(failedPassword.element('dashboard-password-status').innerHTML, '');
    assert.equal(failedPassword.element('btn-change-dashboard-password').disabled, false);
    console.log('PASS: invalid/failed password changes neither navigate nor inject server errors');

    for (const value of ['1', ' ', 'x'.repeat(257), 'Mật', '']) {
        const simple = fixture([{status: 200, data: {csrf_token: 'fixture-csrf'}},
            {status: 200, data: {success: true, changed: true, requires_login: true}}]);
        simple.element('dashboard-current-password').value = '';
        simple.element('dashboard-new-password').value = value;
        simple.element('dashboard-confirm-password').value = value;
        await simple.context.changeDashboardPassword();
        assert.equal(JSON.parse(simple.calls[1].options.body).new_password, value);
        assert.deepEqual(simple.urls, [value === '' ? '/' : '/login?password_changed=1']);
    }
    const unchangedPassword = fixture([{status: 200, data: {csrf_token: 'fixture-csrf'}},
        {status: 200, data: {success: true, changed: false, requires_login: false, unchanged: true}}]);
    unchangedPassword.element('dashboard-current-password').value = '1';
    unchangedPassword.element('dashboard-new-password').value = '1';
    unchangedPassword.element('dashboard-confirm-password').value = '1';
    await unchangedPassword.context.changeDashboardPassword();
    assert.equal(unchangedPassword.urls.length, 0);
    assert.match(unchangedPassword.element('dashboard-password-status').textContent, /giữ nguyên/);
    console.log('PASS: optional/simple/Unicode/whitespace/long passwords pass exactly; empty disables login and unchanged is idempotent');

    const polls = fixture();
    let release;
    let statusCalls = 0, healthCalls = 0;
    polls.context.api = async url => {
        if (url === '/api/status') {
            statusCalls++;
            await new Promise(resolve => { release = resolve; });
            return {proxy_running: false, total_proxies: 0, progress: {active: true}};
        }
        healthCalls++;
        return {};
    };
    polls.context.syncCompletedStartupRecovery = async () => {};
    const first = polls.context.refreshStatus(false);
    await polls.context.refreshStatus(false);
    assert.equal(statusCalls, 1);
    release();
    await first;
    assert.equal(healthCalls, 0);
    polls.context.loadSettings = async () => {};
    polls.context.loadInterfaces = async () => {};
    polls.context.loadProxies = async () => {};
    polls.context.loadUsers = () => {};
    polls.context.refreshStatus = () => {};
    await polls.init();
    assert(polls.intervals.some(timer => timer.period === 2000));
    assert(polls.intervals.some(timer => timer.period === 15000));
    console.log('PASS: cheap progress polls never overlap and run independently of heavy health checks');

    const stop = fixture([{status: 200, data: {csrf_token: 'fixture-csrf'}},
        {status: 200, data: {success: true, message: 'Stopped'}}]);
    stop.context.refreshStatus = () => {};
    await stop.context.stopProxy();
    assert.deepEqual(stop.calls.map(call => call.url), ['/api/csrf', '/api/proxy/stop']);
    assert.match(stop.element('status-message').textContent, /Stop/);
    console.log('PASS: Stop remains a separate immediately dispatched request during pool builds');

    const template = fs.readFileSync('templates/index.html', 'utf8');
    assert(template.includes('id="max-conn" value="64"'));
    assert(template.includes('id="thread-limit" value="4096" min="256" max="16384" step="1"'));
    assert(template.includes('id="thread-limit-save-status" class="network-detail" role="status" aria-live="polite"'));
    assert(template.includes('id="resource-warning" class="network-detail" role="status" aria-live="polite"'));
    assert(template.includes('id="build-progress-bar" role="progressbar"'));
    assert(template.includes('id="dashboard-password-status" role="status" aria-live="polite"'));
    for (const id of ['dashboard-current-password', 'dashboard-new-password', 'dashboard-confirm-password']) {
        const input = template.match(new RegExp(`<input[^>]*id="${id}"[^>]*>`))[0];
        assert(!/(?:minlength|maxlength|required)=/.test(input));
    }
    assert(!/\son(?:click|change|input)=/i.test(template));
    const ids = [...template.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
    assert.equal(new Set(ids).size, ids.length);
    console.log('PASS: new controls are accessible, unique, handler-free and retain existing UI');
})().catch(error => { console.error(error); process.exitCode = 1; });
