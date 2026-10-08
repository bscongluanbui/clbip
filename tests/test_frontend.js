'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');
const source = fs.readFileSync('static/app.js', 'utf8');

function fixture(responses = []) {
    const elements = new Map(), calls = [], toasts = [];
    let init;
    function element(id) {
        if (!elements.has(id)) elements.set(id, {
            value: '', checked: false, innerHTML: '', textContent: '', style: {},
            classList: { add() {}, remove() {} }, addEventListener() {}, append() {},
            appendChild() {}, focus() {}, querySelector() { return element('child'); }
        });
        return elements.get(id);
    }
    const document = {
        addEventListener(event, callback) { if (event === 'DOMContentLoaded') init = callback; },
        getElementById: element, querySelectorAll() { return []; },
        querySelector(selector) { return {value: selector.includes('netmask') ? '64' : 'http'}; },
        createElement() { return element('new-' + elements.size); }
    };
    const context = vm.createContext({document, console, crypto, confirm: () => true,
        setTimeout() {}, setInterval() {}, clearInterval() {},
        fetch: async (url, options) => {
            calls.push({url, options});
            const response = responses.shift();
            if (!response) throw new Error('Unexpected fetch: ' + url);
            return {ok: response.status < 400, status: response.status, json: async () => response.data};
        }
    });
    vm.runInContext(source, context);
    context.showToast = (message, type) => toasts.push({message, type});
    context.refreshStatus = () => {};
    context.loadProxies = () => {};
    const values = {'ipv6-subnet': '2001:db8:1::', 'proxy-count': '5', 'start-port': '10000',
        'interface-select': 'eth0', 'rotation-interval': '10', 'auth-user': 'fixture',
        'auth-pass': 'fixture', 'topology-mode': 'lan', 'listener-ipv4': '127.0.0.1',
        'probe-url': 'https://api64.ipify.org', 'max-conn': '256'};
    for (const [id, value] of Object.entries(values)) element(id).value = value;
    return {context, calls, toasts, element, init: () => init()};
}

(async () => {
    const xss = fixture();
    const marker = '<img src=x onerror="alert(1)">';
    xss.context.renderUserList([{username: marker, created_at: marker}]);
    assert(!xss.element('user-list').innerHTML.includes(marker));
    assert(xss.element('user-list').innerHTML.includes('&lt;img'));
    assert(!xss.element('user-list').innerHTML.includes('onclick='));
    xss.context.renderProxyTable([{id: 1, ipv6: marker, port: 10000, protocol: marker, status: marker, created_at: marker}]);
    assert(!xss.element('proxy-tbody').innerHTML.includes(marker));
    assert(!xss.element('proxy-tbody').innerHTML.includes('onclick='));
    console.log('PASS: stored user/proxy HTML is escaped; dynamic handlers are delegated');

    const csrf = fixture([{status: 200, data: {csrf_token: 'fixture-csrf'}}, {status: 400, data: {success: false, error: 'invalid fixture'}}]);
    await assert.rejects(() => csrf.context.api('/api/settings', {method: 'POST', body: '{}'}), /invalid fixture/);
    assert.equal(csrf.calls[1].options.headers['X-CSRF-Token'], 'fixture-csrf');
    assert.match(csrf.calls[1].options.headers['Idempotency-Key'], /^[0-9a-f-]{36}$/);
    assert.equal(csrf.calls[1].options.credentials, 'same-origin');
    csrf.context.crypto = {getRandomValues: crypto.webcrypto.getRandomValues.bind(crypto.webcrypto)};
    assert.match(csrf.context.idempotencyKey(), /^[0-9a-f-]{36}$/);
    console.log('PASS: API checks HTTP/result errors and attaches CSRF/idempotency headers');

    const failed = fixture([{status: 200, data: {csrf_token: 'fixture-csrf'}}, {status: 400, data: {success: false, error: 'generation failed'}}]);
    await failed.context.generateProxies();
    assert.deepEqual(failed.calls.map(x => x.url), ['/api/csrf', '/api/proxies/generate']);
    assert(!failed.toasts.some(x => x.type === 'success'));
    console.log('PASS: failed generation performs no settings/user mutation or restart and no success toast');

    for (const oldUsers of [[], [{username: 'old-account'}]]) {
        const blankAuth = fixture([{status: 200, data: {csrf_token: 'fixture-csrf'}},
            {status: 200, data: {success: true, generated: 5}}]);
        vm.runInContext(`allUsers = ${JSON.stringify(oldUsers)};`, blankAuth.context);
        blankAuth.element('auth-user').value = '';
        blankAuth.element('auth-pass').value = '';
        await blankAuth.context.generateProxies();
        assert.deepEqual(blankAuth.calls.map(call => call.url), ['/api/csrf', '/api/proxies/generate']);
        const body = JSON.parse(blankAuth.calls[1].options.body);
        assert.equal(body.auth_type, 'none');
        assert.equal(body.username, '');
        assert.equal(body.password, '');
        assert.equal(body.public_proxy, true);
        assert.equal(body.listener_ipv4, '127.0.0.1');
        assert.deepEqual(body.allowed_ips, []);
    }
    console.log('PASS: blank proxy fields explicitly request no-auth even when old accounts exist, retaining listener/ACL');

    const checkedNoAuth = fixture([{status: 200, data: {csrf_token: 'fixture-csrf'}},
        {status: 200, data: {success: true, generated: 5}}]);
    checkedNoAuth.element('opt-no-auth').checked = true;
    checkedNoAuth.element('opt-public').checked = false;
    await checkedNoAuth.context.generateProxies();
    const noAuthBody = JSON.parse(checkedNoAuth.calls[1].options.body);
    assert.equal(noAuthBody.auth_type, 'none');
    assert.equal(noAuthBody.username, '');
    assert.equal(noAuthBody.password, '');
    assert.equal(noAuthBody.public_proxy, true);
    assert.match(checkedNoAuth.element('status-message').textContent, /Không yêu cầu tài khoản\/mật khẩu/);
    console.log('PASS: the explicit no-auth option no longer silently returns when Public Proxy is unchecked');

    for (const pair of [['fixture', ''], ['', 'fixture']]) {
        const partialAuth = fixture();
        partialAuth.element('auth-user').value = pair[0];
        partialAuth.element('auth-pass').value = pair[1];
        await partialAuth.context.generateProxies();
        assert.equal(partialAuth.calls.length, 0);
        assert(partialAuth.toasts.some(toast => /cả username và password|cả tài khoản và mật khẩu/i.test(toast.message)));
    }
    console.log('PASS: partially blank proxy credentials reject clearly before sending a request');

    const ipAuth = fixture([{status: 200, data: {csrf_token: 'fixture-csrf'}},
        {status: 200, data: {success: true, generated: 5}}]);
    vm.runInContext("currentSettings = {auth_type: 'ip'};", ipAuth.context);
    ipAuth.element('auth-user').value = '';
    ipAuth.element('auth-pass').value = '';
    ipAuth.element('allowed-ips').value = '192.168.1.0/24';
    await ipAuth.context.generateProxies();
    const ipBody = JSON.parse(ipAuth.calls[1].options.body);
    assert.equal(ipBody.auth_type, 'ip');
    assert.deepEqual(ipBody.allowed_ips, ['192.168.1.0/24']);
    assert(!Object.hasOwn(ipBody, 'username'));
    assert(!Object.hasOwn(ipBody, 'password'));
    assert.equal(ipBody.public_proxy, false);
    console.log('PASS: blank fields preserve an explicitly selected IP whitelist instead of disabling its ACL');

    const declinedAuth = fixture();
    declinedAuth.element('auth-user').value = '';
    declinedAuth.element('auth-pass').value = '';
    declinedAuth.context.confirm = () => false;
    await declinedAuth.context.generateProxies();
    assert.equal(declinedAuth.calls.length, 0);
    assert.equal(declinedAuth.element('btn-generate').disabled, undefined);
    console.log('PASS: declining the no-auth confirmation makes no network or loading-state change');

    const bounds = fixture();
    bounds.element('proxy-count').value = '5.5';
    await bounds.context.generateProxies();
    assert.equal(bounds.calls.length, 0);
    bounds.element('max-conn').value = '-1';
    bounds.element('timeout-connect').value = '10';
    bounds.element('timeout-idle').value = '300';
    await bounds.context.saveConnectionSettings();
    assert.equal(bounds.calls.length, 0);
    for (const password of [' space', 'colon:', 'dollar$', 'quote"', 'slash\\', 'comment#']) {
        assert.equal(bounds.context.validCredentials('fixture', password), false);
    }
    console.log('PASS: fractional counts, negative connection limits and unsafe credential tokens fail client validation');

    const initialized = fixture();
    const order = [];
    initialized.context.loadSettings = async () => { order.push('settings-start'); await Promise.resolve(); order.push('settings-done'); };
    initialized.context.loadInterfaces = async () => { order.push('interfaces'); };
    initialized.context.loadUsers = () => {};
    await initialized.init();
    assert.deepEqual(order, ['settings-start', 'settings-done', 'interfaces']);
    assert(!/\son(?:click|change|input)=/i.test(fs.readFileSync('templates/index.html', 'utf8')));
    assert(fs.readFileSync('templates/login.html', 'utf8').includes('name="csrf_token"'));
    assert(!fs.readFileSync('templates/index.html', 'utf8').includes('href="/logout"'));
    console.log('PASS: startup is ordered; templates contain no inline script handlers and login includes CSRF');

    const recoveryLoad = fixture([{status: 200, data: {
        auth_type: 'userpass', startup_rebuild_enabled: true, startup_proxy_count: 75
    }}]);
    await recoveryLoad.context.loadSettings();
    assert.equal(recoveryLoad.element('startup-rebuild-enabled').checked, true);
    assert.equal(recoveryLoad.element('startup-proxy-count').value, 75);
    const legacyLoad = fixture([{status: 200, data: {auth_type: 'userpass'}}]);
    await legacyLoad.context.loadSettings();
    assert.equal(legacyLoad.element('startup-rebuild-enabled').checked, false);
    assert.equal(legacyLoad.element('startup-proxy-count').value, 25);
    console.log('PASS: recovery settings load typed values and legacy defaults without extra requests');

    const recoverySave = fixture([
        {status: 200, data: {csrf_token: 'fixture-csrf'}},
        {status: 200, data: {success: true, settings: {startup_rebuild_enabled: true, startup_proxy_count: 75}}}
    ]);
    recoverySave.element('startup-rebuild-enabled').checked = true;
    recoverySave.element('startup-proxy-count').value = '75';
    await recoverySave.context.saveStartupRecoverySettings();
    assert.deepEqual(recoverySave.calls.map(x => x.url), ['/api/csrf', '/api/settings']);
    assert.deepEqual(JSON.parse(recoverySave.calls[1].options.body), {startup_rebuild_enabled: true, startup_proxy_count: 75});
    assert.equal(recoverySave.element('btn-save-startup-recovery').disabled, false);
    assert.match(recoverySave.element('startup-recovery-save-status').textContent, /75 proxy/);
    assert.match(recoverySave.element('startup-recovery-save-status').textContent, /Start/);
    console.log('PASS: recovery save submits only the two typed controls and reports next-start/Stop behavior');

    const recoveryBounds = fixture();
    for (const count of ['', '0', '-1', '1.5', '1025', 'NaN']) {
        recoveryBounds.element('startup-proxy-count').value = count;
        await recoveryBounds.context.saveStartupRecoverySettings();
    }
    assert.equal(recoveryBounds.calls.length, 0);
    const recoveryFailed = fixture([
        {status: 200, data: {csrf_token: 'fixture-csrf'}},
        {status: 400, data: {success: false, error: marker}}
    ]);
    recoveryFailed.element('startup-proxy-count').value = '25';
    await recoveryFailed.context.saveStartupRecoverySettings();
    assert.equal(recoveryFailed.element('btn-save-startup-recovery').disabled, false);
    assert(recoveryFailed.element('startup-recovery-save-status').textContent.includes(marker));
    assert(!recoveryFailed.toasts.some(x => x.type === 'success'));
    assert.equal(recoveryFailed.element('startup-recovery-save-status').innerHTML, '');
    console.log('PASS: recovery count validation and failed-save feedback are non-destructive and text-only');

    const recoveryStatus = fixture();
    for (const [state, pattern] of Object.entries({
        waiting: /Đang chờ/, rebuilding: /Đang dọn/, ready: /hoàn tất/, error: /thử lại/,
        stopped: /Start/, disabled: /đang tắt/
    })) {
        recoveryStatus.context.renderStartupRecovery({startup_recovery: {
            state, message: marker, base_ipv6: '2001:db8:2::1', subnet: '2001:db8:2::', target_count: 75
        }});
        assert.match(recoveryStatus.element('startup-recovery-status').textContent, pattern);
        assert(recoveryStatus.element('startup-recovery-tool-status').textContent.includes(marker));
        assert.equal(recoveryStatus.element('startup-recovery-tool-status').innerHTML, '');
        assert.match(recoveryStatus.element('startup-recovery-detail').textContent, /2001:db8:2::1/);
        assert.match(recoveryStatus.element('startup-recovery-detail').textContent, /75/);
    }
    const template = fs.readFileSync('templates/index.html', 'utf8');
    assert(template.includes('Tạo lại proxy khi khởi động'));
    assert(template.includes('id="startup-proxy-count" min="1" max="1024" step="1"'));
    assert(template.includes('id="startup-recovery-save-status" role="status" aria-live="polite"'));
    console.log('PASS: waiting/rebuilding/error/ready/stopped status is explicit, accessible and text-only');

    const beforeRecovery = {auth_type: 'userpass', interface: 'eth0', subnet: '2001:db8:1::',
        prefix_len: 64, startup_rebuild_enabled: true, startup_proxy_count: 75};
    const afterRecovery = {...beforeRecovery, subnet: '2001:db8:2::'};
    const completed = {startup_recovery: {state: 'ready', completed_at: 123,
        base_ipv6: '2001:db8:2::1', subnet: '2001:db8:2::', prefix_len: 64}};
    const completion = fixture([
        {status: 200, data: beforeRecovery}, {status: 200, data: afterRecovery},
        {status: 200, data: afterRecovery}, {status: 200, data: {csrf_token: 'fixture-csrf'}},
        {status: 200, data: {success: true, settings: {...afterRecovery, startup_proxy_count: 200}}}
    ]);
    await completion.context.loadSettings();
    completion.element('startup-proxy-count').value = '200';
    let completedListLoads = 0;
    completion.context.loadProxies = async () => { completedListLoads++; return true; };
    await Promise.all([completion.context.syncCompletedStartupRecovery(completed),
        completion.context.syncCompletedStartupRecovery(completed)]);
    await completion.context.syncCompletedStartupRecovery(completed);
    assert.equal(completedListLoads, 1);
    assert.equal(completion.calls.length, 2);
    assert.equal(completion.element('ipv6-subnet').value, '2001:db8:2::');
    assert.equal(completion.element('startup-proxy-count').value, '200');
    await completion.context.syncCompletedStartupRecovery({startup_recovery: {...completed.startup_recovery, completed_at: 124}});
    assert.equal(completedListLoads, 2);
    assert.equal(completion.calls.length, 3);
    assert.equal(completion.element('startup-proxy-count').value, '200');
    await completion.context.saveStartupRecoverySettings();
    assert.equal(JSON.parse(completion.calls[4].options.body).startup_proxy_count, 200);
    assert.equal(completion.element('startup-proxy-count').value, '200');
    console.log('PASS: each recovery completion refreshes settings/list once without overlapping or overwriting count edits');

    for (const editing of ['edited-subnet', 'focused-subnet', 'other-interface']) {
        const untouched = fixture([{status: 200, data: beforeRecovery}, {status: 200, data: afterRecovery}]);
        await untouched.context.loadSettings();
        if (editing === 'edited-subnet') untouched.element('ipv6-subnet').value = '2001:db8:9::';
        if (editing === 'focused-subnet') untouched.context.document.activeElement = untouched.element('ipv6-subnet');
        if (editing === 'other-interface') untouched.element('interface-select').value = 'eth1';
        const value = untouched.element('ipv6-subnet').value;
        await untouched.context.syncCompletedStartupRecovery(completed);
        assert.equal(untouched.element('ipv6-subnet').value, value);
    }
    console.log('PASS: completion preserves edited/focused subnet and another selected interface');

    const staleCandidates = fixture([{status: 200, data: {subnets: [
        {subnet: '2001:db8:1::', prefix_len: 64, source_address: '2001:db8:1::1', full: '2001:db8:1::/64'},
        {subnet: '2001:db8:2::', prefix_len: 64, source_address: '2001:db8:2::1', full: '2001:db8:2::/64'}
    ]}}]);
    staleCandidates.element('ipv6-subnet').value = '';
    await staleCandidates.context.detectSubnets('eth0');
    assert.equal(staleCandidates.element('ipv6-subnet').value, '');
    assert(staleCandidates.element('subnet-list').innerHTML.includes('chưa xác minh Internet'));
    const verifiedCandidate = fixture([{status: 200, data: {subnets: [
        {subnet: '2001:db8:1::', prefix_len: 64, source_address: '2001:db8:1::1'},
        {subnet: '2001:db8:2::', prefix_len: 64, source_address: '2001:db8:2::1', verified: true}
    ]}}]);
    verifiedCandidate.element('ipv6-subnet').value = '';
    await verifiedCandidate.context.detectSubnets('eth0');
    assert.equal(verifiedCandidate.element('ipv6-subnet').value, '2001:db8:2::');
    assert.equal(staleCandidates.toasts.length, 0);
    console.log('PASS: multiple GUA candidates never auto-select an unverified first/stale subnet');

    const refreshRetry = fixture([
        {status: 200, data: beforeRecovery}, {status: 503, data: {error: 'fixture retry'}},
        {status: 200, data: afterRecovery}
    ]);
    await refreshRetry.context.loadSettings();
    refreshRetry.element('startup-proxy-count').value = '200';
    await refreshRetry.context.syncCompletedStartupRecovery(completed);
    assert.match(refreshRetry.element('startup-recovery-detail').textContent, /fixture retry/);
    await refreshRetry.context.syncCompletedStartupRecovery(completed);
    assert.equal(refreshRetry.calls.length, 3);
    assert.equal(refreshRetry.element('startup-proxy-count').value, '200');
    await refreshRetry.context.syncCompletedStartupRecovery({startup_recovery: {state: 'waiting', completed_at: 999}});
    await refreshRetry.context.syncCompletedStartupRecovery({startup_recovery: {state: 'ready', completed_at: null}});
    assert.equal(refreshRetry.calls.length, 3);
    console.log('PASS: failed completion refresh retries later; pending/invalid completion triggers no loads');
})().catch(error => { console.error(error); process.exitCode = 1; });
