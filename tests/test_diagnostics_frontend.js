'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');
const source = fs.readFileSync('static/app.js', 'utf8');

function fixture(responses = []) {
    const elements = new Map(), calls = [], toasts = [], intervals = [];
    function element(id) {
        if (!elements.has(id)) elements.set(id, {
            value: '', checked: false, disabled: false, textContent: '', innerHTML: '',
            style: {}, dataset: {}, attributes: {},
            setAttribute(name, value) { this.attributes[name] = value; },
            classList: {add() {}, remove() {}}, addEventListener() {},
            appendChild() {}, append() {}, querySelector() { return element('child-' + id); }
        });
        return elements.get(id);
    }
    const context = vm.createContext({console, crypto,
        document: {getElementById: element, querySelectorAll: () => [], querySelector: () => null,
            addEventListener() {}, createElement: () => element('created')},
        window: {location: {protocol: 'http:', port: '7070'}},
        setInterval(callback, period) { intervals.push({callback, period}); }, setTimeout() {},
        fetch: async (url, options) => {
            calls.push({url, options});
            const response = responses.shift();
            if (!response) throw new Error('Unexpected fetch: ' + url);
            return {ok: response.status < 400, status: response.status, json: async () => response.data};
        }
    });
    vm.runInContext(source, context);
    context.showToast = (message, type) => toasts.push({message, type});
    return {context, element, calls, toasts, intervals};
}

(async () => {
    for (const [value, expected] of [[undefined, 15], [1, 1], [5, 5], [30, 30], [0, 15], [31, 15], ['5', 15], [2.5, 15]]) {
        const loaded = fixture([{status: 200, data: {auth_type: 'none', timeout_dns: value}}]);
        await loaded.context.loadSettings();
        assert.equal(loaded.element('timeout-dns').value, expected);
    }
    console.log('PASS: DNS timeout loads strict 1..30 integers and preserves default15 compatibility');

    const saved = fixture([{status: 200, data: {csrf_token: 'fixture-csrf'}}, {status: 200, data: {success: true}}]);
    saved.element('max-conn').value = '256';
    saved.element('timeout-connect').value = '5';
    saved.element('timeout-dns').value = '3';
    saved.element('timeout-idle').value = '60';
    await saved.context.saveConnectionSettings();
    assert.deepEqual(JSON.parse(saved.calls[1].options.body), {max_connections: 256, timeout_connect: 5, timeout_dns: 3, timeout_idle: 60});
    assert.equal(saved.toasts[0].type, 'success');
    const invalid = fixture();
    invalid.element('max-conn').value = '64';
    invalid.element('timeout-connect').value = '5';
    invalid.element('timeout-idle').value = '60';
    for (const value of ['', '0', '31', '1.2', 'NaN', 'Infinity']) {
        invalid.element('timeout-dns').value = value;
        await invalid.context.saveConnectionSettings();
    }
    assert.equal(invalid.calls.length, 0);
    assert(invalid.toasts.every(toast => toast.type === 'warning'));
    console.log('PASS: DNS timeout saves exact integer with connection settings and rejects invalid bounds before API');

    const success = fixture([{status: 200, data: {csrf_token: 'fixture-csrf'}}, {status: 200, data: {
        success: true, target_host: 'www.bing.com', dns: {available: true, results: [], summary: []},
        history: {sample_count: 0, success_count: 0, error_count: 0, error_categories: {}, by_port: [], by_domain: []}
    }}]);
    success.element('speedtest-url').value = 'custom';
    success.element('speedtest-custom-url').value = 'https://www.bing.com/?q=example';
    await success.context.runProxyDiagnostics();
    assert.deepEqual(success.calls.map(call => call.url), ['/api/csrf', '/api/proxy/diagnostics']);
    assert.deepEqual(JSON.parse(success.calls[1].options.body), {target_url: 'https://www.bing.com/?q=example'});
    assert.equal(success.element('btn-proxy-diagnostics').disabled, false);
    assert.equal(success.element('proxy-diagnostics-panel').attributes['aria-busy'], 'false');
    assert.equal(success.element('proxy-diagnostics-result').style.display, 'block');
    assert.match(success.element('proxy-diagnostics-status').textContent, /www.bing.com/);
    assert.match(success.element('diagnostics-history-tbody').innerHTML, /Chưa có speedtest/);
    assert.equal(success.intervals.length, 0);
    console.log('PASS: on-demand diagnostics uses selected target, one CSRF-protected POST and no background DNS polling');

    let release;
    const pending = fixture();
    let requests = 0;
    pending.context.api = async () => { requests++; await new Promise(resolve => { release = resolve; }); return {target_host: 'bing.com'}; };
    const first = pending.context.runProxyDiagnostics();
    assert.equal(pending.element('btn-proxy-diagnostics').disabled, true);
    assert.equal(pending.element('proxy-diagnostics-panel').attributes['aria-busy'], 'true');
    await pending.context.runProxyDiagnostics();
    assert.equal(requests, 1);
    release();
    await first;
    assert.equal(pending.element('btn-proxy-diagnostics').disabled, false);
    assert.equal(pending.element('proxy-diagnostics-panel').attributes['aria-busy'], 'false');
    console.log('PASS: diagnostics in-flight guard prevents duplicate DNS probes and releases accessible busy state');

    const marker = '<img src=x onerror="alert(1)">';
    const rendered = fixture();
    rendered.context.renderProxyDiagnostics({target_host: marker,
        dns: {available: true, results: [{server: marker, hostname: marker, success: true, outcome: marker, rcode: marker, elapsed_ms: 0, addresses: [marker]}],
            summary: [{server: marker, samples: 2, successes: 1, p50_ms: 0, p95_ms: null, p99_ms: 35}]},
        history: {sample_count: 4, success_count: 2, error_count: 2, p50_ms: 342, p95_ms: 550, p99_ms: 770,
            error_categories: {[marker]: 1, connect: 1},
            by_port: [{port: 10001, sample_count: 2, success_count: 1, error_count: 1, p50_ms: 342, p95_ms: 550, p99_ms: 770}],
            by_domain: [{domain: marker, sample_count: 2, success_count: 1, error_count: 1, p50_ms: 100, p95_ms: null, p99_ms: null}]},
        resources: {observation: 'cached', observed_at: Date.now() / 1000 - 3,
            threads: {current: 0, limit: 6044}, sockets: {established: 0, close_wait: 0}, memory: {current_bytes: 1048576},
            cpu: {usage_percent_one_core: 0, throttled_events_delta: 0, throttled_seconds_delta: 0, sample_seconds: 5},
            network: {sample_seconds: 5, interfaces: [{interface: marker, speed_mbps: 100, rx_mbps: 0, tx_mbps: 1.2,
                rx_errors_delta: 0, tx_errors_delta: 0, rx_dropped_delta: 0, tx_dropped_delta: 0}],
                tcp: {listen_overflows_delta: 0, listen_drops_delta: 0, syn_retrans_delta: 0, retrans_segments_delta: 0}}}
    });
    for (const id of ['diagnostics-dns-tbody', 'diagnostics-history-tbody']) {
        assert(!rendered.element(id).innerHTML.includes(marker));
        assert(rendered.element(id).innerHTML.includes('&lt;img'));
    }
    for (const id of ['diagnostics-dns-summary', 'diagnostics-history-errors', 'diagnostics-network-summary']) {
        assert(rendered.element(id).textContent.includes(marker));
        assert.equal(rendered.element(id).innerHTML, '');
    }
    assert.match(rendered.element('diagnostics-dns-tbody').innerHTML, /0\.0 ms/);
    assert.match(rendered.element('diagnostics-history-summary').textContent, /P50 342\.0 ms.*P95 550\.0 ms.*P99 770\.0 ms/);
    assert.match(rendered.element('diagnostics-resource-summary').textContent, /cache.*Thread 0\/6044.*CLOSE_WAIT 0/);
    assert.match(rendered.element('diagnostics-cpu-summary').textContent, /0\.0%/);
    assert.match(rendered.element('diagnostics-network-summary').textContent, /không chỉ proxy.*ListenOverflows \+0/);
    console.log('PASS: DNS outcomes, per-port/domain percentiles and scoped CPU/NIC deltas escape untrusted text and preserve real zeros');

    const noAAAA = fixture();
    noAAAA.context.renderProxyDiagnostics({dns: {available: true, results: [{server: '1.1.1.1', success: false, outcome: 'no_aaaa', rcode: 0, rcode_name: 'NOERROR', addresses: [], elapsed_ms: 24}]},
        resources: {observation: 'unavailable', threads: {current: 99}, sockets: {close_wait: 99},
            cpu: {usage_percent_one_core: 999}, network: {tcp: {listen_overflows_delta: 99}}}});
    assert.match(noAAAA.element('diagnostics-dns-tbody').innerHTML, /Không có AAAA/);
    assert.match(noAAAA.element('diagnostics-resource-summary').textContent, /Thread —\/—.*CLOSE_WAIT —/);
    assert(!noAAAA.element('diagnostics-cpu-summary').textContent.includes('999'));
    assert(!noAAAA.element('diagnostics-network-summary').textContent.includes('+99'));
    assert.equal(noAAAA.context.diagnosticNumber(null), '—');
    assert.equal(noAAAA.context.diagnosticNumber('0'), '—');
    assert.equal(noAAAA.context.diagnosticNumber(Infinity), '—');
    assert.equal(noAAAA.context.diagnosticNumber(-1), '—');
    noAAAA.context.renderProxyDiagnostics({dns: {available: false, error: marker}});
    assert(noAAAA.element('diagnostics-dns-summary').textContent.includes(marker));
    assert.equal(noAAAA.element('diagnostics-dns-summary').innerHTML, '');
    console.log('PASS: successful no-AAAA responses stay distinct from errors; unavailable/missing observations never fabricate zero');

    const failed = fixture([{status: 200, data: {csrf_token: 'fixture-csrf'}}, {status: 503, data: {success: false, error: marker}}]);
    failed.element('speedtest-url').value = 'https://www.bing.com';
    await failed.context.runProxyDiagnostics();
    assert(failed.element('proxy-diagnostics-status').textContent.includes(marker));
    assert.equal(failed.element('proxy-diagnostics-status').innerHTML, '');
    assert.equal(failed.element('proxy-diagnostics-result').style.display, 'none');
    assert.equal(failed.element('btn-proxy-diagnostics').disabled, false);
    assert.equal(failed.element('proxy-diagnostics-panel').attributes['aria-busy'], 'false');
    console.log('PASS: diagnostic API failures remain visible text, hide stale results and always restore usable controls');

    const template = fs.readFileSync('templates/index.html', 'utf8');
    assert(template.includes('id="timeout-dns" min="1" max="30" step="1" value="15"'));
    assert(template.includes('id="proxy-diagnostics-status" class="network-detail" role="status" aria-live="polite"'));
    assert(template.includes('không phải DNS của website'));
    assert(template.includes('không chỉ TLS'));
    assert(template.includes('không ghi nhận tự động traffic của trình duyệt'));
    assert(!template.includes('DNS curl'));
    assert(!/\son(?:click|change|input)=/i.test(template));
    const ids = [...template.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]);
    assert.equal(new Set(ids).size, ids.length);
    assert(!source.includes('setInterval(runProxyDiagnostics'));
    console.log('PASS: accessible diagnostics controls retain unique IDs and clearly distinguish proxy timings, resolver probes and speedtest-only history');
})().catch(error => { console.error(error); process.exitCode = 1; });
