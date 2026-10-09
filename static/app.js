/**
 * IPv6 Proxy Manager - Frontend Application
 * Handles all UI interactions and API calls
 */

// ============ STATE ============
let allProxies = [];
let allUsers = [];
let currentSettings = {};
let startupRecoveryRefreshInFlight = null;
let lastStartupRecoveryCompletedAt = null;
let interfaceInventory = [];
let statusPollInFlight = false;
let healthPollInFlight = false;
let generationInFlight = false;
let statusNextPollAt = 0;
let threadSettingsInFlight = false;

// ============ INIT ============
document.addEventListener('DOMContentLoaded', async () => {
    // Setup navigation
    document.querySelectorAll('.nav-item[data-page]').forEach(item => {
        item.addEventListener('click', (e) => {
            e.preventDefault();
            switchPage(item.dataset.page);
        });
    });

    const actions = {
        onInterfaceChange, generateProxies, startProxy, stopProxy, restartProxy, logout,
        exportProxies, deleteAllProxies, filterProxies, refreshProxyList,
        toggleCheckAll, closeExportModal, copyExport, downloadExport, addUser,
        updateAuthType, onSpeedtestUrlChange, runSingleSpeedtest, runBatchSpeedtest,
        runAutoOptimize, saveDNS, saveConnectionSettings, saveThreadLimitSettings, saveStartupRecoverySettings, saveSourceChangeSettings,
        changeDashboardPassword, saveTelegramSettings,
        testTelegram, refreshIPv6Info, cleanupIPv6, testProxy, refreshLogs
    };
    for (const eventName of ['click', 'change', 'input']) {
        document.querySelectorAll(`[data-${eventName}-action]`).forEach(element => {
            element.addEventListener(eventName, event => {
                const action = actions[element.dataset[`${eventName}Action`]];
                if (!action) return;
                const arg = element.dataset.actionValue === 'true' ? element.value : element.dataset.actionArg;
                action(arg, event);
            });
        });
    }

    // Load initial data
    await loadSettings();
    await loadInterfaces();
    loadProxies();
    loadUsers();
    refreshStatus();

    document.getElementById('user-list').addEventListener('click', event => {
        const button = event.target.closest('[data-delete-user]');
        if (button) deleteUser(button.dataset.deleteUser);
    });
    document.getElementById('proxy-tbody').addEventListener('click', event => {
        const button = event.target.closest('[data-proxy-action]');
        if (!button) return;
        const id = Number(button.dataset.proxyId);
        if (!Number.isSafeInteger(id)) return;
        if (button.dataset.proxyAction === 'rotate') rotateProxy(id);
        if (button.dataset.proxyAction === 'delete') deleteProxy(id);
    });
    document.getElementById('subnet-list').addEventListener('click', event => {
        const item = event.target.closest('[data-subnet]');
        if (item) selectSubnet(item.dataset.subnet, Number(item.dataset.prefix));
    });

    // Cheap progress polling stays independent of heavier diagnostics.
    setInterval(() => { if (Date.now() >= statusNextPollAt) refreshStatus(false); }, 2000);
    setInterval(refreshHealth, 15000);

    // Protocol radio change handler - show/hide dual info
    document.querySelectorAll('input[name="protocol"]').forEach(radio => {
        radio.addEventListener('change', () => {
            const dualInfo = document.getElementById('dual-protocol-info');
            if (dualInfo) {
                dualInfo.style.display = radio.value === 'dual' ? 'block' : 'none';
            }
        });
    });
});

// ============ NAVIGATION ============
function switchPage(page) {
    // Update nav
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelector(`[data-page="${page}"]`).classList.add('active');

    // Update pages
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.getElementById(`page-${page}`).classList.add('active');

    // Load page-specific data
    if (page === 'list') {
        loadProxies();
    } else if (page === 'users') {
        loadUsers();
    } else if (page === 'tools') {
        refreshIPv6Info();
    } else if (page === 'logs') {
        refreshLogs();
    }
}

// ============ API HELPERS ============
let csrfToken = null;
function escapeHtml(value) {
    return String(value ?? '').replace(/[&<>"']/g, char => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[char]);
}
function validCredentials(username, password) {
    return /^[A-Za-z0-9_.@-]{1,64}$/.test(username) && password.length <= 256 && /^[!-~]+$/.test(password) && !/[:$"\\#]/.test(password);
}
function idempotencyKey() {
    if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
    // getRandomValues also works on an HTTP LAN origin; randomUUID requires secure context.
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    const hex = Array.from(bytes, value => value.toString(16).padStart(2, '0')).join('');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}
async function api(url, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    const method = (options.method || 'GET').toUpperCase();
    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
        if (!csrfToken) {
            const csrf = await fetch('/api/csrf', { credentials: 'same-origin' });
            if (!csrf.ok) throw new Error('Phiên đăng nhập đã hết hạn');
            csrfToken = (await csrf.json()).csrf_token;
            if (!csrfToken) throw new Error('Thiếu CSRF token');
        }
        headers['X-CSRF-Token'] = csrfToken;
        headers['Idempotency-Key'] = headers['Idempotency-Key'] || idempotencyKey();
    }
    const response = await fetch(url, { ...options, headers, credentials: 'same-origin' });
    let data;
    try { data = await response.json(); }
    catch (_) { throw new Error('Server trả về phản hồi không hợp lệ'); }
    if (!response.ok || data.success === false) {
        if (response.status === 401 || response.status === 403) csrfToken = null;
        throw new Error(data.error || data.message || `HTTP ${response.status}`);
    }
    return data;
}

// ============ TOAST NOTIFICATIONS ============
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const icons = {
        success: '✅',
        error: '❌',
        info: 'ℹ️',
        warning: '⚠️'
    };

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    const icon = document.createElement('span');
    icon.className = 'toast-icon';
    icon.textContent = icons[type] || icons.info;
    const text = document.createElement('span');
    text.className = 'toast-message';
    text.textContent = String(message ?? '');
    toast.append(icon, text);

    container.appendChild(toast);

    // Auto remove after 4 seconds
    setTimeout(() => {
        toast.classList.add('removing');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ============ SETTINGS ============
async function loadSettings() {
    try {
        const data = await api('/api/settings');
        currentSettings = data;

        // Fill form fields
        if (data.start_port) document.getElementById('start-port').value = data.start_port;
        if (data.subnet) document.getElementById('ipv6-subnet').value = data.subnet;
        if (data.rotation_interval) document.getElementById('rotation-interval').value = data.rotation_interval;

        document.getElementById('opt-no-auth').checked = data.auth_type === 'none';
        document.getElementById('opt-public').checked = Boolean(data.public_proxy);
        document.getElementById('opt-no-rotate').checked = !data.rotation_enabled;
        document.getElementById('opt-autostart').checked = Boolean(data.auto_start);
        document.getElementById('startup-rebuild-enabled').checked = Boolean(data.startup_rebuild_enabled);
        document.getElementById('startup-proxy-count').value = data.startup_proxy_count ?? 25;

        // Netmask radio
        const netmaskVal = data.prefix_len || 64;
        const netmaskRadio = document.querySelector(`input[name="netmask"][value="${netmaskVal}"]`);
        if (netmaskRadio) netmaskRadio.checked = true;

        // Protocol radio
        if (data.protocol) {
            const protocolRadio = document.querySelector(`input[name="protocol"][value="${data.protocol}"]`);
            if (protocolRadio) protocolRadio.checked = true;
        }

        // DNS fields on tools page
        if (data.dns1) document.getElementById('dns1').value = data.dns1;
        if (data.dns2) document.getElementById('dns2').value = data.dns2;
        document.getElementById('max-conn').value = data.max_connections ?? 64;
        document.getElementById('thread-limit').value = Number.isSafeInteger(data.thread_limit) && data.thread_limit >= 256 && data.thread_limit <= 16384 ? data.thread_limit : 4096;
        document.getElementById('source-change-confirmations').value = data.source_change_confirmations ?? 2;
        document.getElementById('source-poll-interval').value = data.source_poll_interval ?? 5;
        if (data.timeout_connect) document.getElementById('timeout-connect').value = data.timeout_connect;
        if (data.timeout_idle) document.getElementById('timeout-idle').value = data.timeout_idle;
        document.getElementById('telegram-token').value = '';
        document.getElementById('telegram-token').placeholder = data.telegram_bot_token_configured ? 'Đã cấu hình; để trống để giữ nguyên' : 'Nhập token mới';
        if (data.telegram_chat_id) document.getElementById('telegram-chat-id').value = data.telegram_chat_id;

        for (const [field, id] of Object.entries({topology_mode: 'topology-mode', routed_prefix: 'routed-prefix', listener_ipv4: 'listener-ipv4', probe_url: 'probe-url'})) {
            if (data[field] !== undefined && document.getElementById(id)) document.getElementById(id).value = data[field];
        }
        document.getElementById('allowed-ips').value = (data.allowed_ips || []).join('\n');
        document.getElementById('telegram-allowed-user-ids').value = (data.telegram_allowed_user_ids || []).join(', ');
        // Auth type on users page
        const authRadio = document.querySelector(`input[name="auth-type"][value="${data.auth_type || 'userpass'}"]`);
        if (authRadio) authRadio.checked = true;

    } catch (e) {
        console.error('Failed to load settings:', e);
    }
}

// ============ INTERFACES ============
async function loadInterfaces() {
    try {
        const data = await api('/api/interfaces');
        const select = document.getElementById('interface-select');
        select.innerHTML = '';
        interfaceInventory = Array.isArray(data.details) ? data.details : [];

        if (data.interfaces && data.interfaces.length > 0) {
            data.interfaces.forEach(iface => {
                const opt = document.createElement('option');
                const name = typeof iface === 'string' ? iface : iface.device || iface.name;
                const detail = interfaceInventory.find(row => row.device === name) || (typeof iface === 'object' ? iface : null);
                opt.value = name;
                opt.textContent = detail ? `${name} — ${detail.kind || 'network'} · ${detail.active ? 'Up' : 'Down'}${detail.ipv4?.length ? ' · ' + detail.ipv4.join(', ') : ''}` : name;
                if (currentSettings.interface === name) opt.selected = true;
                select.appendChild(opt);
            });
        } else {
            select.innerHTML = '<option value="eth0">eth0</option>';
        }

        // Auto-detect subnets for the currently selected interface
        const selectedIface = select.value;
        renderInterfaceDetail(selectedIface);
        if (selectedIface) {
            detectSubnets(selectedIface);
        }
    } catch (e) {
        console.error('Failed to load interfaces:', e);
    }
}

async function onInterfaceChange(iface) {
    renderInterfaceDetail(iface);
    detectSubnets(iface);
}

function renderInterfaceDetail(name) {
    const element = document.getElementById('interface-detail');
    if (!element) return;
    const row = interfaceInventory.find(item => item.device === name || item.name === name);
    if (!row) { element.textContent = ''; return; }
    // Raw ipv6 is a full diagnostic inventory, including all generated aliases.
    // Only backend-classified system source candidates belong in this summary.
    const classified = Array.isArray(row.source_ipv6);
    const ipv6 = (classified ? row.source_ipv6 : []).filter(item =>
        item && item.origin === 'system').map(item =>
        typeof item === 'string' ? item : `${item.address || ''}${Number.isInteger(item.prefix_len) ? '/' + item.prefix_len : ''}`);
    const sourceSummary = ipv6.slice(0, 3).join(', ') + (ipv6.length > 3 ? ` (+${ipv6.length - 3} IPv6 hệ thống khác)` : '');
    element.textContent = [`${row.name || row.device} (${row.kind || 'network'}) — ${row.active ? 'đang kết nối' : 'chưa kết nối'}`,
        row.ipv4?.length ? `IPv4: ${row.ipv4.join(', ')}` : 'Chưa có IPv4',
        ipv6.length ? `IPv6 nguồn ứng viên: ${sourceSummary}` : classified ? 'Chưa có IPv6 nguồn đủ điều kiện' : 'Đang chờ worker phân loại IPv6 nguồn/pool',
        Number.isInteger(row.managed_ipv6_count) ? `Pool do tool quản lý: ${row.managed_ipv6_count} IPv6` : 'Số IPv6 pool: chưa có dữ liệu phân loại',
        row.uncertain_ipv6_count > 0 ? `Chờ xác minh quyền quản lý: ${row.uncertain_ipv6_count} IPv6` : '',
        row.pool_capable ? 'Có IPv6 ứng viên; tool vẫn xác minh DAD và Internet trước khi dùng.' : (row.reason || 'Chưa có IPv6 ứng viên cho pool')].filter(Boolean).join(' | ');
}

async function detectSubnets(iface) {
    const container = document.getElementById('subnet-detected');
    const listEl = document.getElementById('subnet-list');

    try {
        const data = await api(`/api/interface-subnets?interface=${encodeURIComponent(iface)}`);

        if (data.subnets && data.subnets.length > 0) {
            container.style.display = 'block';
            listEl.innerHTML = data.subnets.map(s => `
                <div class="subnet-item" data-subnet="${escapeHtml(s.subnet)}" data-prefix="${escapeHtml(s.prefix_len)}" title="Click để sử dụng subnet này">
                    <span class="subnet-icon">🌐</span>
                    <div class="subnet-info">
                        <span class="subnet-addr">${escapeHtml(s.full)}</span>
                    <span class="subnet-source">từ ${escapeHtml(s.source_address)} — ${s.verified === true ? 'đã xác minh Internet' : 'chưa xác minh Internet'}</span>
                    </div>
                    <span class="subnet-use-btn">Sử dụng →</span>
                </div>
            `).join('');

            // Address order does not prove that an old SLAAC prefix still works.
            // Only an explicitly egress-verified result may auto-fill the field.
            const subnetInput = document.getElementById('ipv6-subnet');
            const verifiedSubnet = data.subnets.find(row => row.verified === true);
            if (!subnetInput.value && verifiedSubnet) {
                selectSubnet(verifiedSubnet.subnet, verifiedSubnet.prefix_len);
            }
        } else {
            container.style.display = 'block';
            listEl.innerHTML = '<div class="subnet-empty">⚠️ Không tìm thấy IPv6 subnet global trên interface này</div>';
        }
    } catch (e) {
        console.error('Failed to detect subnets:', e);
        container.style.display = 'none';
    }
}

function selectSubnet(subnet, prefixLen) {
    document.getElementById('ipv6-subnet').value = subnet;

    // Update the netmask radio to match
    const radio = document.querySelector(`input[name="netmask"][value="${prefixLen}"]`);
    if (radio) {
        radio.checked = true;
    }

    // Highlight selected item
    document.querySelectorAll('.subnet-item').forEach(el => el.classList.remove('selected'));
    const items = document.querySelectorAll('.subnet-item');
    items.forEach(el => {
        if (el.querySelector('.subnet-addr').textContent.includes(subnet)) {
            el.classList.add('selected');
        }
    });

    showToast(`Đã chọn subnet: ${subnet}/${prefixLen}`, 'success');
}

// ============ STATUS ============
async function refreshStatus(includeHealth = true) {
    if (statusPollInFlight) return;
    statusPollInFlight = true;
    try {
        const data = await api('/api/status');
        statusNextPollAt = Date.now() + (data.progress?.active ? 2000 : 10000);
        renderStartupRecovery(data);
        renderBuildProgress(data);
        renderNetworkStatus(data);
        renderDashboardHosts(data);
        renderResourceStatus(data);
        await syncCompletedStartupRecovery(data);

        const desiredState = document.getElementById('desired-state');
        if (desiredState) desiredState.textContent = data.desired_state || (data.desired_running ? 'running' : 'stopped');
        renderProcessStatus(data);
        // Update header stats
        document.querySelector('#stat-total .stat-value').textContent = data.total_proxies;

    } catch (e) {
        // Silent fail for status polling
        statusNextPollAt = Date.now() + 10000;
        renderResourceStatus({});
    } finally {
        statusPollInFlight = false;
    }
    if (includeHealth) await refreshHealth();
}

function renderProcessStatus(data) {
    const statusIndicator = document.getElementById('global-status');
    const dot = statusIndicator.querySelector('.status-dot');
    const text = statusIndicator.querySelector('.status-text');
    const runBadge = document.querySelector('#stat-running .stat-value');
    const busy = data.progress?.active === true || data.observation === 'cached_during_mutation';
    const ready = data.proxy_running === true;
    const known = typeof data.proxy_running === 'boolean';
    const live = data.observation === 'live' && !busy && known;
    const observed = data.processes?.observed_at;
    const age = typeof observed === 'number' && Number.isFinite(observed) && observed > 0 && observed <= Date.now() / 1000 + 1 ?
        `${Math.max(0, Math.floor(Date.now() / 1000 - observed))}s trước` : 'chưa có thời điểm quan sát';
    statusIndicator.setAttribute('aria-busy', String(busy));
    if (!live) {
        // A cheap cache read is not a listener check. In particular, startup
        // recovery can stop the old engine while its last observation was ready.
        dot.className = 'status-dot';
        dot.style.background = 'var(--warning)';
        dot.style.boxShadow = 'none';
        const last = known ? (ready ? 'Online' : 'Offline') : 'chưa quan sát';
        text.textContent = busy ? `3proxy: Đang xử lý — cache gần nhất: ${last} (${age}); cần health xác minh` :
            `3proxy: ${last} theo cache (${age}); cần health xác minh`;
        runBadge.textContent = busy ? 'Đang xử lý' : known ? `${last} (cache)` : 'Chưa xác minh';
        runBadge.style.color = 'var(--warning)';
        return;
    }
    dot.style.background = '';
    dot.style.boxShadow = '';
    dot.className = ready ? 'status-dot online' : 'status-dot offline';
    text.textContent = ready ? '3proxy: Online (tất cả instances ready)' : '3proxy: Offline';
    runBadge.textContent = ready ? 'Online' : 'Offline';
    runBadge.style.color = ready ? 'var(--success)' : 'var(--danger)';
}

function resourceInteger(value) {
    return Number.isSafeInteger(value) && value >= 0 ? value : null;
}

function resourceBytes(value) {
    const bytes = resourceInteger(value);
    return bytes === null ? 'Chưa quan sát' : `${(bytes / 1048576).toFixed(1)} MiB`;
}

function renderHostControl(control) {
    const element = document.getElementById('thread-limit-runtime');
    if (!element) return;
    const limit = resourceInteger(control?.effective_limit);
    const suffix = typeof control?.error === 'string' && control.error ? ` | ${control.error}` : '';
    element.textContent = control?.available === true ?
        `Host helper sẵn sàng; trần runtime quan sát: ${limit === null ? 'chưa xác minh' : limit}.${suffix}` :
        control?.available === false ? `Host helper chưa sẵn sàng; chưa xác minh áp dụng trần runtime.${suffix}` :
        'Chưa có quan sát host helper; giá trị lưu không chứng minh trần runtime đã được áp dụng.';
}

function renderResourceStatus(data) {
    const resources = data.metrics?.resources || {};
    const threads = resources.threads || {}, sockets = resources.sockets || {};
    const worker = resources.worker || {}, engine = resources.engine || data.metrics?.proxy_children || {};
    const unavailable = resources.observation === 'unavailable';
    const current = unavailable ? null : resourceInteger(threads.current);
    const limit = unavailable ? null : resourceInteger(threads.limit);
    const denied = unavailable ? null : resourceInteger(threads.events_max_delta);
    const percent = current !== null && limit !== null && limit > 0 ? current * 100 / limit : null;
    const put = (id, text) => {
        const element = document.getElementById(id);
        if (element) element.textContent = text;
        return element;
    };
    const threadValue = put('health-threads', `${current ?? '—'} / ${limit ?? '—'}`);
    const level = denied !== null && denied > 0 || percent !== null && percent >= 90 ? 'critical' :
        percent !== null && percent >= 80 ? 'warning' : percent === null ? 'unavailable' : 'ok';
    if (threadValue) threadValue.style.color = level === 'critical' ? 'var(--danger)' :
        level === 'warning' || level === 'unavailable' ? 'var(--warning)' : 'var(--success)';
    put('health-thread-utilization', percent === null ? 'Chưa quan sát' : `${percent.toFixed(1)}%`);
    put('health-thread-denied', denied === null ? 'Chưa có mẫu so sánh' : `+${denied}`);
    put('health-closewait', unavailable ? '—' : resourceInteger(sockets.close_wait) ?? '—');
    put('health-established', unavailable ? '—' : resourceInteger(sockets.established) ?? '—');
    put('health-timewait', unavailable ? '—' : resourceInteger(sockets.states?.['TIME-WAIT']) ?? '—');
    put('health-fds', unavailable ? 'Chưa quan sát' :
        `Worker ${resourceInteger(worker.fd_count) ?? '—'} · 3proxy ${resourceInteger(engine.fd_count) ?? '—'}`);
    put('health-memory', unavailable ? 'Chưa quan sát' : resourceBytes(engine.rss_bytes));
    const observed = resources.observed_at;
    const knownTime = typeof observed === 'number' && Number.isFinite(observed) && observed > 0 && observed <= Date.now() / 1000 + 1;
    const age = knownTime ? `${Math.max(0, Math.floor(Date.now() / 1000 - observed))}s trước` : 'chưa có thời điểm quan sát';
    put('resource-observation', `Tài nguyên worker: ${resources.cached === true || resources.observation === 'cached' ? 'snapshot cache' : resources.observation === 'live' ? 'snapshot trực tiếp' : 'chưa quan sát'} (${age}). RAM toàn worker: ${unavailable ? 'Chưa quan sát' : resourceBytes(resources.memory?.current_bytes)}. Socket chỉ thuộc port của pool.`);
    const warnings = [];
    if (level === 'critical') warnings.push('NGHIÊM TRỌNG: thread đạt từ 90% trần hoặc có lần cấp thread bị từ chối; kết nối mới có thể phải chờ.');
    else if (level === 'warning') warnings.push('CẢNH BÁO: thread đạt từ 80% trần; theo dõi trước khi mở thêm profile.');
    else if (level === 'unavailable') warnings.push('Chưa đủ số liệu để xác minh mức sử dụng và trần thread.');
    else warnings.push('Thread dưới ngưỡng cảnh báo 80% tại snapshot này.');
    for (const alert of Array.isArray(resources.alerts) ? resources.alerts : []) {
        if (typeof alert?.message === 'string' && alert.message) warnings.push(alert.message);
    }
    warnings.push('Chỉ cảnh báo; dashboard không tự restart hoặc đổi pool.');
    const warning = put('resource-warning', [...new Set(warnings)].join(' '));
    if (warning) warning.style.color = level === 'critical' ? 'var(--danger)' : level === 'ok' ? '' : 'var(--warning)';
    renderHostControl(resources.host_control);
}

async function refreshHealth() {
    if (healthPollInFlight) return;
    healthPollInFlight = true;
    try {
        const health = await api('/api/proxy/health');
        
        // Update instances badge
        const instEl = document.querySelector('#stat-instances .stat-value');
        if (instEl) {
            const running = health.instances_running ? health.instances_running.length : 0;
            const total = health.instances_total || 0;
            instEl.textContent = `${running}/${total}`;
            instEl.style.color = running >= total && total > 0 ? 'var(--success)' : 'var(--warning)';
        }
        
        // Update health panel
        const estEl = document.getElementById('health-established');
        const twEl = document.getElementById('health-timewait');
        const memEl = document.getElementById('health-memory');
        const upEl = document.getElementById('health-uptime');
        
        if (health.metrics?.resources) renderResourceStatus(health);
        else if (estEl) estEl.textContent = health.tcp?.established ?? '-';
        if (twEl) {
            const tw = health.metrics?.resources ? resourceInteger(health.metrics.resources.sockets?.states?.['TIME_WAIT'] ?? health.metrics.resources.sockets?.states?.['TIME-WAIT']) : resourceInteger(health.tcp?.time_wait);
            twEl.textContent = tw ?? '—';
            twEl.style.color = tw === null ? '' : tw > 5000 ? 'var(--danger)' : tw > 1000 ? 'var(--warning)' : 'var(--success)';
        }
        
        if (memEl && !health.metrics?.resources && health.instances_running) {
            const totalMem = health.instances_running.reduce((sum, inst) => sum + (inst.memory_kb || 0), 0);
            memEl.textContent = totalMem > 1024 ? `${(totalMem / 1024).toFixed(1)} MB` : `${totalMem} KB`;
        }
        
        if (upEl && health.system?.uptime_minutes) {
            const min = health.system.uptime_minutes;
            if (min > 60) {
                upEl.textContent = `${(min / 60).toFixed(1)}h`;
            } else {
                upEl.textContent = `${Math.round(min)}m`;
            }
        }
    } catch (e) {
        // Silent fail
    } finally {
        healthPollInFlight = false;
    }
}

function renderBuildProgress(data) {
    const progress = data.progress || {};
    const panel = document.getElementById('build-progress-panel');
    if (!panel) return;
    const integer = value => Number.isFinite(value) ? Math.max(0, Math.floor(value)) : 0;
    const total = integer(progress.total), added = integer(progress.added), ready = integer(progress.ready), verified = integer(progress.verified);
    const stages = {idle: 'Chờ thao tác', queued: 'Đã xếp hàng', discovery: 'Tìm IPv6 gốc', waiting: 'Chờ mạng',
        cleanup: 'Dọn pool cũ', adding: 'Thêm alias', verifying: 'Xác minh DAD / Internet', starting: 'Khởi động 3proxy',
        ready: 'Pool đã sẵn sàng', complete: 'Hoàn tất', stopped: 'Đã dừng', error: 'Lỗi', cancelled: 'Đã hủy', rollback: 'Đang rollback'};
    const stage = typeof progress.stage === 'string' ? progress.stage : 'idle';
    document.getElementById('build-progress-stage').textContent = stages[stage] || stage;
    document.getElementById('build-progress-counts').textContent = `Alias: ${added}/${total} · DAD: ${ready}/${total} · Egress: ${verified}/${total}`;
    const percent = total ? Math.min(100, Math.round(verified * 100 / total)) : 0;
    const fill = document.getElementById('build-progress-fill');
    fill.style.width = `${percent}%`;
    const bar = document.getElementById('build-progress-bar');
    if (typeof bar.setAttribute === 'function') {
        bar.setAttribute('aria-valuenow', String(percent));
        bar.setAttribute('aria-valuetext', `${verified}/${total} IPv6 đã xác minh Internet`);
    }
    const elapsed = Number.isFinite(progress.elapsed_seconds) ? Math.max(0, progress.elapsed_seconds) : 0;
    const update = Number(progress.last_update);
    const age = Number.isFinite(update) && update > 0 ? Math.max(0, Math.floor(Date.now() / 1000 - update)) : null;
    const errors = progress.failed === true ? 1 : integer(progress.failed);
    document.getElementById('build-progress-detail').textContent = [
        `Thời gian: ${Math.floor(elapsed)}s`, age === null ? 'Chưa có heartbeat' : `Heartbeat: ${age}s trước`,
        errors ? `Thất bại: ${errors}` : '', progress.address ? `Địa chỉ: ${progress.address}` : '',
        progress.last_error || ''
    ].filter(Boolean).join(' | ');
    panel.dataset && (panel.dataset.active = String(Boolean(progress.active)));
}

function renderNetworkStatus(data) {
    const access = document.getElementById('dashboard-password-mode');
    if (access && typeof data.dashboard_password_required === 'boolean') {
        access.textContent = data.dashboard_password_required ? 'Dashboard đang yêu cầu mật khẩu đăng nhập.' : 'Dashboard đang mở không yêu cầu mật khẩu đăng nhập.';
    }
    const element = document.getElementById('current-source-status');
    if (!element) return;
    const source = data.current_source;
    element.textContent = source && typeof source === 'object' && source.address ?
        `IPv6 gốc quan sát: ${source.address}${Number.isInteger(source.prefix_len) ? '/' + source.prefix_len : ''} (${source.interface || ''}) — ${data.source_verified === true ? 'đã xác minh Internet' : 'chưa xác minh Internet'}${data.source_error ? ' | ' + data.source_error : ''}` :
        (data.source_error || 'Chưa quan sát được IPv6 gốc trên interface đã lưu.');
}

function validDashboardIPv4(value) {
    if (typeof value !== 'string' || !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(value)) return false;
    const numbers = value.split('.').map(Number);
    return numbers.every(part => part <= 255) && numbers[0] !== 0 && numbers[0] < 224;
}

function renderDashboardHosts(data) {
    const element = document.getElementById('dashboard-access-urls');
    if (!element) return;
    const hosts = [...new Set((Array.isArray(data.dashboard_hosts) ? data.dashboard_hosts : []).filter(validDashboardIPv4))];
    const location = typeof window !== 'undefined' ? window.location : {};
    const scheme = location.protocol === 'https:' ? 'https:' : 'http:';
    const rawPort = data.dashboard_port ?? location.port ?? 7070;
    const port = String(rawPort) === '' ? '' : Number.isInteger(Number(rawPort)) && Number(rawPort) >= 1 && Number(rawPort) <= 65535 ? ':' + Number(rawPort) : ':7070';
    element.innerHTML = hosts.length ? hosts.map(host => {
        const url = `${scheme}//${host}${port}/`;
        const label = Number(host.split('.')[0]) === 127 ? 'Local' : Number(host.split('.')[0]) === 100 && Number(host.split('.')[1]) >= 64 && Number(host.split('.')[1]) <= 127 ? 'Tailscale' : 'LAN';
        return `<a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${label}: ${escapeHtml(url)}</a>`;
    }).join(' · ') : 'Chưa có địa chỉ dashboard LAN/Tailscale trong snapshot mạng.';
}

function renderStartupRecovery(data) {
    const recovery = data.startup_recovery || {};
    const state = recovery.state || 'disabled';
    const labels = {
        disabled: 'Tự tạo lại khi khởi động: đang tắt',
        waiting: 'Đang chờ IPv6 gốc mới có kết nối Internet',
        rebuilding: 'Đang dọn IPv6 do tool tạo và tạo lại proxy',
        ready: 'Khôi phục sau khởi động đã hoàn tất',
        error: 'Khôi phục đang chờ thử lại',
        stopped: 'Đã dừng thủ công — bấm Start để tiếp tục'
    };
    const message = [labels[state] || 'Trạng thái khôi phục', recovery.message].filter(Boolean).join(' — ');
    for (const id of ['startup-recovery-status', 'startup-recovery-tool-status']) {
        const element = document.getElementById(id);
        if (!element) continue;
        element.textContent = message;
        element.style.color = state === 'error' ? 'var(--danger)' :
            ['waiting', 'rebuilding'].includes(state) ? 'var(--warning)' :
            state === 'ready' ? 'var(--success)' : 'var(--text-secondary)';
    }
    const detailText = [
        recovery.base_ipv6 ? `IPv6 gốc đã xác minh: ${recovery.base_ipv6}` : '',
        recovery.subnet ? `Subnet: ${recovery.subnet}${Number.isInteger(recovery.prefix_len) ? '/' + recovery.prefix_len : ''}` : '',
        Number.isInteger(recovery.target_count) ? `Số proxy mục tiêu: ${recovery.target_count}` : ''
    ].filter(Boolean).join(' | ');
    for (const id of ['startup-recovery-detail', 'startup-recovery-tool-detail']) {
        const detail = document.getElementById(id);
        if (detail) detail.textContent = detailText;
    }
}

async function syncCompletedStartupRecovery(data) {
    const recovery = data.startup_recovery || {};
    const completedAt = recovery.completed_at;
    if (recovery.state !== 'ready' || !Number.isFinite(completedAt) || completedAt <= 0 ||
        completedAt === lastStartupRecoveryCompletedAt) return;
    if (startupRecoveryRefreshInFlight) return;
    startupRecoveryRefreshInFlight = (async () => {
        const before = currentSettings;
        const subnetInput = document.getElementById('ipv6-subnet');
        const previousSubnet = subnetInput.value;
        const previousPrefix = document.querySelector('input[name="netmask"]:checked')?.value;
        const [settings, proxiesLoaded] = await Promise.all([api('/api/settings'), loadProxies()]);
        if (proxiesLoaded === false) throw new Error('Chưa tải được danh sách proxy mới');
        currentSettings = settings;
        // A status refresh must not overwrite a user's in-progress settings edits.
        // In particular startup_proxy_count may already contain the next desired count.
        const selectedInterface = document.getElementById('interface-select').value;
        if (document.activeElement !== subnetInput && subnetInput.value === previousSubnet &&
            previousSubnet === (before.subnet || '') && selectedInterface === settings.interface &&
            settings.subnet === recovery.subnet && recovery.base_ipv6) {
            subnetInput.value = settings.subnet;
            if (previousPrefix === String(before.prefix_len || 64) &&
                document.querySelector('input[name="netmask"]:checked')?.value === previousPrefix) {
                const radio = document.querySelector(`input[name="netmask"][value="${settings.prefix_len}"]`);
                if (radio && document.activeElement !== radio) radio.checked = true;
            }
        }
        lastStartupRecoveryCompletedAt = completedAt;
    })();
    try {
        await startupRecoveryRefreshInFlight;
    } catch (error) {
        for (const id of ['startup-recovery-detail', 'startup-recovery-tool-detail']) {
            const detail = document.getElementById(id);
            if (detail) detail.textContent += ` | Đang chờ tải lại danh sách: ${error.message}`;
        }
    } finally {
        startupRecoveryRefreshInFlight = null;
    }
}

// ============ GENERATE PROXIES ============
async function generateProxies() {
    if (generationInFlight) return;
    const btn = document.getElementById('btn-generate');
    const statusMsg = document.getElementById('status-message');

    // Collect form data
    const subnet = document.getElementById('ipv6-subnet').value.trim();
    const count = Number(document.getElementById('proxy-count').value);
    const startPort = Number(document.getElementById('start-port').value);
    const iface = document.getElementById('interface-select').value;
    const username = document.getElementById('auth-user').value.trim();
    const password = document.getElementById('auth-pass').value.trim();
    const noAuth = document.getElementById('opt-no-auth').checked;
    // Empty form fields are an explicit no-auth choice, not omitted API fields
    // that would silently reuse accounts from the old pool.
    const authType = noAuth ? 'none' : currentSettings.auth_type === 'ip' ? 'ip' :
        !username && !password ? 'none' : 'userpass';
    const noRotate = document.getElementById('opt-no-rotate').checked;
    const publicProxy = authType === 'none' || document.getElementById('opt-public').checked;
    const recreate = document.getElementById('opt-recreate').checked;
    const autoStart = document.getElementById('opt-autostart').checked;
    const rotationInterval = Number(document.getElementById('rotation-interval').value);

    const prefixLen = parseInt(document.querySelector('input[name="netmask"]:checked')?.value || 64);
    const protocol = document.querySelector('input[name="protocol"]:checked')?.value || 'http';

    // Validate
    if (!subnet) {
        showToast('Vui lòng nhập IPv6 Subnet!', 'warning');
        document.getElementById('ipv6-subnet').focus();
        return;
    }
    if (!Number.isInteger(count) || count < 1 || count > 10000) {
        showToast('Số proxy phải là số nguyên từ 1 đến 10000!', 'warning');
        return;
    }

    if (count * (protocol === 'dual' ? 2 : 1) > 1024) {
        showToast('Tối đa 1024 dịch vụ (512 proxy dual)!', 'warning'); return;
    }
    if (!['http', 'socks5', 'dual'].includes(protocol) || !Number.isInteger(startPort) || startPort < 1024 || startPort + count - 1 + (protocol === 'dual' ? 10000 : 0) > 65535) {
        showToast('Protocol hoặc dải port không hợp lệ!', 'warning');
        return;
    }
    if (!Number.isInteger(rotationInterval) || rotationInterval < 1 || rotationInterval > 10080) {
        showToast('Rotation interval phải là số nguyên 1..10080 phút', 'warning'); return;
    }
    if (authType === 'userpass' && (!username || !password)) {
        showToast('Vui lòng nhập cả username và password, hoặc để trống cả hai để không dùng tài khoản.', 'warning');
        return;
    }
    if (authType === 'userpass' && !validCredentials(username, password)) {
        showToast('Username/password không hợp lệ: ASCII, không space/control hoặc : $ \" \\ # trong password', 'warning');
        return;
    }
    if (recreate && !confirm('Thay thế toàn bộ proxy cũ? Worker sẽ rollback nếu kiểm tra mới thất bại.')) return;
    if (authType === 'none' && !confirm('Tài khoản/mật khẩu để trống: tạo proxy không yêu cầu đăng nhập, giữ nguyên listener và ACL đích?')) return;

    // UI loading state
    generationInFlight = true;
    statusNextPollAt = 0;
    btn.disabled = true;
    btn.classList.add('btn-loading');
    btn.innerHTML = '<span class="spinner"></span> ĐANG TẠO PROXY...';
    statusMsg.textContent = 'Đang tạo proxy...';
    refreshStatus(false);

    try {
        const result = await api('/api/proxies/generate', {
            method: 'POST',
            body: JSON.stringify({
                subnet, prefix_len: prefixLen, count, start_port: startPort,
                protocol, interface: iface, recreate,
                ...(authType === 'ip' ? {} : { username: authType === 'none' ? '' : username,
                    password: authType === 'none' ? '' : password }),
                auth_type: authType,
                rotation_enabled: !noRotate, rotation_interval: rotationInterval,
                public_proxy: publicProxy, auto_start: autoStart, start: true,
                topology_mode: document.getElementById('topology-mode').value,
                routed_prefix: document.getElementById('routed-prefix').value.trim(),
                listener_ipv4: document.getElementById('listener-ipv4').value.trim(),
                allowed_ips: document.getElementById('allowed-ips').value.split(/[\n,]+/).map(v => v.trim()).filter(Boolean),
                probe_url: document.getElementById('probe-url').value.trim(),
                max_connections: Number(document.getElementById('max-conn').value)
            })
        });

        if (result.success) {
            const protoLabel = protocol === 'dual' ? 'Dual (HTTP+SOCKS5)' : protocol.toUpperCase();
            showToast(`Đã tạo ${result.generated} ${protoLabel} proxy!`, 'success');
            statusMsg.textContent = `✅ Đã tạo ${result.generated} proxy thành công!${authType === 'none' ? ' Không yêu cầu tài khoản/mật khẩu.' : ''}`;
        } else {
            showToast(result.error || 'Lỗi tạo proxy', 'error');
            statusMsg.textContent = `❌ Lỗi: ${result.error}`;
        }

        // The worker applies and verifies the operation transactionally.

        // Refresh data
        refreshStatus();
        loadProxies();

    } catch (e) {
        statusMsg.textContent = '❌ Lỗi tạo proxy!';
        showToast('Lỗi tạo proxy: ' + e.message, 'error');
    }

    // Reset button
    btn.classList.remove('btn-loading');
    btn.disabled = false;
    generationInFlight = false;
    btn.innerHTML = '<span class="btn-icon">🚀</span> BẮT ĐẦU CHẠY PROXY';
}

async function logout() {
    try {
        const csrf = await api('/api/csrf');
        const response = await fetch('/logout', {
            method: 'POST', credentials: 'same-origin',
            headers: {'X-CSRF-Token': csrf.csrf_token, 'Idempotency-Key': idempotencyKey()}
        });
        if (!response.ok) throw new Error('Đăng xuất thất bại');
        csrfToken = null;
        window.location.assign('/login');
    } catch (error) { showToast(error.message, 'error'); }
}

// ============ PROXY CONTROL ============
async function startProxy() {
    statusNextPollAt = 0;
    try {
        const result = await api('/api/proxy/start', { method: 'POST' });
        showToast(result.message, result.success ? 'success' : 'error');
        refreshStatus();
    } catch (e) {
        showToast('Lỗi khởi động proxy', 'error');
    }
}

async function stopProxy() {
    statusNextPollAt = 0;
    const feedback = document.getElementById('status-message');
    if (feedback) feedback.textContent = 'Đang gửi yêu cầu Stop; tác vụ kiểm tra đang chạy sẽ kết thúc trước khi dọn alias.';
    try {
        const result = await api('/api/proxy/stop', { method: 'POST' });
        showToast(result.message, result.success ? 'success' : 'error');
        refreshStatus();
    } catch (e) {
        showToast('Lỗi dừng proxy: ' + e.message, 'error');
    }
}

async function restartProxy() {
    try {
        const result = await api('/api/proxy/restart', { method: 'POST' });
        showToast(result.message, result.success ? 'success' : 'error');
        refreshStatus();
    } catch (e) {
        showToast('Lỗi restart proxy', 'error');
    }
}

// ============ PROXY LIST ============
async function loadProxies() {
    try {
        const data = await api('/api/proxies');
        allProxies = data.proxies || [];
        renderProxyTable(allProxies);
        return true;
    } catch (e) {
        console.error('Failed to load proxies:', e);
        return false;
    }
}

function renderProxyTable(proxies) {
    const tbody = document.getElementById('proxy-tbody');
    const countEl = document.getElementById('table-count');

    if (proxies.length === 0) {
        tbody.innerHTML = `
            <tr class="empty-row">
                <td colspan="9">
                    <div class="empty-state">
                        <span class="empty-icon">📡</span>
                        <p>Chưa có proxy nào. Hãy tạo proxy mới!</p>
                    </div>
                </td>
            </tr>
        `;
        countEl.textContent = '0 proxy';
        return;
    }

    tbody.innerHTML = proxies.map((p, i) => {
        const isDual = p.protocol === 'dual';
        const protocolBadge = isDual
            ? '<span class="badge badge-dual">DUAL</span>'
            : `<span class="badge badge-${['http', 'socks5'].includes(p.protocol) ? p.protocol : 'inactive'}">${escapeHtml(String(p.protocol).toUpperCase())}</span>`;
        
        const httpPort = isDual ? `<strong>${escapeHtml(p.port)}</strong>` : `<strong>${escapeHtml(p.port)}</strong>`;
        const socksPort = isDual && p.socks_port ? `<strong>${escapeHtml(p.socks_port)}</strong>` : '<span style="color:var(--text-muted)">-</span>';

        return `
            <tr>
                <td class="th-check"><input type="checkbox" class="proxy-check" data-id="${escapeHtml(p.id)}"></td>
                <td>${i + 1}</td>
                <td class="ipv6-cell" title="${escapeHtml(p.ipv6)}">${escapeHtml(truncateIPv6(p.ipv6))}</td>
                <td>${httpPort}</td>
                <td>${socksPort}</td>
                <td>${protocolBadge}</td>
                <td><span class="badge badge-${p.status === 'active' ? 'active' : 'inactive'}">${escapeHtml(p.status || 'Active')}</span></td>
                <td>${escapeHtml(p.created_at || '-')}</td>
                <td class="action-cell">
                    <button class="btn-rotate-row" data-proxy-action="rotate" data-proxy-id="${escapeHtml(p.id)}" title="Đổi IPv6 mới">🔄</button>
                    <button class="btn-delete-row" data-proxy-action="delete" data-proxy-id="${escapeHtml(p.id)}" title="Xóa proxy">🗑️</button>
                </td>
            </tr>
        `;
    }).join('');

    countEl.textContent = `${proxies.length} proxy`;
}

function truncateIPv6(addr) {
    if (!addr) return '-';
    if (addr.length > 30) {
        return addr.substring(0, 25) + '...';
    }
    return addr;
}

function filterProxies() {
    const search = document.getElementById('search-proxy').value.toLowerCase();
    const protocol = document.getElementById('filter-protocol').value;

    let filtered = allProxies;

    if (search) {
        filtered = filtered.filter(p =>
            p.ipv6.toLowerCase().includes(search) ||
            String(p.port).includes(search)
        );
    }

    if (protocol !== 'all') {
        filtered = filtered.filter(p => p.protocol === protocol);
    }

    renderProxyTable(filtered);
}

function refreshProxyList() {
    loadProxies();
    showToast('Đã refresh danh sách proxy', 'info');
}

function toggleCheckAll() {
    const checked = document.getElementById('check-all').checked;
    document.querySelectorAll('.proxy-check').forEach(cb => cb.checked = checked);
}

async function deleteProxy(id) {
    if (!confirm('Bạn có chắc muốn xóa proxy này?')) return;

    try {
        const result = await api(`/api/proxies/${id}`, { method: 'DELETE' });
        if (result.success) {
            showToast('Đã xóa proxy', 'success');
            loadProxies();
            refreshStatus();
        }
    } catch (e) {
        showToast('Lỗi xóa proxy', 'error');
    }
}

async function rotateProxy(id) {
    const btn = document.querySelector(`button[data-proxy-action="rotate"][data-proxy-id="${id}"]`);
    if (btn) {
        btn.classList.add('btn-loading');
        btn.innerHTML = '<span class="spinner-sm"></span>';
    }

    try {
        const result = await api(`/api/proxies/${id}/rotate`, { method: 'POST' });
        if (result.success) {
            showToast(`Port ${result.port}: Đã đổi IPv6 mới!`, 'success');
            loadProxies();
        } else {
            showToast(result.error || 'Lỗi đổi IPv6', 'error');
        }
    } catch (e) {
        showToast('Lỗi đổi IPv6: ' + e.message, 'error');
    }

    if (btn) {
        btn.classList.remove('btn-loading');
        btn.innerHTML = '🔄';
    }
}

async function deleteAllProxies() {
    if (!confirm('⚠️ Bạn có chắc muốn xóa TẤT CẢ proxy? Hành động này không thể hoàn tác!')) return;

    try {
        const result = await api('/api/proxies/delete-all', { method: 'POST' });
        if (result.success) {
            showToast('Đã xóa tất cả proxy', 'success');
            loadProxies();
            refreshStatus();
        }
    } catch (e) {
        showToast('Lỗi xóa proxy', 'error');
    }
}

// ============ EXPORT ============
async function exportProxies(format) {
    try {
        const protocolFilter = document.getElementById('export-protocol-filter')?.value || 'all';
        const result = await api(`/api/proxies/export?format=${format}&export_protocol=${protocolFilter}`);
        if (result.success && result.count > 0) {
            document.getElementById('export-content').value = result.content;
            document.getElementById('export-modal').classList.add('active');
        } else {
            showToast('Không có proxy để export', 'warning');
        }
    } catch (e) {
        showToast('Lỗi export', 'error');
    }
}

function closeExportModal() {
    document.getElementById('export-modal').classList.remove('active');
}

function copyExport() {
    const textarea = document.getElementById('export-content');
    textarea.select();
    navigator.clipboard.writeText(textarea.value).then(() => {
        showToast('Đã copy vào clipboard!', 'success');
    }).catch(() => {
        document.execCommand('copy');
        showToast('Đã copy!', 'success');
    });
}

function downloadExport() {
    const content = document.getElementById('export-content').value;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'proxy_list.txt';
    a.click();
    URL.revokeObjectURL(url);
    showToast('Đã download file proxy_list.txt', 'success');
}

// ============ USER MANAGEMENT ============
async function loadUsers() {
    try {
        const data = await api('/api/users');
        allUsers = data.users || [];
        renderUserList(allUsers);
    } catch (e) {
        console.error('Failed to load users:', e);
    }
}

function renderUserList(users) {
    const list = document.getElementById('user-list');

    if (users.length === 0) {
        list.innerHTML = `
            <div class="empty-state">
                <span class="empty-icon">👤</span>
                <p>Chưa có user nào</p>
            </div>
        `;
        return;
    }

    list.innerHTML = users.map(u => `
        <div class="user-item">
            <div class="user-info">
                <div class="user-avatar">${escapeHtml(u.username.charAt(0).toUpperCase())}</div>
                <div>
                    <div class="user-name">${escapeHtml(u.username)}</div>
                    <div class="user-date">Tạo: ${escapeHtml(u.created_at || '-')}</div>
                </div>
            </div>
            <button class="btn-delete-row" data-delete-user="${escapeHtml(u.username)}">🗑️</button>
        </div>
    `).join('');
}

async function addUser() {
    const username = document.getElementById('new-username').value.trim();
    const password = document.getElementById('new-password').value.trim();

    if (!validCredentials(username, password)) {
        showToast('Vui lòng nhập đầy đủ username và password!', 'warning');
        return;
    }

    try {
        const result = await api('/api/users', {
            method: 'POST',
            body: JSON.stringify({ username, password })
        });

        if (result.success) {
            showToast(`Đã thêm user: ${username}`, 'success');
            document.getElementById('new-username').value = '';
            document.getElementById('new-password').value = '';
            loadUsers();
        } else {
            showToast(result.error || 'Lỗi thêm user', 'error');
        }
    } catch (e) {
        showToast('Lỗi thêm user', 'error');
    }
}

async function deleteUser(username) {
    if (!confirm(`Xóa user "${username}"?`)) return;

    try {
        const result = await api(`/api/users/${encodeURIComponent(username)}`, { method: 'DELETE' });
        if (result.success) {
            showToast(`Đã xóa user: ${username}`, 'success');
            loadUsers();
        }
    } catch (e) {
        showToast('Lỗi xóa user', 'error');
    }
}

async function updateAuthType(value) {
    try {
        await api('/api/settings', {
            method: 'POST',
            body: JSON.stringify({ auth_type: value })
        });
        await loadSettings();
        showToast(`Đã chuyển auth sang: ${value}`, 'info');
    } catch (e) {
        showToast('Lỗi cập nhật auth: ' + e.message, 'error');
    }
}

// ============ TOOLS ============
async function saveStartupRecoverySettings() {
    const enabled = document.getElementById('startup-rebuild-enabled').checked;
    const count = Number(document.getElementById('startup-proxy-count').value);
    const feedback = document.getElementById('startup-recovery-save-status');
    const button = document.getElementById('btn-save-startup-recovery');
    if (!Number.isInteger(count) || count < 1 || count > 1024) {
        feedback.textContent = 'Số proxy phải là số nguyên từ 1 đến 1024.';
        showToast(feedback.textContent, 'warning');
        document.getElementById('startup-proxy-count').focus();
        return;
    }
    button.disabled = true;
    feedback.textContent = 'Đang lưu cấu hình khôi phục...';
    try {
        const result = await api('/api/settings', {
            method: 'POST',
            body: JSON.stringify({startup_rebuild_enabled: enabled, startup_proxy_count: count})
        });
        currentSettings = {...currentSettings, ...(result.settings || {}),
            startup_rebuild_enabled: enabled, startup_proxy_count: count};
        feedback.textContent = enabled
            ? `Đã lưu: tạo lại ${count} proxy ở lần khởi động worker tiếp theo; Stop thủ công chỉ tiếp tục khi bấm Start.`
            : 'Đã tắt tự tạo lại proxy khi khởi động.';
        showToast('Đã lưu cấu hình khôi phục sau khởi động!', 'success');
    } catch (error) {
        feedback.textContent = `Lưu cấu hình thất bại: ${error.message}`;
        showToast(feedback.textContent, 'error');
    } finally {
        button.disabled = false;
    }
}

async function saveDNS() {
    const dns1 = document.getElementById('dns1').value.trim();
    const dns2 = document.getElementById('dns2').value.trim();

    try {
        await api('/api/settings', {
            method: 'POST',
            body: JSON.stringify({ dns1, dns2 })
        });
        showToast('Đã lưu DNS settings!', 'success');
    } catch (e) {
        showToast('Lỗi lưu DNS: ' + e.message, 'error');
    }
}

async function saveSourceChangeSettings() {
    const value = Number(document.getElementById('source-change-confirmations').value);
    const interval = Number(document.getElementById('source-poll-interval').value);
    if (!Number.isInteger(value) || value < 1 || value > 10) {
        showToast('Số lần xác nhận prefix phải là số nguyên 1..10', 'warning');
        return;
    }
    if (!Number.isInteger(interval) || interval < 2 || interval > 300) {
        showToast('Chu kỳ quan sát prefix phải là số nguyên 2..300 giây', 'warning');
        return;
    }
    const button = document.getElementById('btn-save-source-change');
    button.disabled = true;
    try {
        await api('/api/settings', {method: 'POST', body: JSON.stringify({source_change_confirmations: value, source_poll_interval: interval})});
        showToast(`Đã lưu: xác nhận prefix mới ${value} lần trước khi đổi pool`, 'success');
    } catch (error) {
        showToast('Lỗi lưu xác nhận prefix: ' + error.message, 'error');
    } finally {
        button.disabled = false;
    }
}

async function changeDashboardPassword() {
    const current = document.getElementById('dashboard-current-password');
    const next = document.getElementById('dashboard-new-password');
    const confirm = document.getElementById('dashboard-confirm-password');
    const feedback = document.getElementById('dashboard-password-status');
    const button = document.getElementById('btn-change-dashboard-password');
    if (next.value !== confirm.value) { feedback.textContent = 'Xác nhận mật khẩu mới chưa khớp.'; return; }
    if (button.disabled) return;
    button.disabled = true;
    feedback.textContent = 'Đang xác minh và lưu mật khẩu dashboard...';
    try {
        const response = await api('/api/password', {method: 'POST', body: JSON.stringify({
            current_password: current.value, new_password: next.value, confirm_password: confirm.value
        })});
        const changed = response.changed === true && response.requires_login === true;
        const unchanged = response.changed === false && response.requires_login === false && response.unchanged === true;
        if (!changed && !unchanged) throw new Error('Worker chưa xác nhận đổi mật khẩu');
        const passwordDisabled = next.value === '';
        current.value = next.value = confirm.value = '';
        if (unchanged) {
            feedback.textContent = 'Mật khẩu đang giữ nguyên; pool và tài khoản proxy không thay đổi.';
            return;
        }
        csrfToken = null;
        feedback.textContent = passwordDisabled ? 'Đã tắt yêu cầu mật khẩu dashboard; pool proxy vẫn giữ nguyên.' :
            'Đã đổi mật khẩu. Đăng nhập lại bằng mật khẩu mới; pool proxy vẫn giữ nguyên.';
        window.location.assign(passwordDisabled ? '/' : '/login?password_changed=1');
    } catch (error) {
        feedback.textContent = 'Đổi mật khẩu thất bại: ' + error.message;
    } finally {
        button.disabled = false;
    }
}

async function saveConnectionSettings() {
    const maxConn = Number(document.getElementById('max-conn').value);
    const timeoutConnect = Number(document.getElementById('timeout-connect').value);
    const timeoutIdle = Number(document.getElementById('timeout-idle').value);

    if (!Number.isInteger(maxConn) || maxConn < 1 || maxConn > 10000 || !Number.isInteger(timeoutConnect) || timeoutConnect < 1 || timeoutConnect > 120 || !Number.isInteger(timeoutIdle) || timeoutIdle < 1 || timeoutIdle > 86400) {
        showToast('Maxconn 1..10000, connect 1..120, idle 1..86400; tất cả phải là số nguyên', 'warning'); return;
    }
    try {
        await api('/api/settings', {
            method: 'POST',
            body: JSON.stringify({
                max_connections: maxConn,
                timeout_connect: timeoutConnect,
                timeout_idle: timeoutIdle
            })
        });
        showToast('Đã lưu cấu hình kết nối!', 'success');
    } catch (e) {
        showToast('Lỗi lưu cấu hình: ' + e.message, 'error');
    }
}

async function saveThreadLimitSettings() {
    if (threadSettingsInFlight) return;
    const input = document.getElementById('thread-limit');
    const feedback = document.getElementById('thread-limit-save-status');
    const button = document.getElementById('btn-save-thread-limit');
    const limit = Number(input.value);
    if (!Number.isSafeInteger(limit) || limit < 256 || limit > 16384) {
        feedback.textContent = 'Trần thread phải là số nguyên trong khoảng 256..16384.';
        return;
    }
    threadSettingsInFlight = true;
    button.disabled = true;
    feedback.textContent = 'Đang lưu trần thread và xác minh host helper...';
    try {
        // This independent patch must not submit maxconn/timeouts or restart settings.
        const result = await api('/api/settings', {method: 'POST', body: JSON.stringify({thread_limit: limit})});
        if (result.success === false) throw new Error(result.error || 'Lưu trần thread thất bại');
        currentSettings = {...currentSettings, ...(result.settings || {}), thread_limit: limit};
        if (result.changed === false) {
            // A no-op confirms saved settings, not the currently effective cgroup limit.
            feedback.textContent = `Cấu hình không thay đổi (${limit} thread đã lưu); trần thực tế xem telemetry phía trên.`;
            statusNextPollAt = 0;
            return;
        }
        const control = result.resources?.host_control || result.metrics?.resources?.host_control || result.host_control ||
            (result.thread_limit_applied === true ? {available: true, effective_limit: result.effective_thread_limit} : null);
        renderHostControl(control);
        feedback.textContent = result.thread_limit_applied === true && resourceInteger(result.effective_thread_limit) === limit && result.restarted === false ?
            `Đã lưu và xác minh trần runtime ${limit} thread; pool giữ nguyên, không restart.` :
            `Đã lưu trần ${limit} thread; chưa xác minh áp dụng runtime. Xem trạng thái host helper phía trên.`;
        statusNextPollAt = 0;
    } catch (error) {
        feedback.textContent = 'Lưu trần thread thất bại: ' + error.message;
    } finally {
        threadSettingsInFlight = false;
        button.disabled = false;
    }
}

async function saveTelegramSettings() {
    const token = document.getElementById('telegram-token').value.trim();
    const chatId = document.getElementById('telegram-chat-id').value.trim();

    try {
        await api('/api/settings', {
            method: 'POST',
            body: JSON.stringify({
                ...(token ? { telegram_bot_token: token } : {}),
                telegram_chat_id: chatId,
                telegram_allowed_user_ids: document.getElementById('telegram-allowed-user-ids').value.split(/[,\s]+/).filter(Boolean).map(Number)
            })
        });
        document.getElementById('telegram-token').value = '';
        showToast('Đã lưu cấu hình Telegram!', 'success');
    } catch (e) {
        showToast('Lỗi lưu cấu hình Telegram: ' + e.message, 'error');
    }
}

async function testTelegram() {
    try {
        const result = await api('/api/telegram/test', { method: 'POST' });
        if (result.success) {
            showToast('Đã gửi tin nhắn test thành công!', 'success');
        } else {
            showToast(result.error || 'Lỗi gửi tin nhắn', 'error');
        }
    } catch (e) {
        showToast('Lỗi kết nối API Telegram', 'error');
    }
}

async function refreshIPv6Info() {
    const infoEl = document.getElementById('ipv6-info');

    try {
        const iface = document.getElementById('interface-select')?.value || 'eth0';
        const data = await api(`/api/ipv6-addresses?interface=${encodeURIComponent(iface)}`);

        if (data.addresses && data.addresses.length > 0) {
            const lines = data.addresses.map(a =>
                `${a.address} (${a.interface}, scope: ${a.scope}; ${a.origin === 'managed' ? 'pool do tool quản lý' : a.origin === 'uncertain' ? 'chờ xác minh quyền quản lý' : a.origin === 'system' ? 'IPv6 hệ thống' : 'chưa có dữ liệu phân loại'})`
            );
            infoEl.innerHTML = `<p><strong>Toàn bộ IPv6 trên ${escapeHtml(iface)} (bao gồm pool; không phải danh sách IPv6 gốc):</strong></p>` +
                lines.map(l => `<p style="margin-left:8px; color: var(--accent-secondary);">• ${escapeHtml(l)}</p>`).join('');
        } else {
            infoEl.innerHTML = '<p style="color: var(--text-muted);">Không tìm thấy IPv6 address</p>';
        }
    } catch (e) {
        infoEl.innerHTML = '<p style="color: var(--danger);">Lỗi lấy thông tin IPv6</p>';
    }
}

async function cleanupIPv6() {
    if (!confirm('🧹 Xóa tất cả IPv6 cũ không còn sử dụng?\n\n(Giữ lại IP hệ thống và proxy đang hoạt động)')) return;

    const resultEl = document.getElementById('cleanup-result');
    resultEl.style.display = 'block';
    resultEl.innerHTML = '<p style="color: var(--warning);">🔄 Đang dọn dẹp...</p>';

    try {
        const data = await api('/api/cleanup-ipv6', { method: 'POST' });
        if (data.success) {
            resultEl.innerHTML = `<p style="color: var(--success);">✅ ${escapeHtml(data.message)}</p>`;
            showToast(data.message, 'success');
            refreshIPv6Info();
        } else {
            resultEl.innerHTML = `<p style="color: var(--danger);">❌ Lỗi: ${escapeHtml(data.error)}</p>`;
            showToast('Lỗi dọn dẹp IPv6', 'error');
        }
    } catch (e) {
        resultEl.innerHTML = `<p style="color: var(--danger);">❌ Lỗi kết nối</p>`;
        showToast('Lỗi dọn dẹp IPv6', 'error');
    }
}

async function testProxy() {
    const proxy = document.getElementById('test-proxy').value.trim();
    const url = document.getElementById('test-url').value.trim();
    const resultEl = document.getElementById('test-result');

    if (!proxy) {
        showToast('Vui lòng nhập proxy!', 'warning');
        return;
    }

    resultEl.className = 'test-result';
    resultEl.style.display = 'block';
    resultEl.textContent = '🔄 Đang test...';
    resultEl.style.background = 'var(--warning-bg)';
    resultEl.style.borderColor = 'rgba(255, 183, 77, 0.3)';
    resultEl.style.color = 'var(--warning)';

    // Note: Actual proxy testing requires server-side implementation
    showToast('Test proxy cần thực hiện từ server terminal: curl -x ' + proxy + ' ' + url, 'info');

    resultEl.className = 'test-result info';
    resultEl.textContent = `💡 Chạy lệnh trên server:\ncurl -x ${proxy} ${url}`;
    resultEl.style.display = 'block';
    resultEl.style.background = 'rgba(79, 195, 247, 0.1)';
    resultEl.style.borderColor = 'rgba(79, 195, 247, 0.2)';
    resultEl.style.color = 'var(--info)';
}

// ============ LOGS ============
async function refreshLogs() {
    try {
        const data = await api('/api/logs?lines=200');
        const content = document.getElementById('log-content');
        content.textContent = data.logs || 'No logs available.';
        // Scroll to bottom
        content.scrollTop = content.scrollHeight;
    } catch (e) {
        document.getElementById('log-content').textContent = 'Lỗi tải logs.';
    }
}

// ============ SPEED TEST ============
function onSpeedtestUrlChange() {
    const select = document.getElementById('speedtest-url');
    const customGroup = document.getElementById('speedtest-custom-url-group');
    customGroup.style.display = select.value === 'custom' ? 'flex' : 'none';
}

function getSpeedtestUrl() {
    const select = document.getElementById('speedtest-url');
    if (select.value === 'custom') {
        return document.getElementById('speedtest-custom-url').value.trim() || 'https://www.bing.com';
    }
    return select.value;
}

function formatTime(seconds) {
    if (seconds === undefined || seconds === null) return '-';
    if (seconds < 0.001) return '<1ms';
    if (seconds < 1) return `${Math.round(seconds * 1000)}ms`;
    return `${seconds.toFixed(2)}s`;
}

function getSpeedRating(totalTime) {
    if (totalTime <= 1) return { text: '⚡ Rất nhanh', class: 'speed-fast' };
    if (totalTime <= 3) return { text: '✅ Tốt', class: 'speed-good' };
    if (totalTime <= 5) return { text: '⚠️ Trung bình', class: 'speed-medium' };
    if (totalTime <= 10) return { text: '🐌 Chậm', class: 'speed-slow' };
    return { text: '❌ Rất chậm', class: 'speed-very-slow' };
}

async function runSingleSpeedtest() {
    const btn = document.getElementById('btn-speedtest-single');
    const resultDiv = document.getElementById('speedtest-single-result');
    const port = parseInt(document.getElementById('speedtest-port').value);
    const targetUrl = getSpeedtestUrl();

    btn.classList.add('btn-loading');
    btn.innerHTML = '<span class="spinner"></span> Đang test...';
    resultDiv.style.display = 'none';

    try {
        const data = await api('/api/proxy/speedtest', {
            method: 'POST',
            body: JSON.stringify({
                proxy_host: '127.0.0.1',
                proxy_port: port,
                target_url: targetUrl,
                proxy_protocol: 'http'
            })
        });

        resultDiv.style.display = 'block';

        if (data.success) {
            document.getElementById('st-dns').textContent = formatTime(data.dns_lookup);
            document.getElementById('st-connect').textContent = formatTime(data.tcp_connect);
            document.getElementById('st-tls').textContent = formatTime(data.tls_handshake);
            document.getElementById('st-ttfb').textContent = formatTime(data.ttfb);
            document.getElementById('st-total').textContent = formatTime(data.total_time);
            document.getElementById('st-speed').textContent = formatTransferRate(data);
            document.getElementById('st-code').textContent = data.http_code || '-';
            document.getElementById('st-remote-ip').textContent = data.proxy_peer_ip || data.remote_ip || '-';

            // Color code based on speed
            const rating = getSpeedRating(data.total_time);
            document.getElementById('st-total').className = `timing-value ${rating.class}`;

            // Render timing bar
            renderTimingBar(data);

            showToast(`${rating.text} - Total: ${formatTime(data.total_time)}`, 'success');
        } else {
            document.getElementById('st-dns').textContent = '-';
            document.getElementById('st-connect').textContent = '-';
            document.getElementById('st-tls').textContent = '-';
            document.getElementById('st-ttfb').textContent = '-';
            document.getElementById('st-total').textContent = 'FAILED';
            document.getElementById('st-total').className = 'timing-value speed-very-slow';
            document.getElementById('st-speed').textContent = '-';
            document.getElementById('st-code').textContent = '-';
            document.getElementById('st-remote-ip').textContent = data.error || 'Error';
            document.getElementById('timing-bar-container').style.display = 'none';

            showToast(`Test thất bại: ${data.error}`, 'error');
        }
    } catch (e) {
        showToast('Lỗi kết nối: ' + e.message, 'error');
    }

    btn.classList.remove('btn-loading');
    btn.innerHTML = '🚀 Test Proxy';
}

function formatTransferRate(data) {
    const kib = Number(data.speed_kbps || 0);
    const mbps = Number(data.speed_mbps ?? (kib * 1024 * 8 / 1000000));
    return `${Number.isFinite(kib) ? kib : 0} KiB/s (${Number.isFinite(mbps) ? mbps.toFixed(3) : '0.000'} Mbps)`;
}

function renderTimingBar(data) {
    const container = document.getElementById('timing-bar-container');
    if (!data.total_time || data.total_time <= 0) {
        container.style.display = 'none';
        return;
    }

    container.style.display = 'block';
    const total = data.total_time;

    const dnsTime = data.dns_lookup || 0;
    const connectTime = (data.tcp_connect || 0) - dnsTime;
    const tlsTime = (data.tls_handshake || 0) - (data.tcp_connect || 0);
    const ttfbTime = (data.ttfb || 0) - (data.tls_handshake || data.tcp_connect || 0);
    const downloadTime = total - (data.ttfb || 0);

    document.getElementById('bar-dns').style.width = `${Math.max((dnsTime / total) * 100, 0.5)}%`;
    document.getElementById('bar-connect').style.width = `${Math.max((connectTime / total) * 100, 0.5)}%`;
    document.getElementById('bar-tls').style.width = `${Math.max((tlsTime / total) * 100, 0.5)}%`;
    document.getElementById('bar-ttfb').style.width = `${Math.max((ttfbTime / total) * 100, 0.5)}%`;
    document.getElementById('bar-download').style.width = `${Math.max((downloadTime / total) * 100, 0.5)}%`;

    // Update tooltips
    document.getElementById('bar-dns').title = `DNS: ${formatTime(dnsTime)}`;
    document.getElementById('bar-connect').title = `Connect: ${formatTime(connectTime)}`;
    document.getElementById('bar-tls').title = `CONNECT/TLS: ${formatTime(tlsTime)}`;
    document.getElementById('bar-ttfb').title = `TTFB: ${formatTime(ttfbTime)}`;
    document.getElementById('bar-download').title = `Download: ${formatTime(downloadTime)}`;
}

async function runBatchSpeedtest() {
    const btn = document.getElementById('btn-speedtest-batch');
    const progressDiv = document.getElementById('speedtest-progress');
    const resultsDiv = document.getElementById('speedtest-batch-results');
    const maxTest = parseInt(document.getElementById('speedtest-batch-count').value);
    const targetUrl = document.getElementById('speedtest-batch-url').value;

    btn.classList.add('btn-loading');
    btn.innerHTML = '<span class="spinner"></span> Đang test...';

    progressDiv.style.display = 'block';
    resultsDiv.style.display = 'none';

    const progressFill = document.getElementById('speedtest-progress-fill');
    const progressText = document.getElementById('speedtest-progress-text');
    progressFill.style.width = '0%';
    progressText.textContent = `Đang test ${maxTest} proxy...`;

    // Animate progress
    let progress = 0;
    const progressInterval = setInterval(() => {
        progress += 2;
        if (progress > 90) progress = 90;
        progressFill.style.width = `${progress}%`;
    }, 500);

    try {
        const data = await api('/api/proxy/speedtest-batch', {
            method: 'POST',
            body: JSON.stringify({
                target_url: targetUrl,
                max_test: maxTest
            })
        });

        clearInterval(progressInterval);
        progressFill.style.width = '100%';
        progressText.textContent = 'Hoàn thành!';

        if (data.success) {
            // Update header stats
            document.querySelector('#speedtest-avg-ttfb .stat-value').textContent = formatTime(data.avg_ttfb);
            document.querySelector('#speedtest-avg-total .stat-value').textContent = formatTime(data.avg_total_time);
            document.querySelector('#speedtest-success-rate .stat-value').textContent =
                `${data.total_success}/${data.total_tested}`;

            // Render results table
            const tbody = document.getElementById('speedtest-batch-tbody');
            tbody.innerHTML = data.results.map((r, i) => {
                const rating = r.success ? getSpeedRating(r.total_time) : { text: '❌ Failed', class: 'speed-very-slow' };
                const ipv6Short = r.ipv6 ? (r.ipv6.length > 25 ? r.ipv6.substring(0, 22) + '...' : r.ipv6) : '-';

                return `
                    <tr class="${r.success ? '' : 'row-failed'}">
                        <td>${i + 1}</td>
                        <td><strong>${escapeHtml(r.port || '-')}</strong></td>
                        <td class="ipv6-cell" title="${escapeHtml(r.ipv6 || '')}">${escapeHtml(ipv6Short)}</td>
                        <td>${r.success ? formatTime(r.dns_lookup) : '-'}</td>
                        <td>${r.success ? formatTime(r.tcp_connect) : '-'}</td>
                        <td>${r.success ? formatTime(r.ttfb) : '-'}</td>
                        <td class="${rating.class}">${r.success ? formatTime(r.total_time) : '-'}</td>
                        <td>${r.success ? escapeHtml(formatTransferRate(r)) : '-'}</td>
                        <td><span class="badge badge-${r.success ? 'active' : 'inactive'}">${rating.text}</span></td>
                    </tr>
                `;
            }).join('');

            resultsDiv.style.display = 'block';

            showToast(
                `Test xong: ${data.total_success}/${data.total_tested} OK, Avg: ${formatTime(data.avg_total_time)}`,
                data.total_success > 0 ? 'success' : 'warning'
            );
        } else {
            showToast(data.error || 'Batch test thất bại', 'error');
        }
    } catch (e) {
        clearInterval(progressInterval);
        showToast('Lỗi batch test: ' + e.message, 'error');
    }

    setTimeout(() => {
        progressDiv.style.display = 'none';
    }, 2000);

    btn.classList.remove('btn-loading');
    btn.innerHTML = '📊 Test Tất Cả';
}

// ============ AUTO OPTIMIZE ============
async function runAutoOptimize() {
    const btn = document.getElementById('btn-optimize');
    const resultDiv = document.getElementById('optimize-result');

    btn.classList.add('btn-loading');
    btn.innerHTML = '<span class="spinner"></span> Đang test & tối ưu...';
    resultDiv.style.display = 'none';

    if (!confirm('Kiểm tra source IPv6 hai lần; chỉ thay địa chỉ thất bại cả hai lần?')) {
        btn.classList.remove('btn-loading'); btn.textContent = '🔧 Tối Ưu Proxy'; return;
    }
    try {
        const data = await api('/api/proxy/auto-optimize', {
            method: 'POST',
            body: JSON.stringify({})
        });

        resultDiv.style.display = 'block';

        if (data.success) {
            const isOptimized = data.replaced > 0;
            resultDiv.className = `optimize-result ${isOptimized ? 'warning' : 'success'}`;
            
            let html = `<div class="optimize-summary">
                <span class="optimize-icon">${isOptimized ? '🔄' : '✅'}</span>
                <div>
                    <strong>${escapeHtml(data.message)}</strong>
                    <p>Giữ lại: ${escapeHtml(data.kept ?? data.total)} | Thay thế: ${escapeHtml(data.replaced)}</p>
                </div>
            </div>`;

            if (data.bad_details && data.bad_details.length > 0) {
                html += '<div class="optimize-details"><strong>Proxy đã thay thế:</strong><ul>';
                data.bad_details.forEach(d => {
                    html += `<li>Port ${escapeHtml(d.port)}: ${escapeHtml(d.total_time)}s (HTTP ${escapeHtml(d.http_code)})</li>`;
                });
                html += '</ul></div>';
            }

            resultDiv.innerHTML = html;
            showToast(data.message, isOptimized ? 'warning' : 'success');

            if (isOptimized) {
                loadProxies();
                refreshStatus();
            }
        } else {
            resultDiv.className = 'optimize-result error';
            resultDiv.innerHTML = `<span>❌ ${escapeHtml(data.error)}</span>`;
            showToast(data.error, 'error');
        }
    } catch (e) {
        resultDiv.style.display = 'block';
        resultDiv.className = 'optimize-result error';
        resultDiv.innerHTML = `<span>❌ Lỗi: ${escapeHtml(e.message)}</span>`;
        showToast('Lỗi tối ưu: ' + e.message, 'error');
    }

    btn.classList.remove('btn-loading');
    btn.innerHTML = '🔧 Tối Ưu Proxy';
}
