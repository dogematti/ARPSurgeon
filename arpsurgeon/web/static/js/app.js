const API_BASE = '/api/v1';

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

function getApiKey() {
    return localStorage.getItem('arpsurgeon_api_key') || '';
}

function authHeaders() {
    const headers = {'Content-Type': 'application/json'};
    const key = getApiKey();
    if (key) headers['Authorization'] = `Bearer ${key}`;
    return headers;
}

function authFetch(url, opts = {}) {
    opts.headers = {...(opts.headers || {}), ...authHeaders()};
    return fetch(url, opts);
}

// ---------------------------------------------------------------------------
// Toast Notifications
// ---------------------------------------------------------------------------

function showToast(message, type = 'info') {
    const container = document.getElementById('toastContainer');
    const iconMap = {
        success: 'bi-check-circle-fill',
        danger: 'bi-exclamation-triangle-fill',
        warning: 'bi-exclamation-circle-fill',
        info: 'bi-info-circle-fill',
    };
    const colorMap = {
        success: 'var(--color-success)',
        danger: 'var(--color-danger)',
        warning: 'var(--color-warning)',
        info: 'var(--color-accent)',
    };

    const toast = document.createElement('div');
    toast.className = 'app-toast';
    toast.style.borderLeftColor = colorMap[type] || colorMap.info;
    toast.innerHTML = `
        <i class="bi ${iconMap[type] || iconMap.info}" style="color:${colorMap[type] || colorMap.info}"></i>
        <span>${message}</span>
    `;
    container.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('show'));

    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// ---------------------------------------------------------------------------
// Sidebar & Navigation
// ---------------------------------------------------------------------------

function toggleSidebar() {
    document.getElementById('sidebar').classList.toggle('collapsed');
    document.getElementById('mainContent').classList.toggle('sidebar-collapsed');
}

function showSection(name) {
    document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.sidebar-link').forEach(l => l.classList.remove('active'));
    const section = document.getElementById(`section-${name}`);
    if (section) section.classList.add('active');
    const link = document.querySelector(`.sidebar-link[data-section="${name}"]`);
    if (link) link.classList.add('active');

    // Refresh data when switching sections
    if (name === 'jobs') fetchJobs();
    if (name === 'hosts') fetchHosts();
    if (name === 'topology') fetchTopology();
    if (name === 'dashboard') fetchStats();
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

let settingsModal = null;

function showSettings() {
    document.getElementById('apiKeyInput').value = getApiKey();
    if (!settingsModal) {
        settingsModal = new bootstrap.Modal(document.getElementById('settingsModal'));
    }
    settingsModal.show();
}

function saveApiKey() {
    const key = document.getElementById('apiKeyInput').value.trim();
    if (key) {
        localStorage.setItem('arpsurgeon_api_key', key);
    } else {
        localStorage.removeItem('arpsurgeon_api_key');
    }
    settingsModal.hide();
    initSSE();
    showToast('API key saved', 'success');
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

function formatUptime(seconds) {
    if (seconds < 60) return `${seconds}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m`;
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    return `${h}h ${m}m`;
}

async function fetchStats() {
    try {
        const res = await authFetch(`${API_BASE}/stats`);
        if (!res.ok) return;
        const data = await res.json();
        document.getElementById('statHosts').textContent = data.hosts || 0;
        document.getElementById('statActiveJobs').textContent = data.active_jobs || 0;
        document.getElementById('statEvents').textContent = data.events || 0;
        document.getElementById('statUptime').textContent = formatUptime(data.uptime_seconds || 0);
    } catch (e) {
        // Silently fail for stats
    }
}

// ---------------------------------------------------------------------------
// Jobs
// ---------------------------------------------------------------------------

const STATUS_COLORS = {
    running: 'badge-running',
    completed: 'badge-completed',
    failed: 'badge-failed',
    stopped: 'badge-stopped',
    pending: 'badge-pending',
};

const JOB_TYPE_ICONS = {
    discover: 'bi-radar',
    observe: 'bi-eye',
    profile: 'bi-clipboard-data',
    check: 'bi-heart-pulse',
    poison: 'bi-droplet-fill',
    mitm: 'bi-arrow-left-right',
    'dns-spoof': 'bi-globe',
    sever: 'bi-scissors',
    fuzz: 'bi-shuffle',
    relay: 'bi-arrow-repeat',
    monitor: 'bi-shield-exclamation',
    restore: 'bi-arrow-counterclockwise',
    snapshot: 'bi-camera',
    'restore-snapshot': 'bi-box-arrow-in-down',
    campaign: 'bi-kanban',
};

function formatDuration(startTime, endTime) {
    if (!startTime) return '-';
    const end = endTime || (Date.now() / 1000);
    const dur = end - startTime;
    if (dur < 60) return `${Math.floor(dur)}s`;
    if (dur < 3600) return `${Math.floor(dur / 60)}m ${Math.floor(dur % 60)}s`;
    return `${Math.floor(dur / 3600)}h ${Math.floor((dur % 3600) / 60)}m`;
}

function renderJobRow(job) {
    const icon = JOB_TYPE_ICONS[job.type] || 'bi-gear';
    const badge = STATUS_COLORS[job.status] || 'badge-stopped';
    const duration = formatDuration(job.start_time, job.end_time);
    return `
        <td class="font-monospace">${job.job_id.substring(0, 8)}</td>
        <td><i class="bi ${icon} me-1"></i>${job.type}</td>
        <td><span class="status-badge ${badge}">${job.status}</span></td>
        <td>${job.start_time ? new Date(job.start_time * 1000).toLocaleTimeString() : '-'}</td>
        <td>${duration}</td>
        <td class="text-truncate" style="max-width:180px" title="${job.error || ''}">${job.error || ''}</td>
        <td>
            ${job.status === 'running' ? `<button class="btn btn-xs btn-danger" onclick="stopJob('${job.job_id}')"><i class="bi bi-stop-fill"></i></button>` : ''}
        </td>
    `;
}

function renderDashJobRow(job) {
    const icon = JOB_TYPE_ICONS[job.type] || 'bi-gear';
    const badge = STATUS_COLORS[job.status] || 'badge-stopped';
    const duration = formatDuration(job.start_time, job.end_time);
    return `
        <td class="font-monospace">${job.job_id.substring(0, 8)}</td>
        <td><i class="bi ${icon} me-1"></i>${job.type}</td>
        <td><span class="status-badge ${badge}">${job.status}</span></td>
        <td>${duration}</td>
        <td>
            ${job.status === 'running' ? `<button class="btn btn-xs btn-danger" onclick="stopJob('${job.job_id}')"><i class="bi bi-stop-fill"></i></button>` : ''}
        </td>
    `;
}

async function fetchJobs() {
    try {
        const res = await authFetch(`${API_BASE}/jobs`);
        const jobs = await res.json();

        // Full jobs table
        const filter = document.getElementById('jobFilter')?.value || '';
        const filtered = filter ? jobs.filter(j => j.status === filter) : jobs;
        const tbody = document.querySelector('#jobs-table tbody');
        tbody.innerHTML = '';
        filtered.forEach(job => {
            const tr = document.createElement('tr');
            tr.innerHTML = renderJobRow(job);
            tbody.appendChild(tr);
        });

        // Dashboard jobs table (only running + recent)
        const dashTbody = document.querySelector('#dash-jobs-table tbody');
        if (dashTbody) {
            dashTbody.innerHTML = '';
            const recent = jobs.slice(0, 10);
            recent.forEach(job => {
                const tr = document.createElement('tr');
                tr.innerHTML = renderDashJobRow(job);
                dashTbody.appendChild(tr);
            });
        }
    } catch (e) {
        console.error('Failed to fetch jobs', e);
    }
}

async function stopJob(id) {
    try {
        await authFetch(`${API_BASE}/jobs/${id}`, { method: 'DELETE' });
        showToast('Job stopping...', 'warning');
        fetchJobs();
    } catch (e) {
        showToast('Failed to stop job', 'danger');
    }
}

// ---------------------------------------------------------------------------
// Start Job Modal
// ---------------------------------------------------------------------------

let currentJobType = null;
let jobModal = null;

async function startJob(type) {
    currentJobType = type;
    document.getElementById('modalJobType').textContent = type;
    document.getElementById('argsInput').value = "{}";

    const select = document.getElementById('profileSelect');
    select.innerHTML = '<option value="">-- Select a Preset --</option>';

    try {
        const res = await authFetch(`${API_BASE}/profiles`);
        const allProfiles = await res.json();
        const profiles = allProfiles[type] || [];
        profiles.forEach(p => {
            const opt = document.createElement('option');
            opt.value = JSON.stringify(p.args, null, 2);
            opt.textContent = p.name;
            select.appendChild(opt);
        });
    } catch (e) {
        console.error('Failed to load profiles', e);
    }

    select.onchange = () => {
        if (select.value) {
            document.getElementById('argsInput').value = select.value;
        }
    };

    if (!jobModal) {
        jobModal = new bootstrap.Modal(document.getElementById('startJobModal'));
    }
    jobModal.show();
}

async function confirmStartJob() {
    const argsStr = document.getElementById('argsInput').value;
    try {
        const args = JSON.parse(argsStr);
        const res = await authFetch(`${API_BASE}/jobs/${currentJobType}`, {
            method: 'POST',
            body: JSON.stringify({args: args})
        });
        if (res.ok) {
            const data = await res.json();
            showToast(`Job ${currentJobType} started (${data.job_id})`, 'success');
        } else {
            const err = await res.json();
            showToast(`Failed: ${err.detail || 'Unknown error'}`, 'danger');
        }
        jobModal.hide();
        fetchJobs();
        fetchStats();
    } catch (e) {
        showToast('Invalid JSON: ' + e.message, 'danger');
    }
}

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

let hostSearchTimeout = null;
let currentSort = { by: 'last_seen', order: 'DESC' };

function debouncedSearchHosts() {
    clearTimeout(hostSearchTimeout);
    hostSearchTimeout = setTimeout(() => fetchHosts(), 300);
}

function sortHosts(column) {
    if (currentSort.by === column) {
        currentSort.order = currentSort.order === 'DESC' ? 'ASC' : 'DESC';
    } else {
        currentSort.by = column;
        currentSort.order = 'ASC';
    }

    // Update sort indicators
    document.querySelectorAll('#hosts-table th.sortable i').forEach(i => {
        i.className = 'bi bi-chevron-expand';
    });
    const th = document.querySelector(`#hosts-table th[data-sort="${column}"] i`);
    if (th) {
        th.className = currentSort.order === 'ASC' ? 'bi bi-chevron-up' : 'bi bi-chevron-down';
    }

    fetchHosts();
}

async function fetchHosts() {
    try {
        const search = document.getElementById('hostSearch')?.value?.trim() || '';
        let url = `${API_BASE}/hosts?limit=200&sort_by=${currentSort.by}&sort_order=${currentSort.order}`;
        if (search) url += `&search=${encodeURIComponent(search)}`;

        const res = await authFetch(url);
        const data = await res.json();
        const hosts = data.items || [];
        const total = data.total || 0;

        const tbody = document.querySelector('#hosts-table tbody');
        tbody.innerHTML = '';
        hosts.forEach(host => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td class="font-monospace">${host.ip}</td>
                <td>${host.hostname || '<span class="text-muted">-</span>'}</td>
                <td><code>${host.mac}</code></td>
                <td>${host.vendor || '<span class="text-muted">-</span>'}</td>
                <td>${host.os || '<span class="text-muted">-</span>'}</td>
                <td>${new Date(host.last_seen * 1000).toLocaleString()}</td>
            `;
            tbody.appendChild(tr);
        });

        document.getElementById('hosts-footer').textContent = `${total} host${total !== 1 ? 's' : ''}`;
    } catch (e) {
        console.error('Failed to fetch hosts', e);
    }
}

async function clearHosts() {
    if (!confirm('Clear all discovered hosts?')) return;
    await authFetch(`${API_BASE}/hosts`, { method: 'DELETE' });
    fetchHosts();
    fetchStats();
    showToast('Hosts cleared', 'info');
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

function exportHosts(format) {
    const key = getApiKey();
    let url = `${API_BASE}/hosts/export?format=${format}`;
    if (key) url += `&token=${encodeURIComponent(key)}`;
    window.open(url, '_blank');
}

function exportEvents(format) {
    const key = getApiKey();
    let url = `${API_BASE}/events/export?format=${format}`;
    if (key) url += `&token=${encodeURIComponent(key)}`;
    window.open(url, '_blank');
}

// ---------------------------------------------------------------------------
// Events (SSE)
// ---------------------------------------------------------------------------

let eventSource = null;
const knownEventTypes = new Set();

const EVENT_TYPE_COLORS = {
    // Recon
    'arp_new': 'event-recon',
    'arp_change': 'event-warning',
    'host_discovered': 'event-recon',
    'discover': 'event-recon',
    'observe': 'event-recon',
    'profile': 'event-recon',
    'health_check': 'event-recon',
    // Attack
    'poison': 'event-attack',
    'mitm': 'event-attack',
    'dns_spoof': 'event-attack',
    'sever': 'event-attack',
    'fuzz': 'event-attack',
    // Defense
    'monitor': 'event-defense',
    'restore': 'event-defense',
    'snapshot': 'event-defense',
    'arp_storm': 'event-warning',
    // System
    'job_start': 'event-system',
    'job_stop': 'event-system',
    'job_fail': 'event-system',
};

function getEventClass(type) {
    if (EVENT_TYPE_COLORS[type]) return EVENT_TYPE_COLORS[type];
    if (type && type.includes('arp')) return 'event-recon';
    if (type && (type.includes('poison') || type.includes('spoof') || type.includes('sever'))) return 'event-attack';
    if (type && (type.includes('monitor') || type.includes('restore'))) return 'event-defense';
    return 'event-system';
}

function addEventRow(evt, target) {
    const tr = document.createElement('tr');
    tr.classList.add('event-fade-in');
    const ts = evt.timestamp ? new Date(evt.timestamp * 1000).toLocaleTimeString() : '-';
    const detail = JSON.stringify(evt.data || {});
    const typeClass = getEventClass(evt.type);

    tr.innerHTML = `
        <td class="text-nowrap text-muted">${ts}</td>
        <td><span class="event-badge ${typeClass}">${evt.type || '?'}</span></td>
        <td class="text-truncate font-monospace small" style="max-width:400px" title="${detail.replace(/"/g, '&quot;')}">${detail.substring(0, 120)}</td>
    `;
    target.prepend(tr);

    // Track event types for filter dropdown
    if (evt.type && !knownEventTypes.has(evt.type)) {
        knownEventTypes.add(evt.type);
        const select = document.getElementById('eventFilter');
        const opt = document.createElement('option');
        opt.value = evt.type;
        opt.textContent = evt.type;
        select.appendChild(opt);
    }
}

function filterEvents() {
    const filter = document.getElementById('eventFilter').value;
    const rows = document.querySelectorAll('#events-table tbody tr');
    rows.forEach(row => {
        const type = row.querySelector('.event-badge')?.textContent || '';
        row.style.display = (!filter || type === filter) ? '' : 'none';
    });
}

async function clearEvents() {
    if (!confirm('Clear all events?')) return;
    try {
        await authFetch(`${API_BASE}/events`, { method: 'DELETE' });
    } catch (e) {
        // API might not support DELETE yet; clear UI anyway
    }
    document.querySelector('#events-table tbody').innerHTML = '';
    document.querySelector('#dash-events-table tbody').innerHTML = '';
    fetchStats();
    showToast('Events cleared', 'info');
}

function setConnectionStatus(connected) {
    const el = document.getElementById('connectionStatus');
    if (connected) {
        el.innerHTML = '<span class="status-dot connected"></span><span>Connected</span>';
    } else {
        el.innerHTML = '<span class="status-dot disconnected"></span><span>Disconnected</span>';
    }
}

function initSSE() {
    if (eventSource) {
        eventSource.close();
    }
    let url = `${API_BASE}/events/stream`;
    const key = getApiKey();
    if (key) url += `?token=${encodeURIComponent(key)}`;

    eventSource = new EventSource(url);

    eventSource.onopen = function() {
        setConnectionStatus(true);
    };

    eventSource.onmessage = function(e) {
        try {
            const evt = JSON.parse(e.data);

            // Events table
            const eventsTbody = document.querySelector('#events-table tbody');
            addEventRow(evt, eventsTbody);
            while (eventsTbody.children.length > 200) eventsTbody.removeChild(eventsTbody.lastChild);

            // Dashboard events table
            const dashEventsTbody = document.querySelector('#dash-events-table tbody');
            if (dashEventsTbody) {
                addEventRow(evt, dashEventsTbody);
                while (dashEventsTbody.children.length > 50) dashEventsTbody.removeChild(dashEventsTbody.lastChild);
            }

            // Auto-scroll
            if (document.getElementById('autoScrollToggle')?.checked) {
                const container = document.getElementById('eventsScrollContainer');
                if (container) container.scrollTop = 0;
            }

            // Apply filter
            filterEvents();
        } catch (err) {
            // Ignore keepalive or parse errors
        }
    };

    eventSource.onerror = function() {
        setConnectionStatus(false);
    };
}

// ---------------------------------------------------------------------------
// Topology (vis.js)
// ---------------------------------------------------------------------------

let topoNetwork = null;

async function fetchTopology() {
    try {
        const res = await authFetch(`${API_BASE}/topology`);
        const data = await res.json();
        const container = document.getElementById('topology-graph');

        if (!data.nodes || data.nodes.length === 0) {
            if (topoNetwork) { topoNetwork.destroy(); topoNetwork = null; }
            container.innerHTML = '<div class="empty-state"><i class="bi bi-diagram-3"></i><p>No topology data yet.<br>Run a profile or discover scan.</p></div>';
            return;
        }

        const nodes = new vis.DataSet(data.nodes.map(n => ({
            ...n,
            color: {
                background: 'var(--color-surface, #1a1f2e)',
                border: 'var(--color-accent, #00d4aa)',
                highlight: { background: '#1e2940', border: '#00ffcc' },
            },
            font: { color: '#c8d0e0', size: 13, face: 'system-ui' },
            borderWidth: 2,
            margin: 12,
        })));
        const edges = new vis.DataSet(data.edges.map(e => ({
            ...e,
            color: { color: '#334155', highlight: '#00d4aa' },
            font: { color: '#64748b', size: 10 },
        })));

        const options = {
            physics: {
                solver: 'barnesHut',
                barnesHut: { gravitationalConstant: -3000, springLength: 150 },
                stabilization: { iterations: 100 },
            },
            interaction: { hover: true, tooltipDelay: 200 },
            nodes: { borderWidth: 2, margin: 10, shape: 'box' },
        };

        if (topoNetwork) {
            topoNetwork.setData({ nodes, edges });
        } else {
            container.innerHTML = '';
            topoNetwork = new vis.Network(container, { nodes, edges }, options);
        }
    } catch (e) {
        console.error('Failed to fetch topology', e);
    }
}

function toggleFullscreenTopo() {
    const section = document.getElementById('section-topology');
    const graph = document.getElementById('topology-graph');
    if (section.classList.contains('fullscreen')) {
        section.classList.remove('fullscreen');
        graph.style.height = '500px';
    } else {
        section.classList.add('fullscreen');
        graph.style.height = '100vh';
    }
    if (topoNetwork) topoNetwork.fit();
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
    fetchStats();
    fetchJobs();
    fetchHosts();
    fetchTopology();
    initSSE();

    setInterval(fetchStats, 5000);
    setInterval(fetchJobs, 3000);
    setInterval(fetchHosts, 10000);
    setInterval(fetchTopology, 30000);
});
