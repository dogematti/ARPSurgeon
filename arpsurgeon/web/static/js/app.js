const API_BASE = '/api/v1';

async function fetchJobs() {
    const res = await fetch(`${API_BASE}/jobs`);
    const jobs = await res.json();
    const tbody = document.querySelector('#jobs-table tbody');
    tbody.innerHTML = '';
    jobs.forEach(job => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${job.job_id.substring(0, 8)}</td>
            <td>${job.type}</td>
            <td><span class="badge ${job.status === 'running' ? 'bg-success' : 'bg-secondary'}">${job.status}</span></td>
            <td>${new Date(job.start_time * 1000).toLocaleTimeString()}</td>
            <td>
                ${job.status === 'running' ? `<button class="btn btn-sm btn-danger" onclick="stopJob('${job.job_id}')">Stop</button>` : ''}
            </td>
        `;
        tbody.appendChild(tr);
    });
}

async function fetchHosts() {
    const res = await fetch(`${API_BASE}/hosts`);
    const hosts = await res.json();
    const tbody = document.querySelector('#hosts-table tbody');
    tbody.innerHTML = '';
    hosts.forEach(host => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${host.ip}</td>
            <td>${host.hostname || '-'}</td>
            <td><code>${host.mac}</code></td>
            <td>${host.vendor || '-'}</td>
            <td>${host.os || '-'}</td>
            <td>${new Date(host.last_seen * 1000).toLocaleString()}</td>
        `;
        tbody.appendChild(tr);
    });
}

let currentJobType = null;
let jobModal = null;

async function stopJob(id) {
    await fetch(`${API_BASE}/jobs/${id}`, { method: 'DELETE' });
    fetchJobs();
}

async function startJob(type) {
    currentJobType = type;
    document.getElementById('modalJobType').textContent = type;
    document.getElementById('argsInput').value = "{}";
    
    // Fetch profiles
    const select = document.getElementById('profileSelect');
    select.innerHTML = '<option value="">-- Select a Preset --</option>';
    
    try {
        const res = await fetch(`${API_BASE}/profiles`);
        const allProfiles = await res.json();
        const profiles = allProfiles[type] || [];
        
        profiles.forEach((p, index) => {
            const opt = document.createElement('option');
            opt.value = JSON.stringify(p.args, null, 2);
            opt.textContent = p.name;
            select.appendChild(opt);
        });
    } catch (e) {
        console.error("Failed to load profiles", e);
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
        await fetch(`${API_BASE}/jobs/${currentJobType}`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({args: args})
        });
        jobModal.hide();
        fetchJobs();
    } catch (e) {
        alert("Invalid JSON: " + e);
    }
}

// Initial load
document.addEventListener('DOMContentLoaded', () => {
    fetchJobs();
    fetchHosts();
    setInterval(fetchJobs, 2000); // Poll jobs every 2s
    setInterval(fetchHosts, 5000); // Poll hosts every 5s
});
