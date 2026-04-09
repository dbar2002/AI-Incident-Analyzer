/* ===== Incident History Page ===== */

document.addEventListener('DOMContentLoaded', loadHistory);

async function loadHistory() {
    try {
        const resp = await fetch('/api/history?limit=50');
        const data = await resp.json();
        renderHistoryTable(data.incidents, data.total);
    } catch (err) {
        console.error('Failed to load history:', err);
        document.getElementById('history-count').textContent = 'Failed to load';
    }
}

function renderHistoryTable(incidents, total) {
    const body = document.getElementById('history-body');
    const empty = document.getElementById('history-empty');
    const table = document.getElementById('history-table-wrap');
    const count = document.getElementById('history-count');

    count.textContent = `${total} incident${total !== 1 ? 's' : ''}`;

    if (!incidents || incidents.length === 0) {
        table.style.display = 'none';
        empty.style.display = 'flex';
        return;
    }

    table.style.display = 'block';
    empty.style.display = 'none';
    body.innerHTML = '';

    for (const inc of incidents) {
        const row = document.createElement('tr');
        row.className = 'history-row';
        row.onclick = () => openIncident(inc.id);

        const time = new Date(inc.timestamp).toLocaleString();
        const confPct = Math.round((inc.confidence || 0) * 100);

        row.innerHTML = `
            <td class="col-time">${escapeHtml(time)}</td>
            <td class="col-type">${escapeHtml(inc.incident_type)}</td>
            <td><span class="severity-badge severity-${inc.severity}">${inc.severity}</span></td>
            <td class="col-conf">${confPct}%</td>
            <td class="col-ioc">${inc.ioc_count}</td>
            <td class="col-summary">${escapeHtml(truncate(inc.summary || '', 80))}</td>
            <td class="col-dur">${inc.analysis_duration_ms}ms</td>
        `;
        body.appendChild(row);
    }
}

async function openIncident(id) {
    const modal = document.getElementById('detail-modal');
    const modalBody = document.getElementById('modal-body');
    const modalTitle = document.getElementById('modal-title');

    modalBody.innerHTML = '<p style="color:var(--text-muted);">Loading...</p>';
    modal.style.display = 'flex';

    try {
        const resp = await fetch(`/api/history/${id}`);
        if (!resp.ok) throw new Error('Not found');
        const data = await resp.json();

        const c = data.classification || {};
        modalTitle.textContent = `${c.incident_type || 'Unknown'} — ${c.severity || ''}`;

        let html = '';

        // Summary
        html += `<div class="modal-section">
            <label>Summary</label>
            <p>${escapeHtml(c.summary || '')}</p>
        </div>`;

        // Attack vector
        html += `<div class="modal-section">
            <label>Attack Vector</label>
            <p>${escapeHtml(c.attack_vector || 'Unknown')}</p>
        </div>`;

        // IOC counts
        const iocs = data.iocs || {};
        const iocLines = [];
        if (iocs.ip_addresses?.length) iocLines.push(`${iocs.ip_addresses.length} IP(s)`);
        if (iocs.domains?.length) iocLines.push(`${iocs.domains.length} domain(s)`);
        if (iocs.urls?.length) iocLines.push(`${iocs.urls.length} URL(s)`);
        if (iocs.hashes?.length) iocLines.push(`${iocs.hashes.length} hash(es)`);
        if (iocs.emails?.length) iocLines.push(`${iocs.emails.length} email(s)`);
        if (iocs.filenames?.length) iocLines.push(`${iocs.filenames.length} filename(s)`);
        if (iocs.cves?.length) iocLines.push(`${iocs.cves.length} CVE(s)`);

        if (iocLines.length) {
            html += `<div class="modal-section">
                <label>IOCs Extracted</label>
                <p>${iocLines.join(' · ')}</p>
            </div>`;
        }

        // MITRE
        if (c.mitre_techniques?.length) {
            html += `<div class="modal-section">
                <label>MITRE ATT&CK</label>
                <div class="tag-list">${c.mitre_techniques.map(t => `<span class="tag tag-mitre">${escapeHtml(t)}</span>`).join('')}</div>
            </div>`;
        }

        // Timeline
        if (data.timeline?.events?.length) {
            html += `<div class="modal-section">
                <label>Timeline (${data.timeline.events.length} events)</label>
                <p style="font-style:italic;color:var(--text-secondary);">${escapeHtml(data.timeline.narrative || '')}</p>
            </div>`;
        }

        html += `<div class="modal-section">
            <label>Analyzed</label>
            <p>${new Date(data.timestamp).toLocaleString()} · ${data.analysis_duration_ms}ms</p>
        </div>`;

        modalBody.innerHTML = html;

    } catch (err) {
        modalBody.innerHTML = `<p style="color:var(--severity-critical);">Failed to load incident details.</p>`;
    }
}

function closeModal(event) {
    if (event.target === document.getElementById('detail-modal')) {
        document.getElementById('detail-modal').style.display = 'none';
    }
}

function truncate(str, len) {
    return str.length > len ? str.substring(0, len) + '...' : str;
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
