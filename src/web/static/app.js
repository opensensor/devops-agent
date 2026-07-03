let currentIncidents = [];
let allIncidents = [];
let activeAbuseReportIncident = null;
const incidentFilters = {
    status: 'all',
    block: 'all',
    report: 'all',
    query: ''
};

document.addEventListener('DOMContentLoaded', function() {
    const tabs = document.querySelectorAll('.nav-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabs.forEach(tab => {
        tab.addEventListener('click', function() {
            const tabName = this.getAttribute('data-tab');

            tabs.forEach(t => t.classList.remove('active'));
            tabContents.forEach(c => c.classList.remove('active'));

            this.classList.add('active');
            document.getElementById(`${tabName}-section`).classList.add('active');

            if (tabName === 'incidents') {
                loadIncidents();
            } else if (tabName === 'allowlist') {
                loadAllowlist();
            }
        });
    });

    document.getElementById('add-ip-btn').addEventListener('click', addAllowlistIp);
    initIncidentFilters();
    ensureAbuseReportModal();

    loadIncidents();
    loadAllowlist();
});

function initIncidentFilters() {
    const controls = [
        ['incident-status-filter', 'status'],
        ['incident-block-filter', 'block'],
        ['incident-report-filter', 'report']
    ];

    controls.forEach(([id, key]) => {
        const element = document.getElementById(id);
        if (!element) return;
        element.addEventListener('change', () => {
            incidentFilters[key] = element.value;
            renderFilteredIncidents();
        });
    });

    const search = document.getElementById('incident-search');
    if (search) {
        search.addEventListener('input', () => {
            incidentFilters.query = search.value.trim().toLowerCase();
            renderFilteredIncidents();
        });
    }

    const clear = document.getElementById('clear-incident-filters');
    if (clear) {
        clear.addEventListener('click', () => {
            incidentFilters.status = 'all';
            incidentFilters.block = 'all';
            incidentFilters.report = 'all';
            incidentFilters.query = '';
            controls.forEach(([id]) => {
                const element = document.getElementById(id);
                if (element) element.value = 'all';
            });
            if (search) search.value = '';
            renderFilteredIncidents();
        });
    }
}

async function loadIncidents(options = {}) {
    const incidentsList = document.getElementById('incidents-list');
    const scrollY = window.scrollY;
    if (!options.preserveScroll) {
        incidentsList.innerHTML = '<p class="loading">Loading incidents...</p>';
    }

    try {
        const response = await fetch('/api/incidents');
        const data = await response.json();

        if (data.success && data.data) {
            allIncidents = data.data;
            renderFilteredIncidents();
            if (options.focusIncidentId) {
                highlightIncident(options.focusIncidentId);
            }
            if (options.preserveScroll) {
                restoreScroll(scrollY);
            }
            return true;
        } else {
            incidentsList.innerHTML = '<p class="message-error">Failed to load incidents</p>';
            return false;
        }
    } catch (error) {
        incidentsList.innerHTML = '<p class="message-error">Error loading incidents</p>';
        return false;
    }
}

function renderFilteredIncidents() {
    const filtered = allIncidents.filter(matchesIncidentFilters);
    renderIncidents(filtered, allIncidents.length);
    updateIncidentFilterCount(filtered.length, allIncidents.length);
}

function matchesIncidentFilters(incident) {
    if (incidentFilters.status !== 'all' && incident.status !== incidentFilters.status) {
        return false;
    }

    if (incidentFilters.block !== 'all' && blockStateKey(incident) !== incidentFilters.block) {
        return false;
    }

    if (incidentFilters.report !== 'all' && reportStateKey(incident) !== incidentFilters.report) {
        return false;
    }

    if (incidentFilters.query && !incidentSearchText(incident).includes(incidentFilters.query)) {
        return false;
    }

    return true;
}

function blockStateKey(incident) {
    if (incident.cluster_blocked === true) return 'active';
    if (incident.cluster_blocked === false && incident.action_status === 'completed') return 'failed';
    if (incident.action_status === 'failed') return 'failed';
    if (incident.action_status === 'dry_run') return 'dry_run';
    if (incident.action_status === 'pending') return 'pending';
    if (incident.status === 'approved' && !incident.block_applied) return 'needs_apply';
    if (incident.block_applied || incident.action_status === 'completed') return 'applied';
    return 'none';
}

function reportStateKey(incident) {
    switch (incident.report_status) {
        case 'completed':
            return 'sent';
        case 'failed':
            return 'failed';
        case 'pending':
            return 'pending';
        default:
            return 'not_sent';
    }
}

function incidentSearchText(incident) {
    const details = incident.details || {};
    const detailText = [
        details.target_hosts,
        details.top_paths,
        details.methods,
        details.status_breakdown
    ]
        .filter(Boolean)
        .map(value => JSON.stringify(value))
        .join(' ');

    return [
        incident.id,
        incident.source_ip,
        incident.status,
        incident.action_status,
        incident.report_status,
        detailText
    ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
}

function updateIncidentFilterCount(visible, total) {
    const count = document.getElementById('incident-filter-count');
    if (!count) return;
    count.textContent = visible === total
        ? incidentCountLabel(total)
        : `${visible} of ${incidentCountLabel(total)}`;
}

function incidentCountLabel(count) {
    return `${count} ${count === 1 ? 'incident' : 'incidents'}`;
}

function renderIncidents(incidents, totalCount = incidents.length) {
    const incidentsList = document.getElementById('incidents-list');
    currentIncidents = incidents;

    if (totalCount === 0) {
        incidentsList.innerHTML = '<p class="loading">No incidents found</p>';
        return;
    }

    if (incidents.length === 0) {
        incidentsList.innerHTML = '<p class="loading">No incidents match the active filters</p>';
        return;
    }

    let html = '';
    incidents.forEach(incident => {
        const statusClass = `status-${incident.status}`;
        html += `
            <div class="incident-item" data-id="${incident.id}">
                <div class="incident-header">
                    <div class="incident-info">
                        <div class="incident-ip">${escapeHtml(incident.source_ip)}</div>
                        <div class="incident-detected">Last seen: ${escapeHtml(formatTime(incident.detected_at))}</div>
                        ${renderActionState(incident)}
                        ${renderReportState(incident)}
                    </div>
                    <span class="incident-status ${statusClass}">${statusLabel(incident.status)}</span>
                    <div class="incident-actions">
                        ${incident.status === 'detected' ? `
                            <button class="btn-approve" onclick="approveIncident('${incident.id}')" title="Create a Traefik deny rule for this IP">Block IP</button>
                            <button class="btn-block-report" onclick="blockAndReportIncident('${incident.id}')" title="Block this IP and then open the abuse report modal">Block + Report</button>
                            <button class="btn-reject" onclick="rejectIncident('${incident.id}')" title="Mark as not a threat; take no action">Dismiss</button>
                        ` : ''}
                        ${incident.status === 'approved' && !incident.block_applied ? `
                            <button class="btn-apply" onclick="applyBlock('${incident.id}')" title="Apply the Traefik edge deny rule now">Apply Block</button>
                            <button class="btn-block-report" onclick="applyBlockAndReport('${incident.id}')" title="Apply the Traefik edge deny rule and then open the abuse report modal">Apply + Report</button>
                        ` : ''}
                        <button class="btn-whois" onclick="getWhois('${incident.id}')" title="Look up network ownership and abuse contacts">WHOIS</button>
                        <button class="btn-report" onclick="openAbuseReportModal('${incident.id}')" title="Send an abuse report through the configured email provider to RDAP abuse contacts">Report Abuse</button>
                        <button class="btn-recommendation" onclick="getRecommendation('${incident.id}')">Recommendation</button>
                    </div>
                </div>
                ${renderMetrics(incident)}
                <div id="whois-${incident.id}" class="whois-panel" style="display: none;"></div>
                <div id="recommendation-${incident.id}" class="recommendation" style="display: none;"></div>
            </div>
        `;
    });

    incidentsList.innerHTML = html;
}

function renderActionState(incident) {
    if (incident.cluster_blocked === true) {
        return '<div class="action-state action-completed">Cluster block active</div>';
    }

    if (incident.cluster_blocked === false && incident.action_status === 'completed') {
        return '<div class="action-state action-failed">Cluster block missing</div>';
    }

    const status = incident.action_status;
    if (!status) {
        return incident.status === 'approved'
            ? '<div class="action-state action-missing">No cluster action recorded</div>'
            : '';
    }

    switch (status) {
        case 'completed':
            return '<div class="action-state action-completed">Cluster block applied</div>';
        case 'dry_run':
            return '<div class="action-state action-dry-run">Not applied: dry run</div>';
        case 'failed':
            return '<div class="action-state action-failed">Cluster block failed</div>';
        case 'pending':
            return '<div class="action-state action-pending">Cluster block pending</div>';
        default:
            return `<div class="action-state action-missing">${escapeHtml(status)}</div>`;
    }
}

function renderReportState(incident) {
    const status = incident.report_status;
    if (!status) return '';

    switch (status) {
        case 'completed':
            return `<div class="action-state report-completed">Abuse report sent${incident.report_sent_at ? ` ${escapeHtml(formatTime(incident.report_sent_at))}` : ''}</div>`;
        case 'failed':
            return `<div class="action-state report-failed">Abuse report failed${incident.report_last_attempt_at ? ` ${escapeHtml(formatTime(incident.report_last_attempt_at))}` : ''}</div>`;
        case 'pending':
            return '<div class="action-state report-pending">Abuse report pending</div>';
        default:
            return `<div class="action-state report-pending">Abuse report: ${escapeHtml(status)}</div>`;
    }
}

function restoreScroll(scrollY) {
    window.scrollTo(0, scrollY);
    requestAnimationFrame(() => window.scrollTo(0, scrollY));
}

function findIncidentElement(incidentId) {
    return Array.from(document.querySelectorAll('.incident-item'))
        .find(element => element.dataset.id === incidentId);
}

function highlightIncident(incidentId) {
    const element = findIncidentElement(incidentId);
    if (!element) return;
    element.classList.add('incident-highlight');
    setTimeout(() => element.classList.remove('incident-highlight'), 2400);
}

// Render the detection metrics that explain why an IP was flagged.
function renderMetrics(incident) {
    const d = incident.details;
    const count = incident.failure_count || 0;
    const window = d && d.window_minutes ? `${d.window_minutes} min` : 'window';

    // Summary line: N auth failures in the window.
    let metrics = `
        <div class="incident-metrics">
            <div class="metric-summary">
                <span class="metric-count">${count}</span>
                <span class="metric-label">auth failures (401/403) in last ${escapeHtml(window)}</span>
            </div>`;

    if (d) {
        const chips = (title, pairs, cls) => {
            if (!pairs || !pairs.length) return '';
            const items = pairs.map(([k, v]) =>
                `<span class="chip ${cls || ''}">${escapeHtml(String(k))} <b>${v}</b></span>`).join('');
            return `<div class="metric-row"><span class="metric-row-label">${title}</span>${items}</div>`;
        };

        // Status codes labelled for clarity.
        const statusPairs = (d.status_breakdown || []).map(([k, v]) => {
            const label = k === '401' ? '401 Unauthorized' : k === '403' ? '403 Forbidden' : k;
            return [label, v];
        });

        metrics += chips('Status', statusPairs, 'chip-status');
        metrics += chips('Methods', d.methods, '');
        metrics += chips('Targeted hosts', d.target_hosts, '');
        if (d.top_paths && d.top_paths.length) {
            const paths = d.top_paths.map(([p, v]) =>
                `<li><code>${escapeHtml(String(p))}</code> <span class="path-count">${v}</span></li>`).join('');
            metrics += `<div class="metric-row metric-paths"><span class="metric-row-label">Top requested paths</span><ul>${paths}</ul></div>`;
        }
    } else {
        metrics += `<div class="metric-row metric-note">No detailed metrics captured for this incident.</div>`;
    }

    metrics += `</div>`;
    return metrics;
}

// Render an ISO timestamp as a readable local string, falling back to raw.
function formatTime(iso) {
    const dt = new Date(iso);
    return isNaN(dt.getTime()) ? iso : dt.toLocaleString();
}

// Map an incident's stored status to a user-facing label.
function statusLabel(status) {
    switch (status) {
        case 'detected': return 'Detected';
        case 'approved': return 'Block Approved';
        case 'rejected': return 'Dismissed';
        default: return capitalizeFirst(status);
    }
}

async function approveIncident(incidentId) {
    await blockIncident(incidentId, false);
}

async function blockAndReportIncident(incidentId) {
    await blockIncident(incidentId, true);
}

async function blockIncident(incidentId, openReport) {
    try {
        const response = await fetch(`/api/incidents/${incidentId}/approve`, {
            method: 'POST'
        });
        const data = await response.json();

        if (data.success) {
            showMessage(data.message || 'IP block approved', 'success');
            const loaded = await loadIncidents({ preserveScroll: true, focusIncidentId: incidentId });
            if (openReport && loaded) {
                openAbuseReportModal(incidentId);
            }
        } else {
            showMessage(data.message || 'Failed to block IP', 'error');
        }
    } catch (error) {
        showMessage('Error blocking IP', 'error');
    }
}

async function applyBlock(incidentId) {
    await applyClusterBlock(incidentId, false);
}

async function applyBlockAndReport(incidentId) {
    await applyClusterBlock(incidentId, true);
}

async function applyClusterBlock(incidentId, openReport) {
    try {
        const response = await fetch(`/api/incidents/${incidentId}/apply-block`, {
            method: 'POST'
        });
        const data = await response.json();

        if (data.success) {
            showMessage(data.message || 'Cluster block applied', 'success');
            const loaded = await loadIncidents({ preserveScroll: true, focusIncidentId: incidentId });
            if (openReport && loaded) {
                openAbuseReportModal(incidentId);
            }
        } else {
            showMessage(data.message || 'Failed to apply cluster block', 'error');
        }
    } catch (error) {
        showMessage('Error applying cluster block', 'error');
    }
}

async function getWhois(incidentId) {
    const whoisDiv = document.getElementById(`whois-${incidentId}`);
    whoisDiv.style.display = 'block';
    whoisDiv.innerHTML = '<p class="loading">Loading WHOIS...</p>';

    try {
        const response = await fetch(`/api/incidents/${incidentId}/whois`);
        const data = await response.json();

        if (data.success && data.data) {
            whoisDiv.innerHTML = renderWhois(data.data);
        } else {
            whoisDiv.innerHTML = `<p class="message-error">${escapeHtml(data.message || 'Failed to load WHOIS')}</p>`;
        }
    } catch (error) {
        whoisDiv.innerHTML = '<p class="message-error">Error loading WHOIS</p>';
    }
}

function ensureAbuseReportModal() {
    if (document.getElementById('abuse-report-modal')) {
        return;
    }

    const modal = document.createElement('div');
    modal.id = 'abuse-report-modal';
    modal.className = 'modal-backdrop';
    modal.setAttribute('aria-hidden', 'true');
    modal.innerHTML = `
        <div class="modal-dialog" role="dialog" aria-modal="true" aria-labelledby="abuse-report-title">
            <div class="modal-header">
                <div>
                    <h3 id="abuse-report-title">Send Abuse Report</h3>
                    <p id="abuse-report-subtitle"></p>
                </div>
                <button class="modal-close" type="button" title="Close">X</button>
            </div>
            <div class="modal-body">
                <div id="abuse-report-summary" class="modal-summary"></div>
                <div id="abuse-report-prior" class="modal-warning" style="display: none;"></div>
                <div class="modal-section">
                    <div class="modal-section-label">Recipients</div>
                    <div id="abuse-report-recipients" class="modal-recipients">Loading abuse contacts...</div>
                </div>
                <div id="abuse-report-status" class="modal-status" style="display: none;"></div>
            </div>
            <div class="modal-actions">
                <button id="abuse-report-cancel" class="btn-secondary" type="button">Cancel</button>
                <button id="abuse-report-submit" class="btn-report" type="button">Send Report</button>
            </div>
        </div>
    `;

    document.body.appendChild(modal);
    modal.addEventListener('click', event => {
        if (event.target === modal) closeAbuseReportModal();
    });
    modal.querySelector('.modal-close').addEventListener('click', closeAbuseReportModal);
    modal.querySelector('#abuse-report-cancel').addEventListener('click', closeAbuseReportModal);
    modal.querySelector('#abuse-report-submit').addEventListener('click', () => {
        if (!activeAbuseReportIncident) return;
        const force = activeAbuseReportIncident.report_status === 'completed';
        sendAbuseReport(activeAbuseReportIncident.id, force);
    });

    document.addEventListener('keydown', event => {
        if (event.key === 'Escape') closeAbuseReportModal();
    });
}

function openAbuseReportModal(incidentId) {
    ensureAbuseReportModal();
    const incident = findIncidentById(incidentId);
    if (!incident) {
        showMessage('Incident is no longer loaded', 'error');
        return;
    }

    activeAbuseReportIncident = incident;
    const alreadySent = incident.report_status === 'completed';
    const modal = document.getElementById('abuse-report-modal');
    modal.querySelector('#abuse-report-title').textContent = alreadySent ? 'Abuse Report Sent' : 'Send Abuse Report';
    modal.querySelector('#abuse-report-subtitle').textContent = `${incident.source_ip} via configured email provider`;
    modal.querySelector('#abuse-report-summary').innerHTML = renderAbuseReportSummary(incident);

    const prior = modal.querySelector('#abuse-report-prior');
    if (alreadySent) {
        prior.style.display = 'block';
        prior.textContent = `This incident was already reported${incident.report_sent_at ? ` at ${formatTime(incident.report_sent_at)}` : ''}. Sending again will create another abuse email.`;
    } else {
        prior.style.display = 'none';
        prior.textContent = '';
    }

    const status = modal.querySelector('#abuse-report-status');
    status.style.display = 'none';
    status.textContent = '';

    const submit = modal.querySelector('#abuse-report-submit');
    submit.disabled = true;
    submit.textContent = alreadySent ? 'Send Again' : 'Send Report';

    const recipients = modal.querySelector('#abuse-report-recipients');
    recipients.innerHTML = '<span class="loading-inline">Loading abuse contacts...</span>';

    modal.classList.add('is-open');
    modal.setAttribute('aria-hidden', 'false');
    loadAbuseReportRecipients(incident.id);
}

function findIncidentById(incidentId) {
    return currentIncidents.find(item => item.id === incidentId)
        || allIncidents.find(item => item.id === incidentId);
}

function closeAbuseReportModal() {
    const modal = document.getElementById('abuse-report-modal');
    if (!modal) return;
    modal.classList.remove('is-open');
    modal.setAttribute('aria-hidden', 'true');
    activeAbuseReportIncident = null;
}

function renderAbuseReportSummary(incident) {
    const d = incident.details || {};
    const windowLabel = d.window_minutes ? `${d.window_minutes} minutes` : 'the detection window';
    return `
        <div class="summary-row"><span>Source IP</span><strong>${escapeHtml(incident.source_ip)}</strong></div>
        <div class="summary-row"><span>Failures</span><strong>${incident.failure_count || 0} in ${escapeHtml(windowLabel)}</strong></div>
        <div class="summary-row"><span>Last seen</span><strong>${escapeHtml(formatTime(incident.detected_at))}</strong></div>
    `;
}

async function loadAbuseReportRecipients(incidentId) {
    const modal = document.getElementById('abuse-report-modal');
    const recipientsDiv = modal.querySelector('#abuse-report-recipients');
    const submit = modal.querySelector('#abuse-report-submit');

    try {
        const response = await fetch(`/api/incidents/${incidentId}/whois`);
        const data = await response.json();
        if (!data.success || !data.data) {
            recipientsDiv.innerHTML = `<span class="message-error compact">${escapeHtml(data.message || 'No abuse contacts found')}</span>`;
            submit.disabled = true;
            return;
        }

        const emails = [];
        (data.data.abuse_contacts || []).forEach(contact => {
            (contact.emails || []).forEach(email => {
                const normalized = String(email).trim().toLowerCase();
                if (normalized && !emails.includes(normalized)) emails.push(normalized);
            });
        });

        recipientsDiv.innerHTML = emails.length
            ? emails.map(email => `<span class="recipient-pill">${escapeHtml(email)}</span>`).join('')
            : '<span class="whois-empty">No abuse email listed in RDAP.</span>';
        submit.disabled = emails.length === 0;
    } catch (error) {
        recipientsDiv.innerHTML = '<span class="message-error compact">Error loading abuse contacts</span>';
        submit.disabled = true;
    }
}

async function sendAbuseReport(incidentId, force) {
    const modal = document.getElementById('abuse-report-modal');
    const submit = modal.querySelector('#abuse-report-submit');
    const status = modal.querySelector('#abuse-report-status');
    submit.disabled = true;
    status.style.display = 'block';
    status.className = 'modal-status';
    status.textContent = force ? 'Sending another abuse report...' : 'Sending abuse report...';

    try {
        const response = await fetch(`/api/incidents/${incidentId}/report-abuse`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ force: Boolean(force) })
        });
        const data = await response.json();

        if (data.success) {
            const recipients = data.data && data.data.recipients ? ` (${data.data.recipients.join(', ')})` : '';
            showMessage(`${data.message || 'Abuse report sent'}${recipients}`, 'success');
            closeAbuseReportModal();
            loadIncidents({ preserveScroll: true, focusIncidentId: incidentId });
        } else {
            status.className = 'modal-status modal-status-error';
            status.textContent = data.message || 'Failed to send abuse report';
            submit.disabled = false;
            loadIncidents({ preserveScroll: true, focusIncidentId: incidentId });
        }
    } catch (error) {
        status.className = 'modal-status modal-status-error';
        status.textContent = 'Error sending abuse report';
        submit.disabled = false;
        loadIncidents({ preserveScroll: true, focusIncidentId: incidentId });
    }
}

function renderWhois(info) {
    const rows = [
        ['Network', info.network_name],
        ['Organization', info.organization],
        ['Country', info.country],
        ['Range', rangeLabel(info.start_address, info.end_address)]
    ].filter(([, value]) => value);

    const details = rows.map(([label, value]) => `
        <div class="whois-row">
            <span class="whois-label">${escapeHtml(label)}</span>
            <span class="whois-value">${escapeHtml(value)}</span>
        </div>
    `).join('');

    const abuseContacts = info.abuse_contacts && info.abuse_contacts.length
        ? info.abuse_contacts.map(renderAbuseContact).join('')
        : '<p class="whois-empty">No abuse contact found in RDAP response.</p>';

    const source = info.registry_url
        ? `<a href="${escapeAttr(info.registry_url)}" target="_blank" rel="noopener noreferrer">RDAP source</a>`
        : 'RDAP source unavailable';

    return `
        <h4>WHOIS / Abuse Contacts</h4>
        <div class="whois-grid">${details}</div>
        <div class="whois-abuse">
            <div class="whois-section-title">Abuse reporting</div>
            ${abuseContacts}
        </div>
        <div class="whois-source">${source}</div>
    `;
}

function renderAbuseContact(contact) {
    const emails = contact.emails && contact.emails.length
        ? contact.emails.map(email => {
            const subject = encodeURIComponent('Abuse report: suspicious traffic');
            return `<a class="abuse-email" href="mailto:${escapeAttr(email)}?subject=${subject}">${escapeHtml(email)}</a>`;
        }).join('')
        : '<span class="whois-empty">No email listed</span>';

    return `
        <div class="abuse-contact">
            <div class="abuse-name">${escapeHtml(contact.name || contact.role || 'Abuse contact')}</div>
            <div class="abuse-emails">${emails}</div>
        </div>
    `;
}

function rangeLabel(start, end) {
    if (start && end) return `${start} - ${end}`;
    return start || end || '';
}

async function rejectIncident(incidentId) {
    try {
        const response = await fetch(`/api/incidents/${incidentId}/reject`, {
            method: 'POST'
        });
        const data = await response.json();

        if (data.success) {
            showMessage(data.message || 'Incident dismissed', 'success');
            loadIncidents({ preserveScroll: true, focusIncidentId: incidentId });
        } else {
            showMessage(data.message || 'Failed to dismiss incident', 'error');
        }
    } catch (error) {
        showMessage('Error dismissing incident', 'error');
    }
}

async function getRecommendation(incidentId) {
    const recDiv = document.getElementById(`recommendation-${incidentId}`);
    recDiv.style.display = 'block';
    recDiv.innerHTML = '<p class="loading">Loading recommendation...</p>';

    try {
        const response = await fetch(`/api/incidents/${incidentId}/recommendation`);
        const data = await response.json();

        if (data.success && data.data) {
            recDiv.innerHTML = `
                <h4>Recommendation</h4>
                <p><strong>Action Type:</strong> ${escapeHtml(data.data.action_type)}</p>
                <p><strong>Details:</strong> ${escapeHtml(data.data.recommendation)}</p>
            `;
        } else {
            recDiv.innerHTML = `<p class="message-error">${data.message || 'Failed to get recommendation'}</p>`;
        }
    } catch (error) {
        recDiv.innerHTML = '<p class="message-error">Error loading recommendation</p>';
    }
}

async function loadAllowlist() {
    const allowlistList = document.getElementById('allowlist-list');
    allowlistList.innerHTML = '<p class="loading">Loading allowlist...</p>';

    try {
        const response = await fetch('/api/allowlist');
        const data = await response.json();

        if (data.success && data.data) {
            renderAllowlist(data.data);
        } else {
            allowlistList.innerHTML = '<p class="message-error">Failed to load allowlist</p>';
        }
    } catch (error) {
        allowlistList.innerHTML = '<p class="message-error">Error loading allowlist</p>';
    }
}

function renderAllowlist(ips) {
    const allowlistList = document.getElementById('allowlist-list');

    if (ips.length === 0) {
        allowlistList.innerHTML = '<p class="loading">No IPs in allowlist</p>';
        return;
    }

    let html = '';
    ips.forEach(ip => {
        html += `
            <div class="allowlist-item" data-ip="${escapeHtml(ip.ip)}">
                <div class="allowlist-info">
                    <div class="allowlist-ip">${escapeHtml(ip.ip)}</div>
                    <div class="allowlist-created">${ip.description ? escapeHtml(ip.description) : 'No description'}</div>
                </div>
                <button class="btn-remove" onclick="removeAllowlistIp('${escapeHtml(ip.ip)}')">Remove</button>
            </div>
        `;
    });

    allowlistList.innerHTML = html;
}

async function addAllowlistIp() {
    const ipInput = document.getElementById('new-ip');
    const descInput = document.getElementById('ip-description');
    const ip = ipInput.value.trim();
    const description = descInput.value.trim() || null;

    if (!ip) {
        showMessage('IP address is required', 'error');
        return;
    }

    try {
        const response = await fetch('/api/allowlist', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ip, description })
        });
        const data = await response.json();

        if (data.success) {
            showMessage(data.message || 'IP added to allowlist', 'success');
            ipInput.value = '';
            descInput.value = '';
            loadAllowlist();
        } else {
            showMessage(data.message || 'Failed to add IP to allowlist', 'error');
        }
    } catch (error) {
        showMessage('Error adding IP to allowlist', 'error');
    }
}

async function removeAllowlistIp(ip) {
    if (!confirm(`Remove ${ip} from allowlist?`)) {
        return;
    }

    try {
        const response = await fetch(`/api/allowlist/${ip}`, {
            method: 'DELETE'
        });
        const data = await response.json();

        if (data.success) {
            showMessage(data.message || 'IP removed from allowlist', 'success');
            loadAllowlist();
        } else {
            showMessage(data.message || 'Failed to remove IP from allowlist', 'error');
        }
    } catch (error) {
        showMessage('Error removing IP from allowlist', 'error');
    }
}

function showMessage(message, type) {
    const container = document.querySelector('.container');
    const messageDiv = document.createElement('div');
    messageDiv.className = `message message-${type}`;
    messageDiv.textContent = message;

    container.insertBefore(messageDiv, container.children[1]);

    setTimeout(() => {
        messageDiv.remove();
    }, 5000);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function escapeAttr(text) {
    return escapeHtml(text).replace(/"/g, '&quot;');
}

function capitalizeFirst(str) {
    return str.charAt(0).toUpperCase() + str.slice(1);
}

window.approveIncident = approveIncident;
window.blockAndReportIncident = blockAndReportIncident;
window.applyBlock = applyBlock;
window.applyBlockAndReport = applyBlockAndReport;
window.getWhois = getWhois;
window.openAbuseReportModal = openAbuseReportModal;
window.sendAbuseReport = sendAbuseReport;
window.rejectIncident = rejectIncident;
window.getRecommendation = getRecommendation;
window.addAllowlistIp = addAllowlistIp;
window.removeAllowlistIp = removeAllowlistIp;
