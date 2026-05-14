// ===== CERTS =====
function certTone(cert) {
    const days = cert?.days_remaining;
    if (days == null) return 'unknown';
    if (days < 7) return 'err';
    if (days < 30) return 'warn';
    return 'ok';
}
function certToneLabel(tone) {
    if (tone === 'err') return 'critical';
    if (tone === 'warn') return 'warning';
    if (tone === 'ok') return 'healthy';
    return 'unknown';
}
function certRelativeText(days) {
    if (days == null) return 'Unknown remaining lifetime';
    if (days < 0) return `${Math.abs(days)}d overdue`;
    if (days === 0) return 'Expires today';
    return `${days}d remaining`;
}
function certMatchesRisk(cert) {
    const tone = certTone(cert);
    if (S.certRisk === 'all') return true;
    if (S.certRisk === 'critical') return tone === 'err';
    if (S.certRisk === 'warning') return tone === 'warn';
    if (S.certRisk === 'healthy') return tone === 'ok';
    return true;
}
function certExpiryWidth(days) {
    if (days == null) return 15;
    if (days < 0) return 100;
    return Math.max(8, Math.min(100, Math.round((days / 90) * 100)));
}
function selectCert(entryName) { S.selectedCertEntry = entryName || null; renderCerts(S.cachedCerts || { certificates: [] }); }
function filterCerts() { S.certSearch = document.getElementById('cert-search').value || ''; renderCerts(S.cachedCerts || { certificates: [] }); }
function changeCertRisk() { S.certRisk = document.getElementById('cert-risk').value || 'all'; renderCerts(S.cachedCerts || { certificates: [] }); }
function toggleCertDefaultOnly() {
    S.certDefaultOnly = !S.certDefaultOnly;
    document.getElementById('cert-default-btn').classList.toggle('on', S.certDefaultOnly);
    renderCerts(S.cachedCerts || { certificates: [] });
}
function toggleCertClientCaOnly() {
    S.certClientCaOnly = !S.certClientCaOnly;
    document.getElementById('cert-client-ca-btn').classList.toggle('on', S.certClientCaOnly);
    renderCerts(S.cachedCerts || { certificates: [] });
}
function resetCertFilters() {
    S.certSearch = ''; S.certRisk = 'all'; S.certDefaultOnly = false; S.certClientCaOnly = false;
    document.getElementById('cert-search').value = '';
    document.getElementById('cert-risk').value = 'all';
    document.getElementById('cert-default-btn').classList.remove('on');
    document.getElementById('cert-client-ca-btn').classList.remove('on');
    renderCerts(S.cachedCerts || { certificates: [] });
}
function renderCerts(d) {
    S.cachedCerts = d;
    const consulCerts = d?.certificates || [];
    const fileListeners = d?.listeners || [];
    // Merge file-based listeners into a unified cert list for display
    const listenerCerts = fileListeners.map(l => ({
        entry_name: l.label,
        primary_name: l.common_name || l.label,
        days_remaining: l.days_remaining,
        not_after_unix: l.not_after_unix,
        source: 'file',
        listen: l.listen,
        client_auth: l.client_auth,
        subject: l.subject,
        chain_length: l.chain_length,
    }));
    const certs = [...listenerCerts, ...consulCerts];
    const clientAuth = d?.client_auth || {};
    const query = S.certSearch.trim().toLowerCase();
    const caList = (clientAuth.certificates || []).filter(ca => !query || `${ca.common_name || ''} ${ca.subject || ''} ${ca.entry_name || ''}`.toLowerCase().includes(query));
    const filtered = S.certClientCaOnly ? [] : certs.filter(cert => {
        if (S.certDefaultOnly && d?.default_certificate !== cert.entry_name) return false;
        if (!certMatchesRisk(cert)) return false;
        if (!query) return true;
        return `${cert.primary_name || ''} ${cert.entry_name || ''} ${d?.source || ''}`.toLowerCase().includes(query);
    }).sort((a, b) => {
        const ad = a.days_remaining == null ? Number.MAX_SAFE_INTEGER : a.days_remaining;
        const bd = b.days_remaining == null ? Number.MAX_SAFE_INTEGER : b.days_remaining;
        return ad - bd;
    });
    const critical = certs.filter(cert => (cert.days_remaining ?? CERT_MAX_DAYS) < CERT_EXPIRY_CRIT_DAYS).length;
    const warning = certs.filter(cert => {
        const days = cert.days_remaining;
        return days != null && days >= 7 && days < 30;
    }).length;
    const healthy = certs.filter(cert => {
        const days = cert.days_remaining;
        return days != null && days >= 30;
    }).length;
    const unknown = certs.filter(cert => cert.days_remaining == null).length;
    const nextExpiry = [...certs].filter(cert => cert.days_remaining != null).sort((a,b) => a.days_remaining - b.days_remaining)[0];
    const defaultCert = certs.find(cert => cert.entry_name === d?.default_certificate) || null;
    document.getElementById('certs-summary').innerHTML = `
        <div class="summary-card"><div class="k">TLS Source</div><div class="v">${esc(d?.source || 'disabled')}</div><div class="subtle">${fileListeners.length} file listener(s)${consulCerts.length ? ' · ' + consulCerts.length + ' consul cert(s)' : ''}</div></div>
        <div class="summary-card"><div class="k">Critical / Warning</div><div class="v">${critical} / ${warning}</div><div class="subtle">healthy ${healthy} · unknown ${unknown}</div></div>
        <div class="summary-card"><div class="k">Default cert</div><div class="v">${esc(defaultCert?.primary_name || d?.default_certificate || '—')}</div><div class="subtle">${esc(d?.default_certificate || 'No default selected')}</div></div>
        <div class="summary-card"><div class="k">Client auth</div><div class="v">${esc(clientAuth.mode || 'off')}</div><div class="subtle">${(clientAuth.certificates || []).length} CA entries</div></div>
        <div class="summary-card"><div class="k">Next expiry</div><div class="v">${esc(nextExpiry?.primary_name || '—')}</div><div class="subtle">${nextExpiry ? certRelativeText(nextExpiry.days_remaining) : 'No expiry metadata'}</div></div>
    `;
    document.getElementById('certs-meta').textContent = `${S.certClientCaOnly ? caList.length : filtered.length} shown · ${S.certClientCaOnly ? (clientAuth.certificates || []).length : certs.length} total`;
    if (!filtered.some(cert => cert.entry_name === S.selectedCertEntry)) S.selectedCertEntry = filtered[0]?.entry_name || null;
    const groups = S.certClientCaOnly ? [] : [
        { key: 'err', title: 'Critical expiry', items: filtered.filter(cert => certTone(cert) === 'err') },
        { key: 'warn', title: 'Warning window', items: filtered.filter(cert => certTone(cert) === 'warn') },
        { key: 'ok', title: 'Healthy certificates', items: filtered.filter(cert => certTone(cert) === 'ok') },
        { key: 'unknown', title: 'Unknown lifetime', items: filtered.filter(cert => certTone(cert) === 'unknown') },
    ].filter(group => group.items.length);
    const renderCertCard = cert => {
        const tone = certTone(cert);
        const days = cert.days_remaining;
        const isDefault = d?.default_certificate === cert.entry_name;
        const isListener = !!cert.listen;
        const listenerChips = isListener ? [
            cert.client_auth !== 'off' && cert.client_auth ? `<span class="tag tag-mtls">${esc(cert.client_auth)}</span>` : '',
            `<span class="metric-chip">${esc(cert.listen)}</span>`,
            cert.chain_length ? `<span class="metric-chip">chain: ${cert.chain_length}</span>` : '',
        ].filter(Boolean).join('') : '';
        return `<div class="cert-card ${tone}${S.selectedCertEntry === cert.entry_name ? ' active' : ''}" data-action="select-cert" data-entry="${attrEnc(cert.entry_name)}">
            <div class="cert-card-head">
                <div>
                    <div class="cert-card-title">${esc(cert.primary_name || cert.entry_name || 'Unknown')}${isDefault ? '<span class="tag tag-tls" style="margin-left:0.45rem">default</span>' : ''}</div>
                    <div class="cert-card-sub">${esc(cert.subject || cert.entry_name || '?')} · expires ${esc(fmtExpiry(cert.not_after_unix))}</div>
                </div>
                <div class="cert-days ${tone === 'unknown' ? 'warn' : tone}">${days == null ? '—' : `${days}d`}</div>
            </div>
            <div class="route-inline-meta"><span class="metric-chip">${esc(isListener ? 'file' : (d?.source || 'runtime'))}</span>${listenerChips ? ' ' + listenerChips : ''}<span class="metric-chip">${certToneLabel(tone)}</span></div>
            <div class="cert-expiry-bar"><div class="cert-expiry-fill" style="width:${certExpiryWidth(days)}%;background:${tone==='err'?'var(--red)':tone==='warn'?'var(--yellow)':tone==='ok'?'var(--green)':'var(--text-3)'}"></div></div>
        </div>`;
    };
    let listHtml = '';
    if (S.certClientCaOnly) {
        listHtml = '<div class="empty">Client CA only filter is enabled. Review the inspector panel for CA details.</div>';
    } else if (!filtered.length) {
        listHtml = d?.source === 'disabled' && !fileListeners.length ? '<div class="empty">TLS is disabled. Enable a TLS source to inspect runtime certificates here.</div>' : '<div class="empty">No certificates match the current filters</div>';
    } else {
        listHtml = groups.map(group => `<div class="cert-group"><div class="cert-group-title">${group.title}</div><div class="cert-list">${group.items.map(renderCertCard).join('')}</div></div>`).join('');
    }
    document.getElementById('certs-list').innerHTML = listHtml;
    const selected = filtered.find(cert => cert.entry_name === S.selectedCertEntry) || (S.certClientCaOnly ? null : defaultCert || filtered[0] || certs[0] || null);
    const lastError = d?.last_error || clientAuth?.last_error || '';
    document.getElementById('certs-inspector').innerHTML = `
        <div class="panel-head"><div><div class="panel-title">Certificate inspector</div><div class="subtle">Operational detail for TLS and client CA runtime state</div></div></div>
        <div class="panel-body cert-inspector-grid">
            ${selected ? `<div class="topo-focus-card"><div class="cert-card-title">${esc(selected.primary_name || selected.entry_name || 'Unknown')}</div><div class="route-inline-meta" style="margin-top:0.45rem"><span class="tag ${certTone(selected)==='err'?'tag-tcp':certTone(selected)==='warn'?'tag-grpc':certTone(selected)==='ok'?'tag-tls':'tag'}">${certToneLabel(certTone(selected))}</span>${d?.default_certificate===selected.entry_name?'<span class="tag tag-tls">default</span>':''}<span class="metric-chip">${esc(d?.source || 'runtime')}</span></div><div class="cert-tools" style="margin-top:0.55rem"><button class="config-mini-btn" data-action="copy-data" data-copy="${attrEnc(selected.entry_name || '')}" data-label="${attrEnc('Certificate entry copied')}">Copy entry</button><button class="config-mini-btn" data-action="copy-data" data-copy="${attrEnc(selected.primary_name || '')}" data-label="${attrEnc('Primary name copied')}">Copy name</button></div><dl class="cert-kv" style="margin-top:0.75rem"><dt>Entry</dt><dd class="mono">${esc(selected.entry_name || '—')}</dd><dt>Primary name</dt><dd>${esc(selected.primary_name || '—')}</dd><dt>Expires</dt><dd>${esc(fmtExpiry(selected.not_after_unix))}</dd><dt>Days remaining</dt><dd>${certRelativeText(selected.days_remaining)}</dd><dt>Default cert</dt><dd>${d?.default_certificate===selected.entry_name ? 'Yes' : 'No'}</dd></dl></div>` : '<div class="empty">No certificate selected</div>'}
            <div class="panel-item"><div class="panel-item-head"><div class="panel-item-title">Runtime state</div><span class="metric-chip">index ${d?.last_consul_index || 0}</span></div><div class="cert-runtime-list" style="margin-top:0.7rem"><div class="overview-row"><div class="overview-row-main"><div class="overview-row-title">TLS runtime</div><div class="overview-row-sub">last reload ${d?.last_reload_unix ? fmtDate(d.last_reload_unix * MS_PER_SEC) : 'never'}</div></div><div class="overview-row-side"><span class="metric-chip">${fmt(certs.length)} loaded</span></div></div><div class="overview-row"><div class="overview-row-main"><div class="overview-row-title">Client CA runtime</div><div class="overview-row-sub">last reload ${clientAuth?.last_reload_unix ? fmtDate(clientAuth.last_reload_unix * MS_PER_SEC) : 'never'}</div></div><div class="overview-row-side"><span class="metric-chip">${fmt((clientAuth.certificates || []).length)} CA certs</span></div></div>${lastError ? `<div class="help-item"><strong>Last error</strong>${esc(lastError)}</div>` : '<div class="help-item"><strong>Last error</strong>No runtime TLS / client CA error recorded</div>'}</div></div>
            <div class="panel-item"><div class="panel-item-head"><div class="panel-item-title">Client CA certificates</div><span class="metric-chip">${esc(clientAuth.mode || 'off')}</span></div><div class="cert-runtime-list" style="margin-top:0.7rem">${caList.length ? caList.map(ca => `<div class="cert-ca-item"><div class="cert-card-title">${esc(ca.common_name || ca.subject || ca.entry_name || 'unknown')}</div><div class="cert-card-sub">${esc(ca.entry_name || '?')}</div><div class="cert-tools" style="margin-top:0.45rem"><button class="config-mini-btn" data-action="copy-data" data-copy="${attrEnc(ca.subject || '')}" data-label="${attrEnc('CA subject copied')}">Copy subject</button><button class="config-mini-btn" data-action="copy-data" data-copy="${attrEnc(ca.common_name || '')}" data-label="${attrEnc('CA common name copied')}">Copy CN</button></div><dl class="cert-kv" style="margin-top:0.55rem"><dt>Subject</dt><dd>${esc(ca.subject || '—')}</dd><dt>Organization</dt><dd>${esc(ca.organization || '—')}</dd><dt>Org unit</dt><dd>${esc(ca.organizational_unit || '—')}</dd></dl></div>`).join('') : `<div class="empty">${clientAuth.mode && clientAuth.mode !== 'off' ? 'No client CA certificates loaded' : 'Client authentication is off'}</div>`}</div></div>
            <div class="panel-item"><div class="panel-item-head"><div class="panel-item-title">Operator hints</div><span class="metric-chip">certs</span></div><div class="help-list" style="margin-top:0.7rem"><div class="help-item"><strong>Critical expiry</strong> Anything under 7 days should be treated as a rotation incident candidate.</div><div class="help-item"><strong>Default certificate</strong> Verify the default entry first if clients hit unexpected SNI fallbacks.</div><div class="help-item"><strong>Client CA mode</strong> If mTLS is required but no CA certs are loaded, handshake failures will look like client-side TLS errors.</div></div></div>
        </div>`;
}


function exportCerts(){dl(S.cachedCerts||{},'sentirum-certs.json');}
