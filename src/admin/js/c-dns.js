// ===== DNS =====
function filterDns() { S.dnsSearch = document.getElementById('dns-search').value || ''; renderDns(S.cachedDns || { stats:{}, entries:[] }); }
function toggleDnsNegatives() {
    S.dnsNegativesOnly = !S.dnsNegativesOnly;
    document.getElementById('dns-negatives-btn').classList.toggle('on', S.dnsNegativesOnly);
    renderDns(S.cachedDns || { stats:{}, entries:[] });
}
function resetDnsFilters() {
    S.dnsSearch = ''; S.dnsNegativesOnly = false;
    document.getElementById('dns-search').value = '';
    document.getElementById('dns-negatives-btn').classList.remove('on');
    renderDns(S.cachedDns || { stats:{}, entries:[] });
}
function renderDns(d) {
    const entries = d.entries || [];
    const query = S.dnsSearch.trim().toLowerCase();
    const filtered = entries.filter(e => {
        if (S.dnsNegativesOnly && !e.is_negative) return false;
        if (!query) return true;
        return `${e.host||''} ${(e.addrs||[]).join(' ')}`.toLowerCase().includes(query);
    });
    const expiringSoon = filtered.filter(e => (e.ttl_remaining_secs || 0) <= 10).length;
    const negativeCount = filtered.filter(e => e.is_negative).length;
    const hotEntry = [...filtered].sort((a, b) => (a.ttl_remaining_secs || 0) - (b.ttl_remaining_secs || 0))[0];
    document.getElementById('dns-stats').innerHTML=
        `<div class="stat-card"><div class="stat-label">Entries</div><div class="stat-value">${filtered.length}</div></div>`+
        `<div class="stat-card"><div class="stat-label">Hits</div><div class="stat-value green">${d.stats?.hits||0}</div></div>`+
        `<div class="stat-card"><div class="stat-label">Misses</div><div class="stat-value">${d.stats?.misses||0}</div></div>`+
        `<div class="stat-card"><div class="stat-label">Hit Rate</div><div class="stat-value ${((d.stats?.hit_rate||0)>80?'green':'yellow')}">${d.stats?.hit_rate||0}%</div></div>`;
    document.getElementById('dns-meta').textContent = `${filtered.length} shown · ${entries.length} total`;
    document.getElementById('dns-inspector').innerHTML = `
        <div class="panel-head"><div><div class="panel-title">DNS inspector</div><div class="subtle">Fast visibility into expiry pressure and negative cache spread</div></div></div>
        <div class="panel-body">
            <div class="summary-grid" style="margin-bottom:0.9rem">
                <div class="summary-card"><div class="k">Negative entries</div><div class="v">${negativeCount}</div></div>
                <div class="summary-card"><div class="k">Expiring ≤10s</div><div class="v">${expiringSoon}</div></div>
                <div class="summary-card"><div class="k">Next expiry</div><div class="v">${esc(hotEntry?.host || '—')}</div><div class="subtle">${hotEntry ? `${hotEntry.ttl_remaining_secs}s` : 'No entries'}</div></div>
            </div>
            <div class="help-list">
                <div class="help-item"><strong>Negative cache</strong> NX entries can explain upstream discovery flaps when DNS TTLs are too aggressive.</div>
                <div class="help-item"><strong>Expiring soon</strong> Entries below 10s are likely to churn; correlate with request latency spikes.</div>
            </div>
        </div>`;
    document.getElementById('dns-entries').innerHTML=filtered.length ? `<div class="dns-entry-list">${filtered.map(e=>{
        const ttl = e.ttl_remaining_secs || 0;
        const tone = e.is_negative ? 'tag-tcp' : ttl <= 10 ? 'tag-grpc' : 'tag-tls';
        const label = e.is_negative ? 'NEGATIVE' : ttl <= 10 ? 'HOT' : 'CACHED';
        return `<div class="dns-entry"><div class="dns-entry-main"><div class="dns-entry-host">${esc(e.host)}</div><div class="dns-entry-meta mono">${esc((e.addrs||[]).join(', ') || 'NXDOMAIN')}</div></div><div class="dns-entry-side"><span class="tag ${tone}">${label}</span><span class="metric-chip">TTL ${ttl}s</span></div></div>`;
    }).join('')}</div>` : '<div class="empty">No DNS entries match the current filters</div>';
}

