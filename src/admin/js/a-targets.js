// ===== TARGETS =====
function targetHeatChip(t) {
    const heat = targetHeat(t);
    const color = heat >= 0.82 ? '#fb923c' : heat >= 0.58 ? '#d946ef' : heat >= 0.34 ? '#60a5fa' : heat >= 0.16 ? '#22d3ee' : '#34d399';
    return `<span class="target-heat-chip" style="border-color:${color}44;background:${color}18;color:${color}">heat ${(heat * 100).toFixed(0)}%</span>`;
}
function targetTrendCard(title, value, series, color, meta = '') {
    return `<div class="target-trend-card"><div class="panel-item-title">${esc(title)}</div><div class="panel-item-sub">${esc(value)}</div>${spark(series.slice(-24), 240, 34, color) || '<div class="subtle" style="margin-top:0.45rem">Not enough points yet</div>'}${meta ? `<div class="target-trend-meta">${esc(meta)}</div>` : ''}</div>`;
}
function targetRelatedRoutes(t) {
    return (S.allTargets || [])
        .filter(x => x.url === t.url && x.service === t.service)
        .sort((a, b) => String(a.host || '').localeCompare(String(b.host || '')) || String(a.path || '').localeCompare(String(b.path || '')));
}
function focusTargetInTopology(i) {
    const t = window._tgts?.[i];
    if (!t) return;
    S.topologyMode = 'all';
    S.topologyHostFilter = t.host || '*';
    S.topologySelectedTargetKey = targetKey(t);
    ['all','issues','hot'].forEach(name => document.getElementById(`topo-mode-${name}`)?.classList.toggle('on', name === 'all'));
    document.getElementById('topo-heat-btn')?.classList.toggle('on', S.topologyHeatMode);
    showPage('topology');
}
function renderTargetDetailEmpty() {
    const p = document.getElementById('target-detail');
    if (!p) return;
    p.className = 'detail-panel target-side-panel empty open';
    p.innerHTML = `
        <div class="detail-head"><span class="detail-title">Target inspector</span></div>
        <div class="target-side-empty">
            <div class="target-side-note">Select a target row to inspect live request, throughput, error and latency trends. Use the quick chips to triage open circuits, probe failures, high latency, or heavy throughput.</div>
            <div class="target-badges">
                <span class="target-health-badge ok">Healthy</span>
                <span class="target-health-badge warn">Watch</span>
                <span class="target-health-badge danger">Critical</span>
                <span class="target-heat-chip">heat 0%</span>
            </div>
            <div class="target-side-note">Inspector stays pinned while the table refreshes, so you can follow one backend without losing context.</div>
        </div>`;
}
function closeTargetDetail() {
    S.selectedTarget = null;
    S.selectedTargetKey = null;
    renderTargetDetailEmpty();
}
function getVisibleTargets() {
    const query = S.targetSearch.trim().toLowerCase();
    const filtered = S.allTargets.filter(t => {
        if (S.targetIssuesOnly) {
            const errPct = t.stats?.error_rate_pct || 0;
            if (!(errPct > 0 || t.circuit_breaker === 'open' || t.circuit_breaker === 'halfopen' || !t.probe_healthy)) return false;
        }
        if (S.targetHotOnly && !targetIsHot(t)) return false;
        if (S.targetQuickFilters.open && t.circuit_breaker !== 'open') return false;
        if (S.targetQuickFilters.probe && t.probe_healthy) return false;
        if (S.targetQuickFilters.latency && !targetIsHighLatency(t)) return false;
        if (S.targetQuickFilters.throughput && !targetIsHighThroughput(t)) return false;
        if (!query) return true;
        const haystack = `${t.service||''} ${t.host||''} ${t.path||''} ${t.url||''} ${t.protocol||''} ${t.source||''}`.toLowerCase();
        return haystack.includes(query);
    });
    filtered.sort((a, b) => {
        switch (S.targetSort) {
            case 'throughput': return targetThroughput(b) - targetThroughput(a);
            case 'active': return (targetLastActive(a) ?? Number.MAX_SAFE_INTEGER) - (targetLastActive(b) ?? Number.MAX_SAFE_INTEGER);
            case 'latency': return (b.stats?.avg_latency_us || 0) - (a.stats?.avg_latency_us || 0);
            case 'requests': return (b.stats?.requests || 0) - (a.stats?.requests || 0);
            case 'connections': return (b.active_connections || 0) - (a.active_connections || 0);
            case 'service': return String(a.service||'').localeCompare(String(b.service||''));
            case 'risk':
            default: return targetRiskScore(b) - targetRiskScore(a);
        }
    });
    return filtered;
}
function renderTargetsSummary(targets) {
    const openCount = targets.filter(t => t.circuit_breaker === 'open').length;
    const halfOpenCount = targets.filter(t => t.circuit_breaker === 'halfopen').length;
    const hotCount = targets.filter(t => topoFlowHot(topoFlow(t)) || targetHeat(t) >= 0.34 || (t.active_connections || 0) > 0).length;
    const unhealthyCount = targets.filter(t => !t.probe_healthy).length;
    const highestRps = [...targets].sort((a, b) => (S.targetHist[targetKey(b)]?.rate || 0) - (S.targetHist[targetKey(a)]?.rate || 0))[0];
    const highestThroughput = [...targets].sort((a, b) => targetThroughput(b) - targetThroughput(a))[0];
    const slowest = [...targets].sort((a, b) => (b.stats?.avg_latency_us || 0) - (a.stats?.avg_latency_us || 0))[0];
    document.getElementById('targets-summary').innerHTML = `
        <div class="summary-card"><div class="k">Visible targets</div><div class="v">${targets.length}</div></div>
        <div class="summary-card"><div class="k">Open / half-open</div><div class="v">${openCount} / ${halfOpenCount}</div><div class="subtle">probe unhealthy ${unhealthyCount}</div></div>
        <div class="summary-card"><div class="k">Hot targets</div><div class="v">${hotCount}</div><div class="subtle">flow or connection activity</div></div>
        <div class="summary-card"><div class="k">Highest req/s</div><div class="v">${esc(highestRps?.service || '—')}</div><div class="subtle">${fmtRate(S.targetHist[targetKey(highestRps || {})]?.rate || 0)}</div></div>
        <div class="summary-card"><div class="k">Highest throughput</div><div class="v">${esc(highestThroughput?.service || '—')}</div><div class="subtle">${fmtBps(targetThroughput(highestThroughput || {}))}</div></div>
        <div class="summary-card"><div class="k">Slowest</div><div class="v">${esc(slowest?.service || '—')}</div><div class="subtle">${fmtLat(slowest?.stats?.avg_latency_us || 0)}</div></div>
    `;
}
function updateTargetsMeta(totalVisible) {
    const quickOn = Object.entries(S.targetQuickFilters).filter(([, on]) => on).map(([name]) => name).join(', ');
    document.getElementById('targets-meta').textContent = `${totalVisible} shown · ${S.allTargets.length} total${S.targetHotOnly ? ' · hot only' : ''}${S.targetIssuesOnly ? ' · issues only' : ''}${quickOn ? ` · ${quickOn}` : ''}`;
}
function syncTargetQuickFilters() {
    Object.entries(S.targetQuickFilters).forEach(([name, on]) => {
        document.getElementById(`target-chip-${name}`)?.classList.toggle('on', on);
    });
}
function filterTargets() { S.targetSearch = document.getElementById('target-search').value || ''; renderTargets(getVisibleTargets(), false); }
function changeTargetSort() { S.targetSort = document.getElementById('target-sort').value || 'risk'; renderTargets(getVisibleTargets(), false); }
function toggleTargetIssues() {
    S.targetIssuesOnly = !S.targetIssuesOnly;
    document.getElementById('target-issues-btn').classList.toggle('on', S.targetIssuesOnly);
    renderTargets(getVisibleTargets(), false);
}
function toggleTargetHot() {
    S.targetHotOnly = !S.targetHotOnly;
    document.getElementById('target-hot-btn').classList.toggle('on', S.targetHotOnly);
    renderTargets(getVisibleTargets(), false);
}
function toggleTargetQuickFilter(name) {
    S.targetQuickFilters[name] = !S.targetQuickFilters[name];
    syncTargetQuickFilters();
    renderTargets(getVisibleTargets(), false);
}
function resetTargetFilters() {
    S.targetSearch = ''; S.targetSort = 'risk'; S.targetIssuesOnly = false; S.targetHotOnly = false;
    S.targetQuickFilters = { open: false, probe: false, latency: false, throughput: false };
    document.getElementById('target-search').value = '';
    document.getElementById('target-sort').value = 'risk';
    document.getElementById('target-issues-btn').classList.remove('on');
    document.getElementById('target-hot-btn').classList.remove('on');
    syncTargetQuickFilters();
    renderTargets(getVisibleTargets(), false);
}
let _lastTargetKeys = [];
function renderTargets(targets, inplace) {
    const tbody = document.getElementById('targets-tbody');
    const keys = targets.map(targetKey);
    if (!targets.length) {
        renderTargetsSummary([]);
        tbody.innerHTML = '<tr><td colspan="11" class="empty">No targets match the current filters</td></tr>';
        _lastTargetKeys = [];
        window._tgts = [];
        closeTargetDetail();
        updateTargetsMeta(0);
        return;
    }
    const canInplace = inplace && _lastTargetKeys.length === keys.length && _lastTargetKeys.every((k,i) => k === keys[i]);
    if (canInplace) {
        const rows = tbody.querySelectorAll('tr');
        targets.forEach((t, i) => {
            const row = rows[i]; if (!row) return;
            const key = targetKey(t);
            const h = S.targetHist[key], rate = h?.rate ?? 0;
            const errPct = t.stats?.error_rate_pct || 0;
            const sc = errPct > 5 ? 'var(--red)' : errPct > 1 ? 'var(--yellow)' : 'var(--green)';
            const wPct = t.weight > 0 ? (t.weight * 100).toFixed(0) : 0;
            const throughput = targetThroughput(t);
            const healthClass = targetHealthClass(t);
            row.className = (errPct > 5 ? 'row-err ' : errPct > 1 || !t.probe_healthy ? 'row-warn ' : '') + 'row-click';
            const wc = row.cells[4];
            if (wc) wc.innerHTML = `<div class="cell-stack"><span><span class="wbar"><span class="wbar-fill" style="width:${wPct}%"></span></span><span style="font-size:0.68rem;color:var(--text-4)">${wPct}%</span></span><span class="cell-sub">fixed ${((t.fixed_weight || 0) * 100).toFixed(0)}%</span></div>`;
            const rc = row.cells[5];
            if (rc) {
                const d = S.prevTargets[key];
                const arrow = d ? trendArrow(d.deltaReq, 0) : '';
                rc.innerHTML = `<div class="target-rate-cell">${spark(h ? h.req.slice(-20) : [], 48, 14, sc)}<div><span style="font-size:0.76rem">${rate.toFixed(1)}</span> ${arrow} <span class="subtle">5s ${fmtRate(topoReqRateStable(topoFlow(t)))}</span></div></div>`;
            }
            const tc = row.cells[6];
            if (tc) {
                tc.innerHTML = `<div class="target-throughput-cell"><span class="target-flowbar"><span class="target-flowbar-fill" style="width:${Math.max(6, Math.min(100, targetHeat(t) * 100))}%"></span></span><span>${fmtBps(throughput)}</span><span class="subtle">${fmtAgoMs(targetLastActive(t))}</span></div>`;
            }
            const ec = row.cells[7];
            if (ec) {
                const d = S.prevTargets[key];
                const arrow = d ? trendArrow(d.deltaErr, 0) : '';
                ec.innerHTML = trendVal(errPct, d?.deltaErr || 0, [0.5, 2, 5], true) + ' ' + arrow;
            }
            const lc = row.cells[8];
            if (lc) {
                const d = S.prevTargets[key];
                lc.innerHTML = trendLat(t.stats?.avg_latency_us || 0, d?.deltaLat || 0);
            }
            const cc = row.cells[9];
            if (cc) {
                const d = S.prevTargets[key];
                cc.innerHTML = trendConn(t.active_connections || 0, d?.deltaConn || 0);
            }
            const bc = row.cells[10];
            if (bc) bc.innerHTML = `<div class="cell-stack"><div class="target-badges tight">${targetHeatChip(t)} <span class="target-health-badge ${healthClass}">${esc(targetHealthLabel(t))}</span></div><span>${cbTL(t.circuit_breaker_history)} <span class="cb cb-${esc(t.circuit_breaker)}">${esc(t.circuit_breaker)}</span></span></div>`;
        });
    } else {
        tbody.innerHTML = targets.map((t, i) => {
            const key = targetKey(t);
            const h = S.targetHist[key], rate = h?.rate ?? 0, reqD = h ? h.req.slice(-20) : [];
            const errPct = t.stats?.error_rate_pct || 0;
            const cls = errPct > 5 ? 'row-err' : errPct > 1 || !t.probe_healthy ? 'row-warn' : '';
            const wPct = t.weight > 0 ? (t.weight * 100).toFixed(0) : 0;
            const fixedPct = ((t.fixed_weight || 0) * 100).toFixed(0);
            const sc = errPct > 5 ? 'var(--red)' : errPct > 1 ? 'var(--yellow)' : 'var(--green)';
            const throughput = targetThroughput(t);
            const healthClass = targetHealthClass(t);
            return `<tr class="${cls} row-click" data-action="toggle-target-detail" data-index="${i}">
                <td style="color:var(--text-4);font-size:0.7rem">${i+1}</td>
                <td><div class="cell-stack"><span class="cell-main">${esc(t.service)}</span><span class="cell-sub mono">${esc((t.host || '*') + t.path)}</span><div class="target-badges tight">${targetHeatChip(t)}</div></div></td>
                <td><div class="cell-stack"><span class="cell-main mono">${esc(t.url)}</span><span class="cell-sub">source: ${esc(t.source || 'runtime')} · active ${fmtAgoMs(targetLastActive(t))}</span></div></td>
                <td><div class="target-badges"><span class="tag">${esc(t.protocol)}</span>${t.tls?'<span class="tag tag-tls">TLS</span>':''}${t.http2?'<span class="tag tag-grpc">H2</span>':''}<span class="target-health-badge ${healthClass}">${esc(targetHealthLabel(t))}</span></div></td>
                <td><div class="cell-stack"><span><span class="wbar"><span class="wbar-fill" style="width:${wPct}%"></span></span><span style="font-size:0.68rem;color:var(--text-4)">${wPct}%</span></span><span class="cell-sub">fixed ${fixedPct}%</span></div></td>
                <td><div class="target-rate-cell">${spark(reqD,48,14,sc)}<div><span style="font-size:0.76rem">${rate.toFixed(1)}</span> <span class="subtle">5s ${fmtRate(topoReqRateStable(topoFlow(t)))}</span></div></div></td>
                <td><div class="target-throughput-cell"><span class="target-flowbar"><span class="target-flowbar-fill" style="width:${Math.max(6, Math.min(100, targetHeat(t) * 100))}%"></span></span><span>${fmtBps(throughput)}</span><span class="subtle">${fmt(t.stats?.bytes_total || 0)} B total</span></div></td>
                <td style="color:${errPct>5?'var(--red)':errPct>1?'var(--yellow)':'var(--text-3)'}">${errPct}%</td>
                <td>${t.stats?.avg_latency_us ? fmtLat(t.stats.avg_latency_us) : '-'}</td>
                <td>${t.active_connections||0}</td>
                <td><div class="cell-stack"><span>${cbTL(t.circuit_breaker_history)} <span class="cb cb-${esc(t.circuit_breaker)}">${esc(t.circuit_breaker)}</span></span><span class="cell-sub">${fmt(t.stats?.requests||0)} req · ${fmtAgoMs(targetLastActive(t))}</span></div></td>
            </tr>`;
        }).join('');
    }
    _lastTargetKeys = keys;
    window._tgts = targets;
    renderTargetsSummary(targets);
    updateTargetsMeta(targets.length);
    if (S.selectedTargetKey) {
        const idx = targets.findIndex(t => targetKey(t) === S.selectedTargetKey);
        if (idx >= 0) toggleDetail(idx, true);
        else closeTargetDetail();
    }
}
function toggleDetail(i, forceOpen = false) {
    const p=document.getElementById('target-detail');
    const t=window._tgts[i]; if(!t)return;
    const key = targetKey(t);
    if(!forceOpen && S.selectedTarget===i && S.selectedTargetKey===key){closeTargetDetail();return;}
    S.selectedTarget=i;
    S.selectedTargetKey=key;
    const h=S.targetHist[key]||{req:[],err:[],errPct:[],lat:[],bytesRate:[],rate:0};
    h.rate ??= 0;
    const flow = topoFlow(t);
    const throughput = targetThroughput(t);
    const relatedRoutes = targetRelatedRoutes(t);
    let cbH='';
    if(t.circuit_breaker_history?.length){
        cbH='<div style="overflow-x:auto"><table style="width:100%"><tr><th>Time</th><th>From</th><th>To</th></tr>';
        t.circuit_breaker_history.slice(0,10).forEach(s=>{cbH+=`<tr><td style="font-size:0.75rem">${fmtTime(s.timestamp_ms)}</td><td><span class="cb cb-${s.from}">${s.from}</span></td><td><span class="cb cb-${s.to}">${s.to}</span></td></tr>`;});
        cbH+='</table></div>';
    } else cbH='<span style="color:var(--text-4)">No transitions</span>';
    p.className = 'detail-panel target-side-panel open';
    p.innerHTML=`
        <div class="detail-head"><span class="detail-title">${esc(t.service)} &mdash; ${esc(t.url)}</span><div class="target-side-actions"><button class="btn btn-sm" data-action="focus-target-topology" data-index="${i}">View in topology</button><button class="btn btn-sm" data-action="close-target-detail">Close</button></div></div>
        <div class="detail-grid">
            <div>
                <div class="target-detail-grid">
                    <div class="summary-card"><div class="k">Circuit</div><div class="v">${esc(t.circuit_breaker)}</div><div class="subtle">${esc(targetHealthLabel(t))}</div></div>
                    <div class="summary-card"><div class="k">Req/sec</div><div class="v">${h.rate.toFixed(2)}</div><div class="subtle">5s ${fmtRate(topoReqRateStable(flow))}</div></div>
                    <div class="summary-card"><div class="k">Throughput</div><div class="v">${fmtBps(throughput)}</div><div class="subtle">${fmt(t.stats?.bytes_total||0)} B total</div></div>
                    <div class="summary-card"><div class="k">Heat</div><div class="v">${(targetHeat(t) * 100).toFixed(0)}%</div><div class="subtle">${esc(flow?.activity_level || 'idle')}</div></div>
                    <div class="summary-card"><div class="k">Latency</div><div class="v">${t.stats?.avg_latency_us?fmtLat(t.stats.avg_latency_us):'-'}</div><div class="subtle">err ${fmtPct(t.stats?.error_rate_pct||0)}</div></div>
                    <div class="summary-card"><div class="k">Connections</div><div class="v">${t.active_connections||0}</div><div class="subtle">active ${fmtAgoMs(targetLastActive(t))}</div></div>
                </div>
                <h4>Route context</h4><dl class="detail-kv">
                    <dt>Host</dt><dd>${esc(t.host)}</dd><dt>Path</dt><dd>${esc(t.path)}</dd>
                    <dt>Protocol</dt><dd>${esc(t.protocol)}${t.tls?' +TLS':''}${t.http2?' +H2':''}</dd>
                    <dt>Source</dt><dd>${esc(t.source)}</dd>
                    <dt>Probe</dt><dd>${esc(t.probe_healthy ? 'healthy' : 'unhealthy')}</dd>
                    <dt>Last active</dt><dd>${fmtAgoMs(targetLastActive(t))}</dd>
                    <dt>Weight</dt><dd>${(t.weight*100).toFixed(1)}% (fixed: ${(t.fixed_weight*100).toFixed(1)}%)</dd>
                </dl>
                <h4 style="margin-top:0.95rem">Owning routes</h4>
                <div class="target-route-context-list">${relatedRoutes.map(rt => `<div class="target-route-context"><div class="panel-item-title">${esc((rt.host || '*') + (rt.path || '/'))}</div><div class="panel-item-sub">${esc(rt.source || 'runtime')} · ${fmtRate(topoReqRateStable(topoFlow(rt)))} · ${fmtBps(targetThroughput(rt))}</div></div>`).join('') || '<div class="subtle">No related routes found</div>'}</div>
            </div>
            <div>
                <h4>Stats</h4><dl class="detail-kv">
                    <dt>Requests</dt><dd>${fmt(t.stats?.requests||0)}</dd>
                    <dt>Errors</dt><dd>${fmt(t.stats?.errors||0)} (${t.stats?.error_rate_pct||0}%)</dd>
                    <dt>Avg Latency</dt><dd>${t.stats?.avg_latency_us?fmtLat(t.stats.avg_latency_us):'-'}</dd>
                    <dt>Bytes</dt><dd>${fmt(t.stats?.bytes_total||0)}</dd>
                    <dt>Connections</dt><dd>${t.active_connections||0}</dd>
                    <dt>Upstream</dt><dd class="mono">${esc(t.url)}</dd>
                </dl>
                <h4 style="margin-top:0.95rem">Trend timelines</h4>
                <div class="target-trend-grid">
                    ${targetTrendCard('Request rate', fmtRate(h.rate), h.req.map((v, idx, arr) => idx === 0 ? 0 : Math.max(0, v - arr[idx - 1])), 'var(--accent)', 'derived from cumulative request deltas')}
                    ${targetTrendCard('Throughput', fmtBps(throughput), h.bytesRate || [], '#60a5fa', 'static refresh cadence')}
                    ${targetTrendCard('Error rate', fmtPct(t.stats?.error_rate_pct || 0), h.errPct || [], 'var(--red)', 'percent of requests ending in error')}
                    ${targetTrendCard('Latency', t.stats?.avg_latency_us?fmtLat(t.stats.avg_latency_us):'-', h.lat || [], '#fbbf24', 'average upstream latency')}
                </div>
                <h4 style="margin-top:0.95rem">Circuit breaker</h4><div style="margin-bottom:0.55rem" class="target-badges">${targetHeatChip(t)} <span class="target-health-badge ${targetHealthClass(t)}">${esc(targetHealthLabel(t))}</span> <span class="cb cb-${esc(t.circuit_breaker)}">${esc(t.circuit_breaker)}</span></div>${cbH}
            </div>
        </div>`;
    if (!forceOpen) p.scrollIntoView({behavior:'smooth',block:'nearest'});
}

