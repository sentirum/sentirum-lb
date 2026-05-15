// ===== TOPOLOGY =====
function topologyTargets(hosts) {
    return (hosts || []).flatMap(host =>
        (host.routes || []).flatMap(route =>
            (route.targets || []).map(t => ({ ...t, host: host.host || '', path: route.path || '/' }))
        )
    );
}
function topologyNeedsAnimation(data = S.topoData) {
    if (!data) return false;
    return topologyTargets(topologyVisibleHosts(data)).some(t => topoFlowHot(topoFlow(t)));
}
function scheduleTopoFrame() {
    if (S.topoAnimFrame) return;
    S.topoAnimFrame = requestAnimationFrame(ts => {
        S.topoAnimFrame = null;
        if (!document.getElementById('page-topology')?.classList.contains('active')) return;
        drawTopo(ts);
        if (topologyNeedsAnimation()) scheduleTopoFrame();
    });
}
function stopTopoAnimation() {
    if (!S.topoAnimFrame) return;
    cancelAnimationFrame(S.topoAnimFrame);
    S.topoAnimFrame = null;
}
function hideTopoTooltip() {
    S.topoHoverItem = null;
    const el = document.getElementById('topo-tooltip');
    if (el) {
        el.classList.add('hidden');
        el.style.transform = 'translate(-9999px, -9999px)';
    }
}
function renderTopoTooltip(item, clientX, clientY) {
    const el = document.getElementById('topo-tooltip');
    const canvas = document.getElementById('topo-canvas');
    const wrap = canvas?.parentElement;
    if (!el || !canvas || !wrap || !item) return;
    const flow = topoFlow(item.data);
    const stats = item.data?.stats || {};
    const title = item.data?.title || item.data?.service || item.data?.path || 'Flow';
    const sub = item.data?.subtitle || topoRoleLabel(item.kind);
    el.innerHTML = `
        <div class="topo-tooltip-title">${esc(title)}</div>
        <div class="topo-tooltip-sub">${esc(sub)}</div>
        <dl class="topo-tooltip-grid">
            <dt>Req/s</dt><dd>${fmtRate(topoReqRate(flow))}</dd>
            <dt>Throughput</dt><dd>${fmtBps(topoByteRate(flow))}</dd>
            <dt>5s req/s</dt><dd>${fmtRate(topoReqRateStable(flow))}</dd>
            <dt>5s bytes</dt><dd>${fmtBps(topoByteRateStable(flow))}</dd>
            <dt>Activity</dt><dd>${esc(flow?.activity_level || 'idle')}</dd>
            <dt>Heat</dt><dd>${(topoHeatLevel(flow) * 100).toFixed(0)}%</dd>
            ${item.kind === 'target' ? `<dt>Latency</dt><dd>${fmtLat(stats?.avg_latency_us || 0)}</dd><dt>Error rate</dt><dd>${fmtPct(stats?.error_rate_pct || 0)}</dd>` : ''}
            ${flow?.last_active_ms_ago != null ? `<dt>Last active</dt><dd>${fmtAgoMs(flow.last_active_ms_ago)}</dd>` : ''}
        </dl>`;
    el.classList.remove('hidden');
    const wrapRect = wrap.getBoundingClientRect();
    const offsetX = clientX - wrapRect.left + 14;
    const offsetY = clientY - wrapRect.top + 14;
    el.style.transform = 'translate(0, 0)';
    const width = el.offsetWidth;
    const height = el.offsetHeight;
    const left = clamp(offsetX, 10, Math.max(10, wrapRect.width - width - 10));
    const top = clamp(offsetY, 10, Math.max(10, wrapRect.height - height - 10));
    el.style.left = `${left}px`;
    el.style.top = `${top}px`;
}
function topoPointSegDist(px, py, x1, y1, x2, y2) {
    const dx = x2 - x1;
    const dy = y2 - y1;
    const denom = (dx * dx) + (dy * dy);
    if (!denom) return Math.hypot(px - x1, py - y1);
    const t = clamp((((px - x1) * dx) + ((py - y1) * dy)) / denom, 0, 1);
    const sx = x1 + dx * t;
    const sy = y1 + dy * t;
    return Math.hypot(px - sx, py - sy);
}
function topoHitAt(point) {
    const nodeHit = S.topoNodeRects.find(n => ((point.x - n.x) ** 2) + ((point.y - n.y) ** 2) <= n.r ** 2);
    if (nodeHit) return nodeHit;
    return S.topoHitAreas.find(area => topoPointSegDist(point.x, point.y, area.x1, area.y1, area.x2, area.y2) <= area.pad);
}
function updateTopologyHistories(data) {
    if (!data?.hosts) return;
    const seen = new Set();
    data.hosts.forEach(host => {
        (host.routes || []).forEach(route => {
            const key = topologyRouteKey(host.host || '*', route.path || '/');
            seen.add(key);
            if (!S.topoRouteHist[key]) S.topoRouteHist[key] = { req: [], bytes: [], errPct: [], lat: [], ts: [] };
            const h = S.topoRouteHist[key];
            const routeTargets = route.targets || [];
            const routeReqs = routeTargets.reduce((sum, t) => sum + Number(t.stats?.requests || 0), 0);
            const routeErrs = routeTargets.reduce((sum, t) => sum + Number(t.stats?.errors || 0), 0);
            const weightedLat = routeTargets.reduce((sum, t) => sum + ((Number(t.stats?.avg_latency_us || 0)) * (Number(t.stats?.requests || 0))), 0);
            const avgLat = routeReqs > 0 ? weightedLat / routeReqs : Math.max(0, ...routeTargets.map(t => Number(t.stats?.avg_latency_us || 0)));
            h.req.push(topoReqRateStable(topoFlow(route)));
            h.bytes.push(topoByteRateStable(topoFlow(route)));
            h.errPct.push(routeReqs > 0 ? (routeErrs / routeReqs) * 100 : 0);
            h.lat.push(avgLat);
            h.ts.push(Date.now());
            if (h.req.length > HIST) {
                h.req.shift();
                h.bytes.shift();
                h.errPct.shift();
                h.lat.shift();
                h.ts.shift();
            }
        });
    });
    Object.keys(S.topoRouteHist).forEach(key => {
        if (!seen.has(key) && S.topoRouteHist[key].ts?.length && (Date.now() - S.topoRouteHist[key].ts[S.topoRouteHist[key].ts.length - 1] > TARGET_HISTORY_TTL_MS)) {
            delete S.topoRouteHist[key];
        }
    });
}
const TOPOLOGY_FILTER_MODES = ['all', 'issues', 'hot'];

function topologyVisibleHosts(data = S.topoData) {
    if (!data) return [];
    let hosts = [...(data.hosts || [])];
    if (S.topologyHostFilter !== '*') hosts = hosts.filter(host => (host.host || '*') === S.topologyHostFilter);
    if (S.topologyMode === 'issues') {
        hosts = hosts.filter(host => (host.routes || []).some(route => (route.targets || []).some(t => t.circuit_breaker !== 'closed' || (t.stats?.error_rate_pct || 0) > 0)));
    } else if (S.topologyMode === 'hot') {
        hosts = hosts.filter(host => (host.routes || []).some(route => topoFlowHot(topoFlow(route)) || (route.targets || []).some(t => topoFlowHot(topoFlow(t)) || (t.active_connections || 0) > 0)));
    }
    return hosts;
}
function syncTopologyControls() {
    TOPOLOGY_FILTER_MODES.forEach(name => document.getElementById(`topo-mode-${name}`)?.classList.toggle('on', name === S.topologyMode));
    document.getElementById('topo-heat-btn')?.classList.toggle('on', S.topologyHeatMode);
}
function refreshTopologyView() {
    hideTopoTooltip();
    renderTopologyPanels(S.topoData);
    drawTopo();
    scheduleTopoFrame();
}
function setTopologyMode(mode) {
    S.topologyMode = TOPOLOGY_FILTER_MODES.includes(mode) ? mode : 'all';
    S.topologySelectedTargetKey = null;
    syncTopologyControls();
    refreshTopologyView();
}
function toggleTopologyHeatMode() {
    S.topologyHeatMode = !S.topologyHeatMode;
    syncTopologyControls();
    refreshTopologyView();
}
function setTopologyHostFilter(host) {
    S.topologyHostFilter = host;
    S.topologySelectedTargetKey = null;
    refreshTopologyView();
}
function selectTopologyTarget(key) {
    S.topologySelectedTargetKey = key || null;
    refreshTopologyView();
}
function resetTopologyFocus() {
    S.topologyMode = 'all';
    S.topologyHeatMode = false;
    S.topologyHostFilter = '*';
    S.topologySelectedTargetKey = null;
    S.topoScale = 1;
    S.topoPan = { x: 0, y: 0 };
    syncTopologyControls();
    refreshTopologyView();
}
function renderTopologyPanels(data) {
    syncTopologyControls();
    if (!data) {
        hideTopoTooltip();
        document.getElementById('topology-summary').innerHTML = '';
        document.getElementById('topology-hosts').innerHTML = '';
        document.getElementById('topology-meta').textContent = 'Topology unavailable';
        document.getElementById('topology-inspector').innerHTML = `<div class="panel-head"><div class="panel-title">Topology inspector</div></div><div class="panel-body"><div class="empty">Topology data is not available yet</div></div>`;
        return;
    }
    const allHosts = data.hosts || [];
    const visibleHosts = topologyVisibleHosts(data);
    const routeCount = visibleHosts.reduce((n, host) => n + (host.routes?.length || 0), 0);
    const targets = topologyTargets(visibleHosts);
    const openCount = targets.filter(t => t.circuit_breaker === 'open').length;
    const halfOpenCount = targets.filter(t => t.circuit_breaker === 'halfopen').length;
    const hotTargets = targets.filter(t => topoFlowHot(topoFlow(t)) || (t.active_connections || 0) > 0).length;
    const hottestHost = [...visibleHosts].sort((a, b) => topoReqRateStable(topoFlow(b)) - topoReqRateStable(topoFlow(a)))[0];
    document.getElementById('topology-summary').innerHTML = `
        <div class="summary-card"><div class="k">Visible hosts</div><div class="v">${visibleHosts.length}<span class="subtle"> / ${allHosts.length}</span></div></div>
        <div class="summary-card"><div class="k">Routes</div><div class="v">${routeCount}</div></div>
        <div class="summary-card"><div class="k">Targets</div><div class="v">${targets.length}</div></div>
        <div class="summary-card"><div class="k">Open / half-open</div><div class="v">${openCount} / ${halfOpenCount}</div></div>
        <div class="summary-card"><div class="k">LB req/s</div><div class="v">${fmtRate(topoReqRate(topoFlow(data.lb)))}</div></div>
        <div class="summary-card"><div class="k">LB throughput</div><div class="v">${fmtBps(topoByteRate(topoFlow(data.lb)))}</div></div>
        <div class="summary-card"><div class="k">Hot targets</div><div class="v">${hotTargets}</div></div>
        <div class="summary-card"><div class="k">Hottest host</div><div class="v">${esc(hottestHost?.host || '*')}</div></div>
    `;
    document.getElementById('topology-hosts').innerHTML = [`<button class="topo-host-btn ${S.topologyHostFilter === '*' ? 'on' : ''}" data-action="set-topology-host-filter" data-host="${attrEnc('*')}">All hosts</button>`]
        .concat(allHosts.map(host => {
            const name = host.host || '*';
            const flow = topoFlow(host);
            return `<button class="topo-host-btn ${S.topologyHostFilter === name ? 'on' : ''}" data-action="set-topology-host-filter" data-host="${attrEnc(name)}" title="Filter topology to host ${esc(name)}">${esc(name)} <span class="subtle">${fmtRate(topoReqRate(flow))}</span></button>`;
        }))
        .join('');
    document.getElementById('topology-meta').textContent = `${visibleHosts.length} host lane(s) · filter ${S.topologyMode}${S.topologyHeatMode ? ' · color by heat' : ''}${S.topologySelectedTargetKey ? ' · target pinned' : ''}`;

    const selected = targets.find(t => targetKey(t) === S.topologySelectedTargetKey);

    const routeItems = visibleHosts.map(host => {
        const routes = host.routes || [];
        return routes.map(route => {
            const hostLabel = host.host || '*';
            const flow = topoFlow(route);
            const routeHist = S.topoRouteHist[topologyRouteKey(hostLabel, route.path || '/')] || { req: [], bytes: [] };
            const routeErr = Math.max(...(route.targets || []).map(t => t.stats?.error_rate_pct || 0), 0);
            const routeHeat = topoHeatLevel(flow);
            const routeSparkColor = S.topologyHeatMode
                ? routeHeat >= 0.82 ? '#fb923c' : routeHeat >= 0.58 ? '#d946ef' : routeHeat >= 0.34 ? '#60a5fa' : '#22d3ee'
                : 'var(--accent)';
            const routeTargets = route.targets || [];
            const openTargets = routeTargets.filter(t => t.circuit_breaker === 'open').length;
            const halfOpenTargets = routeTargets.filter(t => t.circuit_breaker === 'halfopen').length;
            const targetChips = routeTargets.map(t => {
                const key = targetKey({ host: hostLabel, path: route.path, service: t.service, url: t.url });
                const targetFlow = topoFlow(t);
                const cls = S.topologySelectedTargetKey === key ? 'active' : t.circuit_breaker === 'open' ? 'danger' : topoFlowHot(targetFlow) || (t.stats?.error_rate_pct || 0) > 0 || (t.active_connections || 0) > 0 ? 'hot' : '';
                return `<button class="topo-target-chip ${cls}" data-action="select-topology-target" data-key="${attrEnc(key)}" title="${esc(`${t.service || 'target'} · ${t.url || ''} · ${t.circuit_breaker || 'closed'}`)}">${esc(t.service)} · ${fmtRate(topoReqRate(targetFlow))}</button>`;
            }).join('');
            const routeBadge = openTargets ? `<span class="topo-state-badge danger">${openTargets} open</span>` : halfOpenTargets ? `<span class="topo-state-badge warn">${halfOpenTargets} half-open</span>` : routeErr > 0 ? `<span class="topo-state-badge accent">${fmtPct(routeErr)} err</span>` : '';
            return `<div class="topo-route-item"><div class="topo-route-head"><div><div class="panel-item-title">${esc(hostLabel)} ${esc(route.path)}</div><div class="panel-item-sub">${esc(route.matcher || 'prefix')} matcher · ${routeTargets.length} target(s) · ${fmtBps(topoByteRateStable(flow))}</div></div><div class="topo-route-metrics"><div class="topo-route-trend">${spark(routeHist.req.slice(-20), 68, 16, routeSparkColor) || '<span class="subtle">no trend</span>'}<span class="subtle">${fmtRate(topoReqRateStable(flow))}</span></div>${S.topologyHeatMode ? `<span class="topo-heat-badge">heat ${(routeHeat * 100).toFixed(0)}%</span>` : ''}${routeBadge}<span class="metric-chip">${fmtRate(topoReqRateStable(flow))} · ${fmtPct(routeErr)}</span></div></div><div class="topo-route-targets">${targetChips}</div></div>`;
        }).join('');
    }).join('') || '<div class="empty">No routes match the current topology filters</div>';

    const selectedFlow = topoFlow(selected);
    const focusCard = selected
        ? `<div class="topo-focus-card"><div class="topo-focus-head"><div><div class="panel-item-title">Selected target</div><div class="panel-item-sub">${esc(selected.service)} · ${esc(selected.url)}${S.topologyHeatMode ? ' · heat-aware view' : ''}</div></div><div class="topo-focus-actions"><button class="btn btn-sm" data-action="select-topology-target" data-key="">Clear selection</button></div></div><dl class="topo-kv" style="margin-top:0.65rem"><dt>Route</dt><dd>${esc((selected.host || '*') + (selected.path || ''))}</dd><dt>Protocol</dt><dd>${esc(selected.protocol || 'http')}</dd><dt>Circuit</dt><dd>${esc(selected.circuit_breaker || 'closed')}</dd><dt>Live req/s</dt><dd>${fmtRate(topoReqRate(selectedFlow))}</dd><dt>Throughput</dt><dd>${fmtBps(topoByteRate(selectedFlow))}</dd><dt>Heat level</dt><dd>${(topoHeatLevel(selectedFlow) * 100).toFixed(0)}%</dd><dt>Requests</dt><dd>${fmt(selected.stats?.requests || 0)}</dd><dt>Error rate</dt><dd>${fmtPct(selected.stats?.error_rate_pct || 0)}</dd><dt>Latency</dt><dd>${fmtLat(selected.stats?.avg_latency_us || 0)}</dd><dt>Connections</dt><dd>${selected.active_connections || 0}</dd><dt>Last active</dt><dd>${fmtAgoMs(selectedFlow?.last_active_ms_ago)}</dd></dl></div>`
        : `<div class="topo-focus-card"><div class="panel-item-title">How to use this map</div><div class="panel-item-sub">Flow dots reflect short-window traffic. Hover edges for live metrics, use Heat map to bias colors by traffic intensity, and click any target node to pin req/s and throughput details.</div></div>`;

    document.getElementById('topology-inspector').innerHTML = `
        <div class="panel-head"><div><div class="panel-title">Topology inspector</div><div class="subtle">Actionable route lanes instead of a passive graph</div></div></div>
        <div class="panel-body">
            <dl class="mini-kv" style="margin-bottom:0.9rem">
                <dt>Load balancer requests</dt><dd>${fmt(data.lb?.requests || 0)}</dd>
                <dt>Live req/s</dt><dd>${fmtRate(topoReqRate(topoFlow(data.lb)))}</dd>
                <dt>Throughput</dt><dd>${fmtBps(topoByteRate(topoFlow(data.lb)))}</dd>
                <dt>Active connections</dt><dd>${fmt(data.lb?.active_connections || 0)}</dd>
                <dt>Error rate</dt><dd>${data.lb?.error_rate || 0}%</dd>
                <dt>Filter mode</dt><dd>${esc(S.topologyMode)}</dd>
                <dt>Heat map</dt><dd>${S.topologyHeatMode ? 'Enabled' : 'Off'}</dd>
            </dl>
            ${focusCard}
            <div class="panel-title" style="margin-bottom:0.55rem">Visible route lanes</div>
            <div class="topo-route-list">${routeItems}</div>
        </div>`;
}
function drawTopoFlowDots(ctx, x1, y1, x2, y2, color, flow, phase, emphasis = 0) {
    const activity = topoActivityRank(flow);
    const reqRate = topoReqRate(flow);
    if (!activity && reqRate <= 0) return;
    const dx = x2 - x1;
    const dy = y2 - y1;
    const len = Math.hypot(dx, dy);
    if (len < 24) return;
    const count = Math.max(1, Math.min(6, Math.round(activity + Math.log2(1 + reqRate))));
    const speed = 0.12 + clamp(reqRate / 120, 0, 0.7) + emphasis * 0.03;
    const size = 1.7 + activity * 0.6 + emphasis * 0.25;
    ctx.save();
    ctx.fillStyle = color;
    ctx.shadowColor = color;
    ctx.shadowBlur = 8 + emphasis * 2;
    for (let i = 0; i < count; i++) {
        const t = (phase * speed + (i / count)) % 1;
        const px = x1 + dx * t;
        const py = y1 + dy * t;
        ctx.globalAlpha = 0.42 + ((i + 1) / count) * 0.44;
        ctx.beginPath();
        ctx.arc(px, py, size, 0, Math.PI * 2);
        ctx.fill();
    }
    ctx.restore();
    ctx.globalAlpha = 1;
}
function drawTopoArrowheads(ctx, x1, y1, x2, y2, color, intensity = 1) {
    const dx = x2 - x1;
    const dy = y2 - y1;
    const len = Math.hypot(dx, dy);
    if (len < 30) return;
    const ux = dx / len;
    const uy = dy / len;
    const px = -uy;
    const py = ux;
    const size = 6 + intensity * 1.4;
    const step = Math.min(30, Math.max(18, len * 0.18));
    ctx.save();
    ctx.strokeStyle = color;
    ctx.lineWidth = 1.1 + intensity * 0.15;
    ctx.globalAlpha = 0.62;
    for (let i = 2; i >= 1; i--) {
        const cx = x2 - ux * (i * step);
        const cy = y2 - uy * (i * step);
        ctx.beginPath();
        ctx.moveTo(cx - ux * size + px * size * 0.55, cy - uy * size + py * size * 0.55);
        ctx.lineTo(cx, cy);
        ctx.lineTo(cx - ux * size - px * size * 0.55, cy - uy * size - py * size * 0.55);
        ctx.stroke();
    }
    ctx.restore();
}
function drawTopoEdgeLabel(ctx, x1, y1, x2, y2, text, tone, active = false) {
    if (!active || !text) return;
    const mx = (x1 + x2) / 2;
    const my = (y1 + y2) / 2;
    const padX = 7;
    const padY = 4;
    ctx.save();
    ctx.font = '600 8px system-ui';
    const w = ctx.measureText(text).width + padX * 2;
    const h = 18;
    ctx.fillStyle = 'rgba(9,9,11,0.78)';
    ctx.strokeStyle = tone;
    ctx.lineWidth = 1;
    ctx.beginPath();
    if (ctx.roundRect) ctx.roundRect(mx - w / 2, my - 24, w, h, 8); else ctx.rect(mx - w / 2, my - 24, w, h);
    ctx.fill();
    ctx.stroke();
    ctx.fillStyle = '#e4e4e7';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(text, mx, my - 15);
    ctx.restore();
}
function drawTopo(nowTs = performance.now()) {
    if(!S.topoData)return;
    const c=document.getElementById('topo-canvas'); if(!c)return;
    const ctx=c.getContext('2d'), dpr=devicePixelRatio||1, r=c.getBoundingClientRect();
    c.width=r.width*dpr; c.height=r.height*dpr; ctx.scale(dpr,dpr);
    const W=r.width, H=r.height;
    const visibleHosts = topologyVisibleHosts(S.topoData);
    const phase = nowTs / MS_PER_SEC;
    S.topoNodeRects = [];
    S.topoHitAreas = [];
    ctx.clearRect(0,0,W,H);
    ctx.save();
    ctx.translate(80 + S.topoPan.x, 36 + S.topoPan.y);
    ctx.scale(S.topoScale, S.topoScale);

    const laneGap = 28;
    const routeGap = 78;
    const lanePadding = 18;
    const hostHeights = visibleHosts.map(host => Math.max(96, (host.routes?.length || 1) * routeGap + lanePadding));
    const totalHeight = hostHeights.reduce((a, b) => a + b, 0) + Math.max(0, visibleHosts.length - 1) * laneGap;
    const lbX = 78;
    const lbY = totalHeight > 0 ? totalHeight / 2 : 120;
    const lbFlow = topoFlow(S.topoData.lb);
    const lbPalette = topoResolvePalette('closed', lbFlow, false);
    const lbPulse = 24 + clamp(Math.log2(1 + topoReqRate(lbFlow)) * 1.7, 0, 8);

    ctx.beginPath();
    ctx.arc(lbX, lbY, lbPulse + 6 + Math.sin(phase * 4) * Math.min(5, topoActivityRank(lbFlow) * 2), 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(129,140,248,0.12)';
    ctx.fill();
    ctx.beginPath();
    ctx.arc(lbX, lbY, lbPulse + 1.5, 0, Math.PI * 2);
    ctx.fillStyle = 'rgba(56,189,248,0.10)';
    ctx.fill();
    ctx.beginPath(); ctx.arc(lbX, lbY, lbPulse, 0, Math.PI * 2); ctx.fillStyle = lbPalette.node; ctx.fill();
    ctx.fillStyle = '#fff'; ctx.font = 'bold 11px system-ui'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle'; ctx.fillText('LB', lbX, lbY);
    ctx.fillStyle = '#cbd5e1'; ctx.font = '9px system-ui'; ctx.fillText(`${fmtRate(topoReqRate(lbFlow))} → ${fmtBps(topoByteRate(lbFlow))}`, lbX, lbY + 34);
    S.topoNodeRects.push({ id: 'lb', kind: 'lb', x: lbX, y: lbY, r: lbPulse + 10, data: { title: 'Sentirum LB', subtitle: 'Ingress load balancer', flow: lbFlow } });

    let laneY = 0;
    visibleHosts.forEach((host, hostIndex) => {
        const routes = host.routes || [];
        const laneHeight = hostHeights[hostIndex];
        const laneTop = laneY;
        const laneWidth = Math.max(620, W - 180);
        const hostFlow = topoFlow(host);
        const hostActive = topoFlowHot(hostFlow);
        const laneGlow = topoResolvePalette('closed', hostFlow);
        ctx.fillStyle = hostIndex % 2 === 0 ? 'rgba(255,255,255,0.02)' : 'rgba(129,140,248,0.03)';
        if (hostActive) ctx.fillStyle = hostIndex % 2 === 0 ? 'rgba(99,102,241,0.06)' : 'rgba(56,189,248,0.06)';
        ctx.strokeStyle = hostActive ? laneGlow.glow : 'rgba(63,63,70,0.7)';
        ctx.lineWidth = 1;
        const laneRadius = 16;
        ctx.beginPath();
        ctx.moveTo(0 + laneRadius, laneTop);
        ctx.arcTo(laneWidth, laneTop, laneWidth, laneTop + laneHeight, laneRadius);
        ctx.arcTo(laneWidth, laneTop + laneHeight, 0, laneTop + laneHeight, laneRadius);
        ctx.arcTo(0, laneTop + laneHeight, 0, laneTop, laneRadius);
        ctx.arcTo(0, laneTop, laneWidth, laneTop, laneRadius);
        ctx.closePath(); ctx.fill(); ctx.stroke();

        ctx.fillStyle = '#e4e4e7'; ctx.textAlign = 'left'; ctx.font = '600 11px system-ui';
        ctx.fillText(host.host || '*', 18, laneTop + 22);
        ctx.fillStyle = '#71717a'; ctx.font = '9px system-ui';
        const hostTargets = routes.flatMap(route => route.targets || []);
        ctx.fillText(`${routes.length} routes · ${hostTargets.length} targets · ${fmtRate(topoReqRate(hostFlow))}`, 18, laneTop + 38);

        routes.forEach((route, routeIndex) => {
            const routeY = laneTop + 28 + routeIndex * routeGap;
            const routeX = 220;
            const pathLabel = route.path || '/';
            const routeLabelWidth = Math.min(180, Math.max(96, pathLabel.length * 7));
            const routeFlow = topoFlow(route);
            const routeReqRate = topoReqRate(routeFlow);
            const routeByteRate = topoByteRateStable(routeFlow);
            const routePalette = topoResolvePalette('closed', routeFlow, false);
            const routeEdgeId = `lb-route|${host.host || '*'}|${route.path || '/'}`;
            const routeHover = S.topoHoverItem?.id === routeEdgeId;
            const routeLineWidth = 1.5 + clamp(Math.log10(1 + routeByteRate), 0, 3.6) + (routeHover ? 0.8 : 0);
            const routeStartX = lbX + lbPulse;
            const routeEndX = routeX - routeLabelWidth / 2 - 14;

            ctx.strokeStyle = topoStrokeGradient(ctx, routeStartX, lbY, routeEndX, routeY, routePalette);
            ctx.lineWidth = routeLineWidth;
            ctx.beginPath(); ctx.moveTo(routeStartX, lbY); ctx.lineTo(routeEndX, routeY); ctx.stroke();
            drawTopoArrowheads(ctx, routeStartX, lbY, routeEndX, routeY, routePalette.byte, topoActivityRank(routeFlow) + (routeHover ? 1 : 0));
            drawTopoFlowDots(ctx, routeStartX, lbY, routeEndX, routeY, routePalette.dot, routeFlow, phase, topoActivityRank(routeFlow) + (routeHover ? 1 : 0));
            drawTopoEdgeLabel(ctx, routeStartX, lbY, routeEndX, routeY, `${fmtRate(routeReqRate)} → ${fmtBps(routeByteRate)}`, routePalette.edge, routeHover || routeReqRate >= 10);
            S.topoHitAreas.push({
                id: routeEdgeId,
                kind: 'lb-route',
                x1: routeStartX, y1: lbY, x2: routeEndX, y2: routeY,
                pad: Math.max(9, routeLineWidth * 2.1),
                data: { title: `${host.host || '*'} ${route.path || '/'}`, subtitle: `${route.matcher || 'prefix'} matcher`, flow: routeFlow }
            });

            ctx.fillStyle = routeHover || topoFlowHot(routeFlow) ? 'rgba(79,70,229,0.14)' : 'rgba(99,102,241,0.08)';
            ctx.strokeStyle = routeHover || topoFlowHot(routeFlow) ? 'rgba(129,140,248,0.46)' : 'rgba(129,140,248,0.24)';
            ctx.beginPath();
            ctx.roundRect ? ctx.roundRect(routeX - routeLabelWidth / 2, routeY - 18, routeLabelWidth, 36, 12) : ctx.rect(routeX - routeLabelWidth / 2, routeY - 18, routeLabelWidth, 36);
            ctx.fill(); ctx.stroke();
            ctx.fillStyle = '#e4e4e7'; ctx.textAlign = 'center'; ctx.font = '600 10px system-ui'; ctx.fillText(pathLabel, routeX, routeY - 4);
            ctx.fillStyle = '#94a3b8'; ctx.font = '8px system-ui'; ctx.fillText(`${fmtRate(routeReqRate)} → ${(route.targets || []).length} targets`, routeX, routeY + 10);

            (route.targets || []).forEach((t, targetIndex) => {
                const tx = 430 + targetIndex * 144;
                const key = targetKey({ host: host.host || '', path: route.path, service: t.service, url: t.url });
                const cb = t.circuit_breaker || 'closed';
                const flow = topoFlow(t);
                const activity = topoActivityRank(flow);
                const reqRate = topoReqRate(flow);
                const byteRate = topoByteRateStable(flow);
                const selected = S.topologySelectedTargetKey === key;
                const edgeId = `route-target|${key}`;
                const hover = S.topoHoverItem?.id === edgeId || S.topoHoverItem?.key === key;
                const active = topoFlowHot(flow) || (t.active_connections || 0) > 0;
                const palette = topoResolvePalette(cb, flow, selected);
                const radius = 18 + Math.min((t.active_connections || 0) * 0.35, 8) + clamp(Math.log2(1 + reqRate) * 1.6, 0, 7);
                const lineWidth = 1.15 + clamp(Math.log10(1 + byteRate), 0, 4.4) + (selected ? 1 : 0) + (hover ? 0.7 : 0);
                const edgeStartX = routeX + routeLabelWidth / 2;
                const edgeEndX = tx - radius - 8;

                ctx.beginPath();
                ctx.moveTo(edgeStartX, routeY);
                ctx.lineTo(edgeEndX, routeY);
                ctx.strokeStyle = topoStrokeGradient(ctx, edgeStartX, routeY, edgeEndX, routeY, palette);
                ctx.lineWidth = lineWidth;
                ctx.stroke();
                drawTopoArrowheads(ctx, edgeStartX, routeY, edgeEndX, routeY, palette.byte, activity + (hover ? 1 : 0));
                drawTopoFlowDots(ctx, edgeStartX, routeY, edgeEndX, routeY, palette.dot, flow, phase, selected ? 2 : activity + (hover ? 1 : 0));
                drawTopoEdgeLabel(ctx, edgeStartX, routeY, edgeEndX, routeY, `${fmtRate(reqRate)} → ${fmtBps(byteRate)}`, palette.edge, hover || selected || reqRate >= 15);
                S.topoHitAreas.push({
                    id: edgeId,
                    kind: 'route-target',
                    x1: edgeStartX, y1: routeY, x2: edgeEndX, y2: routeY,
                    pad: Math.max(10, lineWidth * 2.2),
                    selectKey: key,
                    data: {
                        title: `${t.service || 'target'} flow`,
                        subtitle: `${host.host || '*'}${route.path || '/'} → ${t.url || ''}`,
                        flow,
                        stats: t.stats || {},
                        service: t.service,
                        url: t.url,
                    }
                });

                ctx.strokeStyle = selected ? '#a5b4fc' : palette.node;
                ctx.fillStyle = palette.fill;
                ctx.lineWidth = selected ? 3 : hover ? 2.2 : 1.6;
                ctx.beginPath(); ctx.arc(tx, routeY, radius, 0, Math.PI * 2); ctx.fill(); ctx.stroke();
                if (selected || active || hover) {
                    ctx.beginPath();
                    ctx.arc(tx, routeY, radius + 6 + Math.sin(phase * 5 + targetIndex) * 1.5, 0, Math.PI * 2);
                    ctx.strokeStyle = palette.glow;
                    ctx.lineWidth = hover ? 1.5 : 1.25;
                    ctx.stroke();
                }
                ctx.fillStyle = '#f4f4f5'; ctx.textAlign = 'center'; ctx.font = '600 8px system-ui'; ctx.fillText(t.service || '', tx, routeY - 2);
                ctx.fillStyle = '#94a3b8'; ctx.font = '7px system-ui'; ctx.fillText(`${fmtRate(reqRate)} · ${fmtLat(t.stats?.avg_latency_us || 0)}`, tx, routeY + 10);
                S.topoNodeRects.push({
                    id: key,
                    key,
                    kind: 'target',
                    selectKey: key,
                    x: tx,
                    y: routeY,
                    r: radius + 8,
                    data: {
                        title: t.service || 'target',
                        subtitle: `${host.host || '*'}${route.path || '/'} · ${t.url || ''}`,
                        flow,
                        stats: t.stats || {},
                        service: t.service,
                        url: t.url,
                    }
                });
            });
        });
        laneY += laneHeight + laneGap;
    });

    ctx.restore();
    if(!c._w){
        c._w=true;let drag=false,lx=0,ly=0,moved=false;
        const worldPoint = e => {
            const rect = c.getBoundingClientRect();
            const clientX = e.touches ? e.touches[0].clientX : e.clientX;
            const clientY = e.touches ? e.touches[0].clientY : e.clientY;
            return {
                x: (clientX - rect.left - (80 + S.topoPan.x)) / S.topoScale,
                y: (clientY - rect.top - (36 + S.topoPan.y)) / S.topoScale,
            };
        };
        const hoverAt = e => {
            const point = worldPoint(e);
            const hit = topoHitAt(point) || null;
            const prev = S.topoHoverItem?.id || S.topoHoverItem?.key || null;
            const next = hit?.id || hit?.key || null;
            S.topoHoverItem = hit;
            if (hit) renderTopoTooltip(hit, e.clientX ?? e.touches?.[0]?.clientX ?? 0, e.clientY ?? e.touches?.[0]?.clientY ?? 0);
            else hideTopoTooltip();
            c.style.cursor = hit?.selectKey ? 'pointer' : hit ? 'crosshair' : drag ? 'grabbing' : 'grab';
            if (prev !== next) { drawTopo(); scheduleTopoFrame(); }
            return hit;
        };
        const trySelect = e => {
            const hit = hoverAt(e);
            if (hit?.selectKey && !moved) selectTopologyTarget(hit.selectKey);
        };
        c.addEventListener('mousedown', e=>{drag=true;moved=false;lx=e.clientX;ly=e.clientY;c.style.cursor='grabbing';});
        c.addEventListener('mousemove', e=>{if(drag){const dx=e.clientX-lx, dy=e.clientY-ly; if(Math.abs(dx)+Math.abs(dy)>2)moved=true; S.topoPan.x+=dx;S.topoPan.y+=dy;lx=e.clientX;ly=e.clientY;hideTopoTooltip();drawTopo();scheduleTopoFrame();} else { hoverAt(e); }});
        c.addEventListener('mouseup', e=>{drag=false; trySelect(e);});
        c.addEventListener('mouseleave', ()=>{drag=false;c.style.cursor='grab';hideTopoTooltip();drawTopo();});
        c.addEventListener('touchstart', e=>{const t=e.touches[0];drag=true;moved=false;lx=t.clientX;ly=t.clientY;hideTopoTooltip();}, { passive: true });
        c.addEventListener('touchmove', e=>{if(drag){e.preventDefault();const t=e.touches[0];const dx=t.clientX-lx, dy=t.clientY-ly; if(Math.abs(dx)+Math.abs(dy)>2)moved=true; S.topoPan.x+=dx;S.topoPan.y+=dy;lx=t.clientX;ly=t.clientY;drawTopo();scheduleTopoFrame();}}, { passive: false });
        c.addEventListener('touchend', ()=>{drag=false;hideTopoTooltip();}, { passive: true });
        c.addEventListener('click', e=>{if(!drag) trySelect(e);});
        c.addEventListener('wheel', e=>{e.preventDefault();S.topoScale=Math.max(0.5,Math.min(2.25,S.topoScale*(e.deltaY<0?1.08:0.92)));hideTopoTooltip();drawTopo();scheduleTopoFrame();}, { passive: false });
    }
    c.style.cursor = S.topoHoverItem?.selectKey ? 'pointer' : S.topoHoverItem ? 'crosshair' : 'grab';
}
function topoZoom(f){S.topoScale=Math.max(0.5,Math.min(2.25,S.topoScale*f));hideTopoTooltip();drawTopo();scheduleTopoFrame();}
function topoReset(){S.topologySelectedTargetKey = null; S.topoScale=1;S.topoPan={x:0,y:0};refreshTopologyView();}

