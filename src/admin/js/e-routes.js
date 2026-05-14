// ===== ROUTES =====
function routeStaticKey(route) { return [route.host || '', route.path || '', route.matcher || 'prefix'].join('|'); }
function routeRuntimeKey(host, path, target) { return [host || '', path || '', target.service || '', target.url || ''].join('|'); }
function routeHostLabel(host) { return host ? host : 'Catch-all'; }
function routeProtocolGroup(protocol) {
    const p = String(protocol || 'http').toLowerCase();
    if (p === 'grpc' || p === 'grpcs') return 'grpc';
    if (p === 'ws' || p === 'wss') return 'websocket';
    if (p === 'tcp') return 'tcp';
    return 'http';
}
function routeProtocolTag(group) {
    const cls = group === 'grpc' ? 'tag tag-grpc' : group === 'tcp' ? 'tag tag-tcp' : 'tag';
    const label = group === 'websocket' ? 'ws' : group;
    return `<span class="${cls}">${esc(label)}</span>`;
}
function routeTargetToneClass(target) {
    const errPct = target.stats?.error_rate_pct || 0;
    if (target.circuit_breaker === 'open' || errPct > 5) return 'err';
    if (target.circuit_breaker === 'halfopen' || errPct > 0) return 'warn';
    return '';
}
function routeToneClass(route) {
    if (route.openCount > 0 || route.errorRatePct > 5) return 'err';
    if (route.halfOpenCount > 0 || route.errorRatePct > 0) return 'warn';
    return '';
}
function summarizeRouteOptions(targets) {
    const keys = [...new Set(targets.flatMap(t => Object.keys(t.opts || {})))];
    const shared = key => {
        const values = [...new Set(targets.map(t => t.opts?.[key]).filter(v => v != null && v !== ''))];
        return values.length === 1 ? values[0] : null;
    };
    const parts = [];
    const strip = shared('strip');
    const prepend = shared('prepend');
    const host = shared('host');
    if (strip) parts.push(`strip ${strip}`);
    if (prepend) parts.push(`prepend ${prepend}`);
    if (host) parts.push(`host ${host}`);
    if (targets.some(t => String(t.opts?.pxyproto || '').toLowerCase() === 'true')) parts.push('PROXY v1');
    if (targets.some(t => String(t.opts?.tlsskipverify || '').toLowerCase() === 'true')) parts.push('skip verify');
    const mixed = keys.some(key => {
        const values = [...new Set(targets.map(t => t.opts?.[key]).filter(v => v != null && v !== ''))];
        return values.length > 1;
    });
    return { keys, parts, mixed };
}
function buildRouteModels(data) {
    const runtime = new Map((S.allTargets || []).map(t => [routeRuntimeKey(t.host, t.path, t), t]));
    return (data.routes || []).map(route => {
        const host = route.host || '';
        const path = route.path || '/';
        const targets = (route.targets || []).map(target => {
            const live = runtime.get(routeRuntimeKey(host, path, target)) || {};
            return {
                ...target,
                ...live,
                host,
                path,
                protocol: live.protocol || target.protocol || 'http',
                tls: live.tls ?? target.tls ?? false,
                http2: live.http2 ?? target.http2 ?? false,
                active_connections: live.active_connections || 0,
                circuit_breaker: live.circuit_breaker || 'closed',
                source: live.source || target.source || 'runtime',
                stats: live.stats || target.stats || {},
                opts: target.opts || {},
            };
        });
        const totalRequests = targets.reduce((sum, target) => sum + (target.stats?.requests || 0), 0);
        const totalErrors = targets.reduce((sum, target) => sum + (target.stats?.errors || 0), 0);
        const activeConnections = targets.reduce((sum, target) => sum + (target.active_connections || 0), 0);
        const weightedLatency = targets.reduce((sum, target) => sum + ((target.stats?.avg_latency_us || 0) * (target.stats?.requests || 0)), 0);
        const avgLatencyUs = totalRequests > 0 ? Math.round(weightedLatency / totalRequests) : Math.max(0, ...targets.map(target => target.stats?.avg_latency_us || 0));
        const protocolGroups = [...new Set(targets.map(target => routeProtocolGroup(target.protocol)))];
        const optionSummary = summarizeRouteOptions(targets);
        const flow = combineFlows(targets.map(target => target.flow));
        const errorRatePct = totalRequests > 0 ? (totalErrors / totalRequests) * 100 : 0;
        const openCount = targets.filter(target => target.circuit_breaker === 'open').length;
        const halfOpenCount = targets.filter(target => target.circuit_breaker === 'halfopen').length;
        return {
            ...route,
            key: routeStaticKey(route),
            host,
            hostLabel: host || '*',
            scopeLabel: `${host || '*'}${path}`,
            path,
            targets,
            targetCount: targets.length,
            totalRequests,
            totalErrors,
            errorRatePct,
            flow,
            reqRate: topoReqRateStable(flow),
            throughput: topoByteRateStable(flow),
            heat: topoHeatLevel(flow),
            lastActiveMsAgo: flow.last_active_ms_ago,
            activeConnections,
            avgLatencyUs,
            openCount,
            halfOpenCount,
            protocolGroups,
            protocolSet: [...new Set(targets.map(target => String(target.protocol || 'http').toLowerCase()))],
            sourceSet: [...new Set(targets.map(target => target.source || 'runtime'))],
            multiTarget: targets.length > 1,
            catchAll: !host,
            optionSummary,
            score: (openCount * ROUTE_RISK_CB_OPEN) + (halfOpenCount * ROUTE_RISK_CB_HALF_OPEN) + (errorRatePct * ROUTE_RISK_ERROR_MULT) + avgLatencyUs + totalRequests + Math.round(topoByteRateStable(flow) / BYTES_PER_KB) + (targets.length * 100),
        };
    });
}
const routeIsHot = route => topoFlowHot(route.flow) || route.heat >= 0.34 || route.activeConnections > 0;
const routeHasRewrite = route => route.optionSummary.parts.some(part => part.startsWith('strip ') || part.startsWith('prepend ') || part.startsWith('host '));
const routeHighThroughput = route => route.throughput >= TARGET_THROUGHPUT_HIGH_BPS || route.heat >= TARGET_HEAT_HIGH;
const routeWeightPalette = ['#818cf8', '#38bdf8', '#34d399', '#fbbf24', '#fb7185', '#c084fc'];
const routeWeightBar = (route, compact = false) => {
    const targets = route.targets || [];
    if (!targets.length) return '<div class="subtle">No target weights</div>';
    const liveTotal = targets.reduce((sum, target) => sum + topoReqRateStable(topoFlow(target)), 0);
    const fallbackTotal = targets.reduce((sum, target) => sum + Number(target.stats?.requests || 0), 0);
    const segments = targets.map((target, idx) => {
        const pct = Math.max(0, Number((target.weight || 0) * 100));
        const color = routeWeightPalette[idx % routeWeightPalette.length];
        return `<span class="route-weightseg" style="width:${pct.toFixed(2)}%;background:${color}"></span>`;
    }).join('');
    const liveSegments = targets.map((target, idx) => {
        const reqShare = liveTotal > 0
            ? (topoReqRateStable(topoFlow(target)) / liveTotal) * 100
            : fallbackTotal > 0
                ? ((Number(target.stats?.requests || 0) / fallbackTotal) * 100)
                : Number((target.weight || 0) * 100);
        const width = Math.max(0, reqShare);
        const color = routeWeightPalette[idx % routeWeightPalette.length];
        return `<span class="route-weightlive-seg" style="width:${width.toFixed(2)}%;background:${color}"></span>`;
    }).join('');
    const chips = targets.slice(0, compact ? 3 : 6).map((target, idx) => {
        const color = routeWeightPalette[idx % routeWeightPalette.length];
        const livePct = liveTotal > 0
            ? (topoReqRateStable(topoFlow(target)) / liveTotal) * 100
            : fallbackTotal > 0
                ? ((Number(target.stats?.requests || 0) / fallbackTotal) * 100)
                : Number((target.weight || 0) * 100);
        return `<span class="route-weight-chip"><span class="route-weight-chip-dot" style="background:${color}"></span>${esc(target.service || 'target')} ${fmtPct((target.weight || 0) * 100)} · live ${fmtPct(livePct)}</span>`;
    }).join('');
    const more = Math.max(0, targets.length - (compact ? 3 : 6));
    return `<div class="route-weight-wrap"><div class="route-weightbar">${segments}<div class="route-weightlive">${liveSegments}</div></div><div class="route-weight-note">Base = configured weight · overlay = live request share</div><div class="route-weight-legend">${chips}${more > 0 ? `<span class="route-weight-chip">+${more} more</span>` : ''}</div></div>`;
};
const routeHeatChip = route => {
    const heat = route.heat || 0;
    const color = heat >= 0.82 ? '#fb923c' : heat >= 0.58 ? '#d946ef' : heat >= 0.34 ? '#60a5fa' : heat >= 0.16 ? '#22d3ee' : '#34d399';
    return `<span class="route-heat-chip" style="border:1px solid ${color}44;background:${color}18;color:${color}">heat ${(heat * 100).toFixed(0)}%</span>`;
};
function routeTrendCard(title, value, series, color, meta = '') {
    return `<div class="route-trend-card"><div class="panel-item-title">${esc(title)}</div><div class="panel-item-sub">${esc(value)}</div>${spark((series || []).slice(-24), 240, 34, color) || '<div class="subtle" style="margin-top:0.45rem">Not enough points yet</div>'}${meta ? `<div class="route-trend-meta">${esc(meta)}</div>` : ''}</div>`;
}
function focusRouteInTopology(routeKey) {
    const route = buildRouteModels(S.cachedRoutes || { routes: [] }).find(r => r.key === routeKey);
    if (!route) return;
    S.topologyMode = 'all';
    S.topologyHostFilter = route.host || '*';
    S.topologySelectedTargetKey = null;
    ['all','issues','hot'].forEach(name => document.getElementById(`topo-mode-${name}`)?.classList.toggle('on', name === 'all'));
    showPage('topology');
}
function syncRouteQuickFilters() {
    Object.entries(S.routeQuickFilters).forEach(([name, on]) => document.getElementById(`route-chip-${name}`)?.classList.toggle('on', on));
}
function renderRoutesSummary(routes) {
    const targets = routes.reduce((sum, route) => sum + route.targetCount, 0);
    const attention = routes.filter(route => route.openCount > 0 || route.halfOpenCount > 0 || route.errorRatePct > 0).length;
    const multiTarget = routes.filter(route => route.multiTarget).length;
    const catchAll = routes.filter(route => route.catchAll).length;
    const hosts = new Set(routes.map(route => route.host)).size;
    const highestRps = [...routes].sort((a, b) => (b.reqRate || 0) - (a.reqRate || 0))[0];
    const highestThroughput = [...routes].sort((a, b) => (b.throughput || 0) - (a.throughput || 0))[0];
    document.getElementById('routes-summary').innerHTML = `
        <div class="summary-card"><div class="k">Visible routes</div><div class="v">${fmt(routes.length)}</div></div>
        <div class="summary-card"><div class="k">Visible targets</div><div class="v">${fmt(targets)}</div></div>
        <div class="summary-card"><div class="k">Host scopes</div><div class="v">${fmt(hosts)}</div></div>
        <div class="summary-card"><div class="k">Needs attention</div><div class="v">${attention}</div></div>
        <div class="summary-card"><div class="k">Multi-target</div><div class="v">${multiTarget}</div></div>
        <div class="summary-card"><div class="k">Catch-all</div><div class="v">${catchAll}</div></div>
        <div class="summary-card"><div class="k">Highest req/s</div><div class="v">${esc(highestRps?.path || '—')}</div><div class="subtle">${fmtRate(highestRps?.reqRate || 0)}</div></div>
        <div class="summary-card"><div class="k">Highest throughput</div><div class="v">${esc(highestThroughput?.path || '—')}</div><div class="subtle">${fmtBps(highestThroughput?.throughput || 0)}</div></div>
    `;
}
function renderRouteHosts(baseRoutes) {
    const counts = baseRoutes.reduce((acc, route) => {
        const key = route.host || '';
        acc[key] = (acc[key] || 0) + 1;
        return acc;
    }, {});
    if (S.routeHostFilter !== '__all__' && counts[S.routeHostFilter] == null) S.routeHostFilter = '__all__';
    const entries = Object.keys(counts).sort((a, b) => routeHostLabel(a).localeCompare(routeHostLabel(b)));
    document.getElementById('route-hosts').innerHTML = [
        `<button class="topo-host-btn ${S.routeHostFilter === '__all__' ? 'on' : ''}" data-action="set-route-host-filter" data-host="${attrEnc('__all__')}">All scopes <span style="color:var(--text-4)">(${baseRoutes.length})</span></button>`,
        ...entries.map(host => `<button class="topo-host-btn ${S.routeHostFilter === host ? 'on' : ''}" data-action="set-route-host-filter" data-host="${attrEnc(host)}">${esc(routeHostLabel(host))} <span style="color:var(--text-4)">(${counts[host]})</span></button>`)
    ].join('');
}
function renderRouteInspector(route) {
    const panel = document.getElementById('route-inspector');
    if (!route) {
        panel.innerHTML = `<div class="panel-head"><div><div class="panel-title">Route inspector</div><div class="subtle">Pick a route to inspect rewrites, flow, fan-out and target health</div></div></div><div class="panel-body"><div class="empty">No route selected</div></div>`;
        return;
    }
    const targetCards = route.targets.map(target => {
        const tone = routeTargetToneClass(target);
        const opts = Object.entries(target.opts || {});
        return `<div class="route-target ${tone}">
            <div class="route-target-head"><div class="cell-stack"><span class="cell-main">${esc(target.service || 'unknown')}</span><span class="cell-sub">${esc(target.source || 'runtime')} · ${esc(target.protocol || 'http')}</span></div><span class="metric-chip">${fmtPct((target.weight || 0) * 100)}</span></div>
            <div class="route-target-url">${esc(target.url || '—')}</div>
            <div class="route-target-meta"><span class="tag ${target.protocol === 'tcp' ? 'tag-tcp' : target.http2 ? 'tag-grpc' : ''}">${esc(target.protocol || 'http')}</span>${target.tls ? '<span class="tag tag-tls">TLS</span>' : ''}${target.http2 ? '<span class="tag tag-grpc">H2</span>' : ''}<span class="cb cb-${esc(target.circuit_breaker || 'closed')}">${esc(target.circuit_breaker || 'closed')}</span>${target.flow ? targetHeatChip(target) : ''}</div>
            <div class="route-target-stats">
                <div class="route-stat"><div class="k">Req/s</div><div class="v">${fmtRate(topoReqRateStable(topoFlow(target)))}</div></div>
                <div class="route-stat"><div class="k">Throughput</div><div class="v">${fmtBps(targetThroughput(target))}</div></div>
                <div class="route-stat"><div class="k">Errors</div><div class="v">${fmtPct(target.stats?.error_rate_pct || 0)}</div></div>
                <div class="route-stat"><div class="k">Latency</div><div class="v">${target.stats?.avg_latency_us ? fmtLat(target.stats.avg_latency_us) : '0µs'}</div></div>
            </div>
            <div class="route-inline-meta">${opts.length ? opts.map(([key, value]) => `<span class="metric-chip">${esc(key)}=${esc(value)}</span>`).join('') : '<span class="subtle">No target-specific opts</span>'}</div>
        </div>`;
    }).join('') || '<div class="empty">No upstream targets are attached to this route</div>';
    const sharedOptions = route.optionSummary.parts.length ? route.optionSummary.parts.map(part => `<span class="metric-chip">${esc(part)}</span>`).join('') : '<span class="subtle">No shared route options</span>';
    const routeHist = S.topoRouteHist[topologyRouteKey(route.host, route.path)] || { req: [], bytes: [], errPct: [], lat: [] };
    panel.innerHTML = `
        <div class="panel-head"><div><div class="panel-title">Route inspector</div><div class="subtle">${esc(route.scopeLabel)} · ${route.targetCount} target(s)</div></div><div class="target-side-actions"><button class="btn btn-sm" data-action="focus-route-topology" data-key="${attrEnc(route.key)}">View in topology</button></div></div>
        <div class="panel-body route-inspector-grid">
            <div class="topo-focus-card">
                <div class="route-entry-head"><div><div class="cell-main mono">${esc(route.path)}</div><div class="cell-sub">${esc(route.hostLabel)} · ${esc(route.matcher || 'prefix')} matcher</div></div><div class="route-kpis wrap-tight">${routeHeatChip(route)}<span class="metric-chip">${fmtRate(route.reqRate)}</span><span class="metric-chip">${fmtBps(route.throughput)}</span></div></div>
                <div class="route-inline-meta">${route.protocolGroups.map(routeProtocolTag).join('')}${route.catchAll ? '<span class="metric-chip">catch-all host</span>' : ''}${route.optionSummary.mixed ? '<span class="metric-chip">mixed target opts</span>' : ''}</div>
                ${route.optionSummary.parts.length ? `<div class="route-inline-note">${esc(route.optionSummary.parts.join(' · '))}</div>` : ''}
            </div>
            <div class="route-mini-grid">
                <div class="route-mini-card"><div class="k">Req/s</div><div class="v">${fmtRate(route.reqRate)}</div></div>
                <div class="route-mini-card"><div class="k">Throughput</div><div class="v">${fmtBps(route.throughput)}</div></div>
                <div class="route-mini-card"><div class="k">Error rate</div><div class="v">${fmtPct(route.errorRatePct)}</div></div>
                <div class="route-mini-card"><div class="k">Latency</div><div class="v">${route.avgLatencyUs ? fmtLat(route.avgLatencyUs) : '0µs'}</div></div>
                <div class="route-mini-card"><div class="k">Open / half</div><div class="v">${route.openCount} / ${route.halfOpenCount}</div></div>
                <div class="route-mini-card"><div class="k">Last active</div><div class="v">${fmtAgoMs(route.lastActiveMsAgo)}</div></div>
            </div>
            <div class="panel-item">
                <div class="panel-item-head"><div class="panel-item-title">Match and rewrite</div><span class="metric-chip">${esc(route.scopeLabel)}</span></div>
                <dl class="route-kv" style="margin-top:0.75rem">
                    <dt>Host scope</dt><dd>${esc(route.hostLabel)}</dd>
                    <dt>Path</dt><dd class="mono">${esc(route.path)}</dd>
                    <dt>Matcher</dt><dd>${esc(route.matcher || 'prefix')}</dd>
                    <dt>Shared options</dt><dd><div class="route-inline-meta">${sharedOptions}</div></dd>
                </dl>
            </div>
            <div class="panel-item">
                <div class="panel-item-head"><div class="panel-item-title">Weight vs live split</div><span class="metric-chip">${route.targetCount} targets</span></div>
                <div style="margin-top:0.75rem">${routeWeightBar(route)}</div>
            </div>
            <div class="route-trend-grid">
                ${routeTrendCard('Request rate', fmtRate(route.reqRate), routeHist.req || [], 'var(--accent)', 'from topology flow snapshots')}
                ${routeTrendCard('Throughput', fmtBps(route.throughput), routeHist.bytes || [], '#60a5fa', '5s byte rate history')}
                ${routeTrendCard('Error rate', fmtPct(route.errorRatePct), routeHist.errPct || [], 'var(--red)', 'aggregate route error percentage')}
                ${routeTrendCard('Latency', route.avgLatencyUs ? fmtLat(route.avgLatencyUs) : '0µs', routeHist.lat || [], '#fbbf24', 'weighted average upstream latency')}
            </div>
            <div class="panel-item">
                <div class="panel-item-head"><div class="panel-item-title">Upstream targets</div><span class="metric-chip">${route.targetCount} targets</span></div>
                <div class="route-list" style="margin-top:0.75rem">${targetCards}</div>
            </div>
        </div>`;
}
function filterRoutes() { S.routeSearch = document.getElementById('route-search').value || ''; renderRoutes(S.cachedRoutes || { routes: [] }); }
function changeRouteSort() { S.routeSort = document.getElementById('route-sort').value || 'attention'; renderRoutes(S.cachedRoutes || { routes: [] }); }
function changeRouteProtocol() { S.routeProtocol = document.getElementById('route-protocol').value || 'all'; renderRoutes(S.cachedRoutes || { routes: [] }); }
function toggleRouteIssues() {
    S.routeIssuesOnly = !S.routeIssuesOnly;
    document.getElementById('route-issues-btn').classList.toggle('on', S.routeIssuesOnly);
    renderRoutes(S.cachedRoutes || { routes: [] });
}
function toggleRouteHot() {
    S.routeHotOnly = !S.routeHotOnly;
    document.getElementById('route-hot-btn').classList.toggle('on', S.routeHotOnly);
    renderRoutes(S.cachedRoutes || { routes: [] });
}
function toggleRouteQuickFilter(name) {
    S.routeQuickFilters[name] = !S.routeQuickFilters[name];
    syncRouteQuickFilters();
    renderRoutes(S.cachedRoutes || { routes: [] });
}
function setRouteHostFilter(host) { S.routeHostFilter = host; renderRoutes(S.cachedRoutes || { routes: [] }); }
function selectRoute(key) { S.selectedRouteKey = key; renderRoutes(S.cachedRoutes || { routes: [] }); }
function resetRouteFilters() {
    S.routeSearch = '';
    S.routeSort = 'attention';
    S.routeProtocol = 'all';
    S.routeIssuesOnly = false;
    S.routeHotOnly = false;
    S.routeQuickFilters = { open: false, rewrite: false, multi: false, throughput: false };
    S.routeHostFilter = '__all__';
    document.getElementById('route-search').value = '';
    document.getElementById('route-sort').value = 'attention';
    document.getElementById('route-protocol').value = 'all';
    document.getElementById('route-issues-btn').classList.remove('on');
    document.getElementById('route-hot-btn').classList.remove('on');
    syncRouteQuickFilters();
    renderRoutes(S.cachedRoutes || { routes: [] });
}
function renderRoutes(data) {
    S.cachedRoutes = data;
    const models = buildRouteModels(data);
    const query = S.routeSearch.trim().toLowerCase();
    const baseRoutes = models.filter(route => {
        const matchesIssues = !S.routeIssuesOnly || route.openCount > 0 || route.halfOpenCount > 0 || route.errorRatePct > 0;
        const matchesProtocol = S.routeProtocol === 'all' || route.protocolGroups.includes(S.routeProtocol);
        const matchesHot = !S.routeHotOnly || routeIsHot(route);
        const matchesQuick = (!S.routeQuickFilters.open || route.openCount > 0)
            && (!S.routeQuickFilters.rewrite || routeHasRewrite(route))
            && (!S.routeQuickFilters.multi || route.multiTarget)
            && (!S.routeQuickFilters.throughput || routeHighThroughput(route));
        if (!matchesIssues || !matchesProtocol || !matchesHot || !matchesQuick) return false;
        if (!query) return true;
        const haystack = [
            route.host,
            route.path,
            route.matcher,
            route.protocolSet.join(' '),
            route.sourceSet.join(' '),
            route.optionSummary.parts.join(' '),
            route.targets.map(target => `${target.service || ''} ${target.url || ''} ${Object.entries(target.opts || {}).map(([key, value]) => `${key}=${value}`).join(' ')}`).join(' ')
        ].join(' ').toLowerCase();
        return haystack.includes(query);
    });
    renderRouteHosts(baseRoutes);
    const filtered = baseRoutes.filter(route => S.routeHostFilter === '__all__' || route.host === S.routeHostFilter);
    filtered.sort((a, b) => {
        switch (S.routeSort) {
            case 'throughput': return (b.throughput - a.throughput) || (b.reqRate - a.reqRate) || (b.score - a.score);
            case 'traffic': return (b.reqRate - a.reqRate) || (b.totalRequests - a.totalRequests) || (b.score - a.score);
            case 'fanout': return (b.targetCount - a.targetCount) || (b.score - a.score);
            case 'host': return String(a.hostLabel).localeCompare(String(b.hostLabel)) || String(a.path).localeCompare(String(b.path));
            case 'path': return String(a.path).localeCompare(String(b.path)) || String(a.hostLabel).localeCompare(String(b.hostLabel));
            case 'attention':
            default: return (b.score - a.score) || String(a.hostLabel).localeCompare(String(b.hostLabel)) || String(a.path).localeCompare(String(b.path));
        }
    });
    renderRoutesSummary(filtered);
    const quickOn = Object.entries(S.routeQuickFilters).filter(([, on]) => on).map(([name]) => name).join(', ');
    document.getElementById('routes-meta').textContent = `${filtered.length} shown · ${models.length} total${S.routeHotOnly ? ' · hot only' : ''}${S.routeIssuesOnly ? ' · issues only' : ''}${quickOn ? ` · ${quickOn}` : ''}`;
    if (!filtered.some(route => route.key === S.selectedRouteKey)) S.selectedRouteKey = filtered[0]?.key || null;
    if (!filtered.length) {
        document.getElementById('routes-list').innerHTML = '<div class="empty">No routes match the current filter</div>';
        renderRouteInspector(null);
        return;
    }
    const listHtml = filtered.map(route => {
        const tone = routeToneClass(route);
        const routeHist = S.topoRouteHist[topologyRouteKey(route.host, route.path)] || { req: [], bytes: [], errPct: [], lat: [] };
        const previewTargets = route.targets.slice(0, 3).map(target => {
            const targetTone = routeTargetToneClass(target);
            return `<div class="route-target ${targetTone}">
                <div class="route-target-head"><span class="cell-main">${esc(target.service || 'unknown')}</span><span class="metric-chip">${fmtPct((target.weight || 0) * 100)}</span></div>
                <div class="route-target-url">${esc(target.url || '—')}</div>
                <div class="route-target-meta"><span class="tag ${target.protocol === 'tcp' ? 'tag-tcp' : target.http2 ? 'tag-grpc' : ''}">${esc(target.protocol || 'http')}</span>${target.tls ? '<span class="tag tag-tls">TLS</span>' : ''}${target.http2 ? '<span class="tag tag-grpc">H2</span>' : ''}${(target.circuit_breaker && target.circuit_breaker !== 'closed') ? `<span class="cb cb-${esc(target.circuit_breaker)}">${esc(target.circuit_breaker)}</span>` : ''}</div>
            </div>`;
        }).join('');
        const moreCount = Math.max(0, route.targets.length - 3);
        return `<div class="route-card ${tone}${route.key === S.selectedRouteKey ? ' active' : ''}" data-action="select-route" data-key="${attrEnc(route.key)}">
            <div class="route-entry-head">
                <div>
                    <div class="cell-main mono">${esc(route.path)}</div>
                    <div class="cell-sub">${esc(route.hostLabel)} · ${esc(route.matcher || 'prefix')} matcher · ${route.targetCount} target(s)</div>
                </div>
                <div class="route-kpis wrap-tight">${routeHeatChip(route)}<span class="metric-chip">${route.targetCount} upstreams</span></div>
            </div>
            <div class="route-flow-head"><div class="route-flow-trend">${spark(routeHist.req.slice(-20), 72, 16, 'var(--accent)') || '<span class="subtle">no trend</span>'}<span class="subtle">${fmtRate(route.reqRate)}</span></div><div class="route-kpis wrap-tight"><span class="metric-chip">${fmtBps(route.throughput)}</span><span class="metric-chip">${fmtPct(route.errorRatePct)} err</span><span class="metric-chip">${route.openCount} open / ${route.halfOpenCount} half</span></div></div>
            <div class="route-inline-meta">${route.protocolGroups.map(routeProtocolTag).join('')}${route.catchAll ? '<span class="metric-chip">catch-all host</span>' : ''}${route.optionSummary.mixed ? '<span class="metric-chip">mixed target opts</span>' : ''}${routeHasRewrite(route) ? '<span class="metric-chip">rewrite</span>' : ''}</div>
            <div style="margin-top:0.55rem">${routeWeightBar(route, true)}</div>
            ${route.optionSummary.parts.length ? `<div class="route-inline-note">${esc(route.optionSummary.parts.join(' · '))}</div>` : ''}
            <div class="route-targets" style="margin-top:0.7rem">${previewTargets}${moreCount > 0 ? `<div class="route-target"><div class="cell-main">+${moreCount} more target(s)</div><div class="cell-sub">Open inspector for full target list</div></div>` : ''}</div>
        </div>`;
    }).join('');
    document.getElementById('routes-list').innerHTML = `<div class="route-list">${listHtml}</div>`;
    renderRouteInspector(filtered.find(route => route.key === S.selectedRouteKey) || filtered[0]);
}


function exportRoutes(){dl(S.cachedRoutes||{},'sentirum-routes.json');}
