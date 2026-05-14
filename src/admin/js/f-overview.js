// ===== OVERVIEW =====
function renderOverview() {
    const routes = buildRouteModels(S.cachedRoutes || { routes: [] });
    const targets = S.allTargets || [];
    const logs = S.cachedLogs || [];
    const dnsEntries = S.cachedDns?.entries || [];
    const certs = S.cachedCerts?.certificates || [];
    const clientAuth = S.cachedCerts?.client_auth || {};
    const watchers = ['services','kv','tls','client_ca'].map(name => {
        const data = S.cachedConsul?.[name] || {};
        const errs = data.errors || 0, backoff = data.backoff_secs || 0;
        const state = errs > 10 ? 'degraded' : errs > 0 || backoff > 0 ? 'recovering' : 'healthy';
        return { name, state, errs, backoff, data };
    });
    const degradedWatchers = watchers.filter(w => w.state === 'degraded');
    const recoveringWatchers = watchers.filter(w => w.state === 'recovering');
    const openTargets = targets.filter(t => t.circuit_breaker === 'open');
    const halfOpenTargets = targets.filter(t => t.circuit_breaker === 'halfopen');
    const activeTargets = targets.filter(t => t.circuit_breaker !== 'open' && (t.stats?.requests || 0) > 0);
    const warningLogs = logs.filter(l => l.level === 'WARN').length;
    const errorLogs = logs.filter(l => l.level === 'ERROR').length;
    const latestErrorLog = logs.find(l => l.level === 'ERROR');
    const latestWarnLog = logs.find(l => l.level === 'WARN');
    const latestAnyLog = logs[0];
    const negativeDns = dnsEntries.filter(e => e.is_negative).length;
    const expiringDns = dnsEntries.filter(e => (e.ttl_remaining_secs || 0) <= 10).length;
    const expiringCerts = certs.filter(c => c.days_remaining != null && c.days_remaining < 30);
    const hotRoutes = [...routes].sort((a, b) => (b.score - a.score) || (b.totalRequests - a.totalRequests)).slice(0, 5);
    const busiestTarget = [...targets].sort((a, b) => (b.stats?.requests || 0) - (a.stats?.requests || 0))[0];
    const slowestTarget = [...targets].sort((a, b) => (b.stats?.avg_latency_us || 0) - (a.stats?.avg_latency_us || 0))[0];
    const highestErrorTarget = [...targets].sort((a, b) => (b.stats?.error_rate_pct || 0) - (a.stats?.error_rate_pct || 0))[0];
    const noisiestWatcher = [...watchers].sort((a, b) => ((b.errs + b.backoff) - (a.errs + a.backoff)) || ((b.data?.last_index || 0) - (a.data?.last_index || 0)))[0];
    const healthy = openTargets.length === 0 && halfOpenTargets.length === 0 && degradedWatchers.length === 0 && errorLogs === 0;
    const warning = !healthy && openTargets.length === 0 && degradedWatchers.length === 0;
    const title = healthy ? 'Traffic and control plane look healthy' : warning ? 'Some pressure is building up' : 'Runtime needs operator attention';
    const subtitleBits = [
        S.currentMetricSnapshot ? `${S.currentMetricSnapshot.rps.toFixed(1)} req/s live traffic` : 'Live metrics warming up',
        `${routes.length} routes across ${new Set(routes.map(r => r.host)).size} host scopes`,
        `${activeTargets.length}/${targets.length || 0} targets are currently active`
    ];
    if (S.cachedConfig?.proxy?.strategy) subtitleBits.push(`strategy ${S.cachedConfig.proxy.strategy}`);
    if (S.cachedConfig?.proxy?.matcher) subtitleBits.push(`matcher ${S.cachedConfig.proxy.matcher}`);
    document.getElementById('overview-title').textContent = title;
    document.getElementById('overview-subtitle').textContent = subtitleBits.join(' · ');

    // Build rich summary chips
    const tlsListeners = S.cachedConfig?.tls_listeners || [];
    const totalTlsListeners = (S.cachedConfig?.tls?.listen ? 1 : 0) + tlsListeners.length;
    const mtlsListeners = tlsListeners.filter(l => l.client_auth === 'required' || l.client_auth === 'optional').length;
    const hcEnabled = S.cachedConfig?.proxy?.health_check_interval && S.cachedConfig.proxy.health_check_interval !== '0s';
    const rlEnabled = S.cachedConfig?.proxy?.rate_limit_per_target > 0;
    const cbEnabled = S.cachedConfig?.proxy?.circuit_breaker_enabled;
    const protoBits = [];
    if (S.cachedConfig?.proxy?.enable_h2c) protoBits.push('h2c');
    if (S.cachedConfig?.tls?.listen) protoBits.push('https');
    if (mtlsListeners > 0) protoBits.push('mtls');
    const totalLogs = logs.length;
    const healthChecks = S.cachedCerts ? undefined : 0; // TODO: from metrics

    document.getElementById('overview-flags').innerHTML = [
        `<span class="metric-chip">${healthy ? 'healthy window' : warning ? 'watch closely' : 'attention required'}</span>`,
        `<span class="metric-chip">${openTargets.length} open CB</span>`,
        `<span class="metric-chip">${recoveringWatchers.length + degradedWatchers.length} watcher signal(s)</span>`,
        `<span class="metric-chip">${errorLogs} error / ${warningLogs} warn log(s)</span>`,
        `<span class="metric-chip">routes ${routes.length} · targets ${targets.length}</span>`,
        `<span class="metric-chip">tls ${totalTlsListeners} listener(s)${mtlsListeners > 0 ? ` · ${mtlsListeners} mTLS` : ''}</span>`,
        `<span class="metric-chip">${cbEnabled ? 'CB on' : 'CB off'}${hcEnabled ? ' · HC on' : ' · HC off'}${rlEnabled ? ' · RL on' : ''}</span>`,
        protoBits.length ? `<span class="metric-chip">proto: ${protoBits.join(', ')}</span>` : '',
    ].filter(Boolean).join('');

    const trendCards = [
        {
            key: 'RPS',
            value: S.currentMetricSnapshot ? `${S.currentMetricSnapshot.rps.toFixed(1)}` : '0.0',
            sub: `${S.overviewHistory.rps.length} samples`,
            data: S.overviewHistory.rps.slice(-20),
            color: 'var(--accent)'
        },
        {
            key: 'Error trend',
            value: S.currentMetricSnapshot ? S.currentMetricSnapshot.errRateText : '0%',
            sub: `${errorLogs} recent error log(s)`,
            data: S.overviewHistory.err.slice(-20),
            color: 'var(--red)'
        },
        {
            key: 'Connections',
            value: `${S.currentMetricSnapshot?.active_connections || 0}`,
            sub: `${activeTargets.length} active target(s)`,
            data: S.overviewHistory.conn.slice(-20),
            color: 'var(--green)'
        },
        {
            key: 'Latency trend',
            value: S.currentMetricSnapshot?.targets?.length ? fmtLat(Math.round(S.overviewHistory.lat[S.overviewHistory.lat.length - 1] || 0)) : '0µs',
            sub: `${slowestTarget ? `slowest ${esc(slowestTarget.service || 'target')}` : 'No latency outlier'}`,
            data: S.overviewHistory.lat.slice(-20),
            color: 'var(--yellow)'
        }
    ];
    document.getElementById('overview-trends').innerHTML = trendCards.map(card => `
        <div class="overview-trend-card">
            <div class="overview-trend-top">
                <div><div class="k">${card.key}</div><div class="v">${card.value}</div><div class="s">${card.sub}</div></div>
                <span class="metric-chip">live</span>
            </div>
            <div class="overview-trend-spark">${spark(card.data, 96, 18, card.color) || '<span class="subtle">Not enough samples yet</span>'}</div>
        </div>
    `).join('');

    document.getElementById('overview-health').innerHTML = `
        <div class="panel-head"><div><div class="panel-title">Operational health</div><div class="subtle">Fast read of runtime, discovery, TLS and protocol status</div></div></div>
        <div class="panel-body overview-panel-grid">
            <div class="overview-mini-grid">
                <div class="overview-mini-card actionable" data-action="focus-config-field" data-path="${attrEnc('proxy.circuit_breaker_enabled')}"><div class="k">Circuit breakers</div><div class="v">${openTargets.length} / ${halfOpenTargets.length}</div><div class="s">open / half-open targets · click to tune</div></div>
                <div class="overview-mini-card"><div class="k">Consul watchers</div><div class="v">${degradedWatchers.length + recoveringWatchers.length}</div><div class="s">recovering or degraded</div></div>
                <div class="overview-mini-card actionable" data-action="focus-config-field" data-path="${attrEnc('proxy.dns_cache_ttl')}"><div class="k">DNS pressure</div><div class="v">${expiringDns}</div><div class="s">entries expiring in ≤10s</div></div>
                <div class="overview-mini-card"><div class="k">TLS listeners</div><div class="v">${totalTlsListeners}</div><div class="s">${mtlsListeners > 0 ? mtlsListeners + ' mTLS · ' : ''}certs loaded${expiringCerts.length > 0 ? ' · ' + expiringCerts.length + ' expiring' : ''}</div></div>
                <div class="overview-mini-card actionable" data-action="focus-config-field" data-path="${attrEnc('proxy.health_check_interval')}"><div class="k">Health checks</div><div class="v">${hcEnabled ? 'active' : 'off'}</div><div class="s">${hcEnabled ? S.cachedConfig.proxy.health_check_interval + ' interval' : 'click to configure'}</div></div>
                <div class="overview-mini-card actionable" data-action="focus-config-field" data-path="${attrEnc('proxy.rate_limit_per_target')}"><div class="k">Rate limiting</div><div class="v">${rlEnabled ? S.cachedConfig.proxy.rate_limit_per_target + '/s' : 'off'}</div><div class="s">${rlEnabled ? 'burst ' + S.cachedConfig.proxy.rate_limit_burst : 'click to configure'}</div></div>
            </div>
            <div class="overview-health-list">
                <div class="overview-row"><div class="overview-row-main"><div class="overview-row-title">Busiest target</div><div class="overview-row-sub">${esc(busiestTarget?.url || 'No traffic yet')}</div></div><div class="overview-row-side"><span class="metric-chip">${esc(busiestTarget?.service || '—')}</span><span class="metric-chip">${fmt(busiestTarget?.stats?.requests || 0)} req</span></div></div>
                <div class="overview-row"><div class="overview-row-main"><div class="overview-row-title">Slowest target</div><div class="overview-row-sub">${esc(slowestTarget?.url || 'No latency data')}</div></div><div class="overview-row-side"><span class="metric-chip">${slowestTarget ? fmtLat(slowestTarget?.stats?.avg_latency_us || 0) : '—'}</span></div></div>
                <div class="overview-row"><div class="overview-row-main"><div class="overview-row-title">Highest error target</div><div class="overview-row-sub">${esc(highestErrorTarget?.url || 'No errors observed')}</div></div><div class="overview-row-side"><span class="metric-chip">${highestErrorTarget ? fmtPct(highestErrorTarget?.stats?.error_rate_pct || 0) : '0%'}</span></div></div>
                <div class="overview-row"><div class="overview-row-main"><div class="overview-row-title">Noisiest watcher</div><div class="overview-row-sub">${esc(noisiestWatcher?.name || 'none')} · index ${noisiestWatcher?.data?.last_index || 0}</div></div><div class="overview-row-side"><span class="metric-chip">${noisiestWatcher ? noisiestWatcher.errs + ' errors' : '0'}</span></div></div>
            </div>
        </div>`;

    document.getElementById('overview-hot-routes').innerHTML = `
        <div class="panel-head"><div><div class="panel-title">Hot routes</div><div class="subtle">Most important routes by traffic, errors and circuit pressure</div></div><button class="btn btn-sm" data-action="nav-to" data-page="routes">Open routes</button></div>
        <div class="panel-body">${hotRoutes.length ? `<div class="overview-route-list">${hotRoutes.map(route => `
            <div class="overview-row">
                <div class="overview-row-main">
                    <div class="overview-row-title mono">${esc(route.path)}</div>
                    <div class="overview-row-sub">${esc(route.hostLabel)} · ${esc(route.matcher || 'prefix')} · ${route.targetCount} target(s)</div>
                </div>
                <div class="overview-row-side">
                    <span class="metric-chip">${fmt(route.totalRequests)} req</span>
                    <span class="metric-chip">${fmtPct(route.errorRatePct)} err</span>
                    ${route.avgLatencyUs ? `<span class="metric-chip">${fmtLat(route.avgLatencyUs)}</span>` : ''}
                    ${route.openCount > 0 || route.halfOpenCount > 0 ? `<span class="metric-chip">${route.openCount}/${route.halfOpenCount} CB</span>` : ''}
                </div>
            </div>`).join('')}</div>` : '<div class="empty">Route activity will appear here once traffic is observed</div>'}</div>`;

    const attentionItems = [];
    openTargets.slice(0, 3).forEach(t => attentionItems.push({
        title: `${t.service || 'unknown'} circuit open`,
        sub: `${t.host || '*'}${t.path || ''} · ${t.url || 'unknown upstream'}`,
        chips: [`${fmtPct(t.stats?.error_rate_pct || 0)} err`, `${t.active_connections || 0} conns`]
    }));
    degradedWatchers.forEach(w => attentionItems.push({
        title: `${w.name.toUpperCase()} watcher degraded`,
        sub: `${w.errs} errors · backoff ${w.backoff}s · last index ${w.data?.last_index || 0}`,
        chips: ['consul']
    }));
    if (expiringCerts[0]) attentionItems.push({
        title: `TLS certificate expiring soon`,
        sub: `${expiringCerts[0].primary_name || expiringCerts[0].entry_name || 'unknown'} · ${expiringCerts[0].days_remaining}d remaining`,
        chips: ['tls']
    });
    if (expiringDns > 0 || negativeDns > 0) attentionItems.push({
        title: `DNS cache pressure`,
        sub: `${expiringDns} entries expiring in ≤10s · ${negativeDns} negative cache entries`,
        chips: ['dns']
    });
    if (errorLogs > 0 || warningLogs > 0) attentionItems.push({
        title: `Recent log signal`,
        sub: `${errorLogs} error and ${warningLogs} warning entries in the buffered log window`,
        chips: ['logs']
    });
    document.getElementById('overview-attention').innerHTML = `
        <div class="panel-head"><div><div class="panel-title">Attention queue</div><div class="subtle">What deserves a closer look right now</div></div><button class="btn btn-sm" data-action="nav-to" data-page="logs">Open logs</button></div>
        <div class="panel-body">${attentionItems.length ? `<div class="overview-attention-list">${attentionItems.slice(0, 6).map(item => `
            <div class="overview-row">
                <div class="overview-row-main"><div class="overview-row-title">${esc(item.title)}</div><div class="overview-row-sub">${esc(item.sub)}</div></div>
                <div class="overview-row-side">${(item.chips || []).map(chip => `<span class="metric-chip">${esc(chip)}</span>`).join('')}</div>
            </div>`).join('')}</div>` : '<div class="empty">No urgent operational signals right now</div>'}</div>`;

    const recentChanges = [
        latestErrorLog ? {
            title: 'Last incident',
            sub: latestErrorLog.message || 'Error log captured',
            meta: logTs(latestErrorLog.ts),
            chips: ['error', latestErrorLog.target || 'runtime']
        } : null,
        latestWarnLog ? {
            title: 'Latest warning',
            sub: latestWarnLog.message || 'Warning log captured',
            meta: logTs(latestWarnLog.ts),
            chips: ['warn', latestWarnLog.target || 'runtime']
        } : latestAnyLog ? {
            title: 'Latest event',
            sub: latestAnyLog.message || 'Latest buffered log entry',
            meta: logTs(latestAnyLog.ts),
            chips: [latestAnyLog.level || 'info', latestAnyLog.target || 'runtime']
        } : null,
        noisiestWatcher ? {
            title: `${noisiestWatcher.name.toUpperCase()} watcher status`,
            sub: `${noisiestWatcher.state} · ${noisiestWatcher.errs} errors · index ${noisiestWatcher.data?.last_index || 0}`,
            meta: noisiestWatcher.backoff > 0 ? `backoff ${noisiestWatcher.backoff}s` : 'no backoff',
            chips: ['consul']
        } : null,
        S.cachedCerts?.last_reload_unix ? {
            title: 'TLS runtime reload',
            sub: `Last certificate reload ${fmtDate(S.cachedCerts.last_reload_unix * MS_PER_SEC)}`,
            meta: expiringCerts.length ? `${expiringCerts.length} cert(s) expiring <30d` : 'No immediate expiry pressure',
            chips: ['tls']
        } : null,
        clientAuth?.last_reload_unix ? {
            title: 'Client CA reload',
            sub: `Client CA refreshed ${fmtDate(clientAuth.last_reload_unix * MS_PER_SEC)}`,
            meta: `${(clientAuth.certificates || []).length} CA certificate(s) loaded`,
            chips: ['mTLS']
        } : null,
        S.cachedConfig ? {
            title: 'Runtime posture',
            sub: `strategy ${S.cachedConfig.proxy?.strategy || 'unknown'} · matcher ${S.cachedConfig.proxy?.matcher || 'unknown'} · no-route ${S.cachedConfig.proxy?.no_route_status || 'n/a'}`,
            meta: `request-id ${S.cachedConfig.proxy?.request_id_header || 'disabled'}`,
            chips: ['config'],
            actionPath: 'proxy.strategy'
        } : null
    ].filter(Boolean);
    document.getElementById('overview-recent-changes').innerHTML = `
        <div class="panel-head"><div><div class="panel-title">Recent changes & incidents</div><div class="subtle">Latest operational signals across logs, Consul and TLS runtime</div></div><button class="btn btn-sm" data-action="nav-to" data-page="certs">Open certs</button></div>
        <div class="panel-body">${recentChanges.length ? `<div class="overview-change-list">${recentChanges.slice(0, 6).map(item => `
            <div class="overview-row${item.actionPath ? ' actionable' : ''}"${item.actionPath ? ` data-action="focus-config-field" data-path="${attrEnc(item.actionPath)}"` : ''}>
                <div class="overview-row-main"><div class="overview-row-title">${esc(item.title)}</div><div class="overview-row-sub">${esc(item.sub)}</div><div class="route-inline-note">${item.meta || ''}${item.actionPath ? ' · click to inspect in configuration' : ''}</div></div>
                <div class="overview-row-side">${(item.chips || []).map(chip => `<span class="metric-chip">${esc(chip)}</span>`).join('')}</div>
            </div>`).join('')}</div>` : '<div class="empty">No recent change signal is available yet</div>'}</div>`;

    const guideItems = [
        openTargets.length > 0 ? {
            title: 'Start with open circuit breakers',
            body: `Open Targets first, then trace the owning route from Routes. ${openTargets.length} target(s) are currently failing fast.`
        } : null,
        degradedWatchers.length > 0 ? {
            title: 'Control plane may be degraded',
            body: `Consul watcher errors usually beat traffic symptoms. Verify ACL/network and blocking-query health before chasing app logs.`
        } : null,
        expiringDns > 0 || negativeDns > 0 ? {
            title: 'Watch DNS churn',
            body: `Short TTL churn or negative cache spikes can look like random upstream instability. Correlate with latency and error bumps.`
        } : null,
        expiringCerts.length > 0 ? {
            title: 'Plan certificate rotation',
            body: `At least one TLS certificate is below 30 days. Confirm renewal path before it becomes an availability issue.`
        } : null,
        !openTargets.length && !degradedWatchers.length && !expiringCerts.length ? {
            title: 'Healthy baseline',
            body: `Use Hot routes and Trend cards to understand normal load shape now, so incident comparisons are easier later.`
        } : null
    ].filter(Boolean);
    document.getElementById('overview-guide').innerHTML = `
        <div class="panel-head"><div><div class="panel-title">Operator guide</div><div class="subtle">Short, actionable hints based on current signals</div></div><button class="btn btn-sm" data-action="nav-to" data-page="topology">Open topology</button></div>
        <div class="panel-body">${guideItems.length ? `<div class="overview-guide-list">${guideItems.slice(0, 4).map(item => `
            <div class="overview-guide-item"><strong>${esc(item.title)}</strong><span>${esc(item.body)}</span></div>`).join('')}</div>` : '<div class="empty">No guide hints available yet</div>'}</div>`;
}

