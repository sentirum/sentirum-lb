    // ===== STATE =====
    const API = '/admin';
    let token = localStorage.getItem('admin_token') || '';
    let username = localStorage.getItem('admin_user') || '';
    let logSse = null, metricsSse = null;
    let charts = {};
    let prevSnap = null;
    let targetHist = {};
    const HIST = 60;
    let allTargets = [];
    let targetSearch = '';
    let targetSort = 'risk';
    let targetIssuesOnly = false;
    let targetHotOnly = false;
    let targetQuickFilters = { open: false, probe: false, latency: false, throughput: false };
    let cachedLogs = [];
    let cachedRoutes = null;
    let routeSearch = '';
    let routeSort = 'attention';
    let routeProtocol = 'all';
    let routeIssuesOnly = false;
    let routeHotOnly = false;
    let routeQuickFilters = { open: false, rewrite: false, multi: false, throughput: false };
    let routeHostFilter = '__all__';
    let selectedRouteKey = null;
    let cachedConsul = null;
    let cachedDns = null;
    let dnsSearch = '';
    let dnsNegativesOnly = false;
    let activeLevels = new Set(['ERROR','WARN','INFO']);
    let logSearch = '';
    let logPreset = 'all';
    let topoData = null, topoScale = 1, topoPan = {x:0,y:0};
    let currentMetricSnapshot = null;
    let overviewHistory = { rps: [], err: [], conn: [], lat: [], ts: [] };
    let topologyMode = 'all';
    let topologyHeatMode = false;
    let topologyHostFilter = '*';
    let topologySelectedTargetKey = null;
    let topoRouteHist = {};
    let topoNodeRects = [];
    let topoHitAreas = [];
    let topoHoverItem = null;
    let topoAnimFrame = null;
    let selectedTarget = null;
    let selectedTargetKey = null;
    let cachedConfig = null;
    let cachedConfigStartup = null;
    let cachedConfigRuntime = null;
    let cachedCerts = null;
    let certSearch = '';
    let certRisk = 'all';
    let certDefaultOnly = false;
    let certClientCaOnly = false;
    let selectedCertEntry = null;
    let configDraft = null;
    let configCollapsedSections = {};
    let configFocusPath = '';
    let configSearch = '';
    let configDiffOnly = false;
    let configStatus = { tone: '', text: '' };
    let sidebarOpen = false;
    let staticRefreshTimer = null;
    let logStreamPaused = false;
    let pendingStreamEntries = 0;
    let logStreamDesired = false;
    let logStreamReconnectTimer = null;
    let logStreamReconnectDelay = 1000;
    // Delta tracking: previous target state per composite target key for trend arrows
    let prevTargets = {};

    // ===== HELPERS =====
    const esc = s => s == null ? '' : String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
    const attrEnc = value => encodeURIComponent(value == null ? '' : String(value));
    const attrDec = value => { try { return decodeURIComponent(value || ''); } catch (_) { return value || ''; } };
    const TARGET_HISTORY_TTL_MS = 10 * 60 * 1000;
    const LOG_STREAM_RECONNECT_MIN_MS = 1000;
    const LOG_STREAM_RECONNECT_MAX_MS = 15000;
    const tsToMs = ts => !ts ? 0 : (ts > 1e12 ? ts : ts * 1000);
    const fmt = n => n >= 1e9 ? (n/1e9).toFixed(1)+'B' : n >= 1e6 ? (n/1e6).toFixed(1)+'M' : n >= 1e3 ? (n/1e3).toFixed(1)+'K' : String(n);
    const fmtLat = us => us < 1000 ? us+'µs' : us < 1e6 ? (us/1000).toFixed(1)+'ms' : (us/1e6).toFixed(2)+'s';
    const fmtPct = n => { const v = Number(n || 0); return v >= 10 ? v.toFixed(0)+'%' : v >= 1 ? v.toFixed(1)+'%' : v > 0 ? v.toFixed(2)+'%' : '0%'; };
    const fmtTime = ms => new Date(ms).toISOString().slice(11,19);
    const fmtDate = ms => new Date(ms).toISOString().slice(0,19).replace('T',' ');
    const fmtRel = ms => { const d=Date.now()-ms; if(d<60000)return Math.floor(d/1000)+'s ago'; if(d<3600000)return Math.floor(d/60000)+'m ago'; if(d<86400000)return Math.floor(d/3600000)+'h ago'; return Math.floor(d/86400000)+'d ago'; };
    const fmtExpiry = unix => unix ? fmtDate(unix * 1000) : 'Unknown';
    const clamp = (n, min, max) => Math.min(max, Math.max(min, n));
    const topoFlow = node => node?.flow || {};
    const topoReqRate = flow => Number(flow?.rps_1s || flow?.rps_5s || 0);
    const topoReqRateStable = flow => Number(flow?.rps_5s || flow?.rps_1s || 0);
    const topoByteRate = flow => Number(flow?.bps_1s || flow?.bps_5s || 0);
    const topoByteRateStable = flow => Number(flow?.bps_5s || flow?.bps_1s || 0);
    const topoActivityRank = flow => flow?.activity_level === 'hot' ? 2 : flow?.activity_level === 'warm' ? 1 : 0;
    const topoFlowHot = flow => topoActivityRank(flow) > 0 || topoReqRate(flow) > 0 || topoByteRate(flow) > 0;
    const topoRoleLabel = kind => kind === 'lb-route' ? 'LB → route flow' : kind === 'route-target' ? 'Route → target flow' : kind === 'lb' ? 'Load balancer' : kind === 'route' ? 'Route lane' : 'Target';
    const topoHeatLevel = flow => Math.max(
        clamp(Math.log2(1 + topoReqRateStable(flow)) / 7, 0, 1),
        clamp(Math.log10(1 + topoByteRateStable(flow)) / 7, 0, 1),
        topoActivityRank(flow) / 2
    );
    const fmtRate = n => {
        const v = Number(n || 0);
        return v >= 100 ? fmt(Math.round(v)) + '/s' : v >= 10 ? v.toFixed(0) + '/s' : v >= 1 ? v.toFixed(1) + '/s' : v > 0 ? v.toFixed(2) + '/s' : '0/s';
    };
    const fmtBps = n => {
        const v = Number(n || 0);
        if (v >= 1024 * 1024 * 1024) return (v / (1024 * 1024 * 1024)).toFixed(1) + ' GB/s';
        if (v >= 1024 * 1024) return (v / (1024 * 1024)).toFixed(1) + ' MB/s';
        if (v >= 1024) return (v / 1024).toFixed(1) + ' KB/s';
        return Math.round(v) + ' B/s';
    };
    const fmtAgoMs = ms => ms == null ? '—' : ms < 1000 ? ms + 'ms ago' : ms < 60000 ? (ms / 1000).toFixed(ms < 10000 ? 1 : 0) + 's ago' : ms < 3600000 ? Math.floor(ms / 60000) + 'm ago' : Math.floor(ms / 3600000) + 'h ago';
    const topoPalette = (cb, flow, selected = false) => {
        const activity = topoActivityRank(flow);
        if (selected) return { edge: 'rgba(129,140,248,0.96)', edgeSoft: 'rgba(129,140,248,0.34)', node: '#a5b4fc', fill: 'rgba(129,140,248,0.22)', dot: 'rgba(196,181,253,0.98)', glow: 'rgba(129,140,248,0.56)', byte: 'rgba(56,189,248,0.95)' };
        if (cb === 'open') return { edge: 'rgba(248,113,113,0.88)', edgeSoft: 'rgba(248,113,113,0.24)', node: '#f87171', fill: 'rgba(248,113,113,0.18)', dot: 'rgba(254,202,202,0.96)', glow: 'rgba(248,113,113,0.38)', byte: 'rgba(252,165,165,0.94)' };
        if (cb === 'halfopen') return { edge: 'rgba(251,191,36,0.86)', edgeSoft: 'rgba(251,191,36,0.24)', node: '#fbbf24', fill: 'rgba(251,191,36,0.16)', dot: 'rgba(253,230,138,0.96)', glow: 'rgba(251,191,36,0.34)', byte: 'rgba(253,224,71,0.92)' };
        if (activity >= 2) return { edge: 'rgba(139,92,246,0.92)', edgeSoft: 'rgba(139,92,246,0.20)', node: '#8b5cf6', fill: 'rgba(99,102,241,0.18)', dot: 'rgba(196,181,253,0.98)', glow: 'rgba(129,140,248,0.44)', byte: 'rgba(56,189,248,0.94)' };
        if (activity === 1) return { edge: 'rgba(56,189,248,0.82)', edgeSoft: 'rgba(56,189,248,0.18)', node: '#38bdf8', fill: 'rgba(56,189,248,0.14)', dot: 'rgba(125,211,252,0.96)', glow: 'rgba(56,189,248,0.32)', byte: 'rgba(34,197,94,0.92)' };
        return { edge: 'rgba(52,211,153,0.46)', edgeSoft: 'rgba(52,211,153,0.12)', node: '#34d399', fill: 'rgba(52,211,153,0.10)', dot: 'rgba(167,243,208,0.86)', glow: 'rgba(52,211,153,0.20)', byte: 'rgba(52,211,153,0.76)' };
    };
    const topoHeatPalette = (flow, selected = false) => {
        const level = topoHeatLevel(flow);
        if (selected) return topoPalette('closed', flow, true);
        if (level >= 0.82) return { edge: 'rgba(251,146,60,0.94)', edgeSoft: 'rgba(251,146,60,0.24)', node: '#fb923c', fill: 'rgba(251,146,60,0.18)', dot: 'rgba(254,215,170,0.98)', glow: 'rgba(251,146,60,0.40)', byte: 'rgba(244,114,182,0.92)' };
        if (level >= 0.58) return { edge: 'rgba(217,70,239,0.92)', edgeSoft: 'rgba(217,70,239,0.20)', node: '#d946ef', fill: 'rgba(217,70,239,0.16)', dot: 'rgba(233,213,255,0.98)', glow: 'rgba(192,132,252,0.38)', byte: 'rgba(96,165,250,0.92)' };
        if (level >= 0.34) return { edge: 'rgba(59,130,246,0.88)', edgeSoft: 'rgba(59,130,246,0.18)', node: '#60a5fa', fill: 'rgba(59,130,246,0.14)', dot: 'rgba(147,197,253,0.96)', glow: 'rgba(56,189,248,0.34)', byte: 'rgba(34,211,238,0.90)' };
        if (level >= 0.16) return { edge: 'rgba(34,211,238,0.82)', edgeSoft: 'rgba(34,211,238,0.16)', node: '#22d3ee', fill: 'rgba(34,211,238,0.12)', dot: 'rgba(165,243,252,0.94)', glow: 'rgba(34,211,238,0.28)', byte: 'rgba(45,212,191,0.88)' };
        return { edge: 'rgba(52,211,153,0.56)', edgeSoft: 'rgba(52,211,153,0.12)', node: '#34d399', fill: 'rgba(52,211,153,0.10)', dot: 'rgba(167,243,208,0.88)', glow: 'rgba(52,211,153,0.20)', byte: 'rgba(45,212,191,0.80)' };
    };
    const topoResolvePalette = (cb, flow, selected = false) => (topologyHeatMode && cb === 'closed') ? topoHeatPalette(flow, selected) : topoPalette(cb, flow, selected);
    const topoStrokeGradient = (ctx, x1, y1, x2, y2, palette) => {
        const g = ctx.createLinearGradient(x1, y1, x2, y2);
        g.addColorStop(0, palette.edgeSoft);
        g.addColorStop(0.48, palette.edge);
        g.addColorStop(1, palette.byte || palette.edge);
        return g;
    };
    const topologyRouteKey = (host, path) => [host || '*', path || '/'].join('|');
    const targetKey = t => [t.host||'', t.path||'', t.service||'', t.url||''].join('|');
    const targetThroughput = t => topoByteRateStable(topoFlow(t));
    const targetLastActive = t => topoFlow(t)?.last_active_ms_ago;
    const targetHeat = t => topoHeatLevel(topoFlow(t));
    const targetIsHot = t => topoFlowHot(topoFlow(t)) || targetHeat(t) >= 0.34 || (t.active_connections || 0) > 0;
    const targetIsHighLatency = t => (t.stats?.avg_latency_us || 0) >= 250000;
    const targetIsHighThroughput = t => targetThroughput(t) >= 128 * 1024 || targetHeat(t) >= 0.58;
    const targetHealthClass = t => t.circuit_breaker === 'open' ? 'danger' : t.circuit_breaker === 'halfopen' || !t.probe_healthy || (t.stats?.error_rate_pct || 0) > 0 ? 'warn' : 'ok';
    const targetHealthLabel = t => t.circuit_breaker === 'open' ? 'CB open' : t.circuit_breaker === 'halfopen' ? 'Half-open' : !t.probe_healthy ? 'Probe down' : 'Healthy';
    const targetRiskScore = t => ((t.stats?.error_rate_pct || 0) * 1000000) + (t.circuit_breaker === 'open' ? 500000 : t.circuit_breaker === 'halfopen' ? 250000 : 0) + (t.stats?.avg_latency_us || 0) + ((t.active_connections || 0) * 100) + Math.round(targetThroughput(t) / 1024);
    const combineFlows = flows => {
        const list = (flows || []).filter(Boolean);
        return {
            rps_1s: list.reduce((sum, flow) => sum + Number(flow?.rps_1s || 0), 0),
            rps_5s: list.reduce((sum, flow) => sum + Number(flow?.rps_5s || 0), 0),
            bps_1s: list.reduce((sum, flow) => sum + Number(flow?.bps_1s || 0), 0),
            bps_5s: list.reduce((sum, flow) => sum + Number(flow?.bps_5s || 0), 0),
            delta_requests: list.reduce((sum, flow) => sum + Number(flow?.delta_requests || 0), 0),
            delta_bytes: list.reduce((sum, flow) => sum + Number(flow?.delta_bytes || 0), 0),
            last_active_ms_ago: list.reduce((best, flow) => {
                const next = flow?.last_active_ms_ago;
                return next == null ? best : best == null ? next : Math.min(best, next);
            }, null),
            activity_level: activityLevelName(list.reduce((rank, flow) => Math.max(rank, topoActivityRank(flow)), 0)),
        };
    };
    const activityLevelName = rank => rank >= 2 ? 'hot' : rank >= 1 ? 'warm' : 'idle';
    const DURATION_RE = /^\d+(ms|s|m|h)$/;
    const CONFIG_EDITOR_FIELDS = [
        {
            title: 'Routing & identity', subtitle: 'Live request routing behavior', fields: [
                { path: 'proxy.strategy', label: 'Strategy', type: 'select', options: ['round-robin','least-connections','random'], hint: 'Load-balancing strategy applied on new picks.' },
                { path: 'proxy.matcher', label: 'Matcher', type: 'select', options: ['prefix','iprefix','glob'], hint: 'Path matching strategy for route lookup.' },
                { path: 'proxy.request_id_header', label: 'Request ID header', type: 'text', allowEmpty: true, hint: 'Leave empty to disable request ID header injection.' },
                { path: 'proxy.no_route_status', label: 'No-route status', type: 'number', min: 100, max: 599, hint: 'HTTP status returned when no route matches.' },
            ]
        },
        {
            title: 'Timeouts', subtitle: 'Runtime network timing knobs', fields: [
                { path: 'proxy.connect_timeout', label: 'Connect timeout', type: 'text', hint: 'Example: 5s' },
                { path: 'proxy.read_timeout', label: 'Read timeout', type: 'text', hint: 'Example: 30s' },
                { path: 'proxy.write_timeout', label: 'Write timeout', type: 'text', hint: 'Example: 30s' },
                { path: 'proxy.idle_timeout', label: 'Idle timeout', type: 'text', hint: 'Example: 120s' },
            ]
        },
        {
            title: 'HTTP/2 & capacity', subtitle: 'Upstream connection and H2 behavior', fields: [
                { path: 'proxy.upstream_h2_max_streams', label: 'Upstream H2 max streams', type: 'number', min: 1, hint: 'Concurrent streams per upstream H2 connection.' },
                { path: 'proxy.upstream_h2_ping_interval', label: 'Upstream H2 ping interval', type: 'text', allowEmpty: true, hint: 'Leave empty to disable periodic pings.' },
                { path: 'proxy.max_connections', label: 'Max connections per target', type: 'number', min: 0, hint: '0 means unlimited.' },
            ]
        },
        {
            title: 'DNS & circuit breaker', subtitle: 'Failure handling and cache behavior', fields: [
                { path: 'proxy.dns_cache_ttl', label: 'DNS cache TTL', type: 'number', min: 0, hint: 'Seconds for positive cache entries.' },
                { path: 'proxy.dns_negative_cache_ttl', label: 'DNS negative TTL', type: 'number', min: 0, hint: 'Seconds for NX / negative cache entries.' },
                { path: 'proxy.circuit_breaker_enabled', label: 'Circuit breaker enabled', type: 'boolean', hint: 'Hot-toggle passive upstream failure protection.' },
                { path: 'proxy.circuit_breaker_error_threshold', label: 'CB error threshold', type: 'number', min: 0, max: 100, hint: 'Percentage threshold to open the breaker.' },
                { path: 'proxy.circuit_breaker_window_size', label: 'CB window size', type: 'number', min: 1, hint: 'Sliding request window size.' },
                { path: 'proxy.circuit_breaker_recovery_timeout', label: 'CB recovery timeout', type: 'number', min: 1, hint: 'Seconds before half-open probe.' },
                { path: 'proxy.circuit_breaker_half_open_max', label: 'CB half-open max', type: 'number', min: 1, hint: 'Probe request budget in half-open state.' },
            ]
        },
        {
            title: 'Health checks', subtitle: 'Active upstream probing configuration', fields: [
                { path: 'proxy.health_check_interval', label: 'Check interval', type: 'text', hint: 'How often to probe targets (e.g. 15s).' },
                { path: 'proxy.health_check_timeout', label: 'Check timeout', type: 'text', hint: 'Timeout per probe request (e.g. 5s).' },
                { path: 'proxy.health_check_path', label: 'Check path', type: 'text', hint: 'HTTP path for health check probes (must start with /).' },
                { path: 'proxy.health_check_fall', label: 'Fall threshold', type: 'number', min: 1, hint: 'Consecutive failures to mark target unhealthy.' },
                { path: 'proxy.health_check_rise', label: 'Rise threshold', type: 'number', min: 1, hint: 'Consecutive successes to mark target healthy.' },
                { path: 'proxy.health_check_tls_skip_verify', label: 'TLS skip verify', type: 'boolean', hint: 'Skip TLS verification for HTTPS health checks (insecure).' },
            ]
        },
        {
            title: 'Rate limiting', subtitle: 'Per-target request rate control', fields: [
                { path: 'proxy.rate_limit_per_target', label: 'Requests/sec per target', type: 'number', min: 0, hint: 'Token bucket rate. 0 = unlimited.' },
                { path: 'proxy.rate_limit_burst', label: 'Burst allowance', type: 'number', min: 1, hint: 'Maximum burst before rate limiting kicks in.' },
            ]
        },
        {
            title: 'Logging', subtitle: 'Runtime log output configuration', fields: [
                { path: 'logging.level', label: 'Log level', type: 'select', options: ['trace','debug','info','warn','error'], hint: 'Minimum log level to emit.' },
                { path: 'logging.format', label: 'Log format', type: 'select', options: ['json','text'], hint: 'Output format for log lines.' },
            ]
        }
    ];
    const logHaystack = l => `${l.level||''} ${l.target||''} ${l.message||''}`.toLowerCase();
    const logMatchesPreset = l => {
        const target = (l.target || '').toLowerCase();
        if (logPreset === 'app') return target.startsWith('sentirum_lb');
        if (logPreset === 'infra') return !target.startsWith('sentirum_lb');
        return true;
    };
    const logMatches = l => activeLevels.has(l.level) && logMatchesPreset(l) && (!logSearch || logHaystack(l).includes(logSearch));
    const logLevelShort = l => ({ERROR:'ERR', WARN:'WRN', INFO:'INF', DEBUG:'DBG', TRACE:'TRC'}[l] || l || 'LOG');
    const scheduleStaticRefresh = (delay = 10000) => {
        if (staticRefreshTimer) clearTimeout(staticRefreshTimer);
        staticRefreshTimer = setTimeout(refreshStatic, delay);
    };
    const updateLivePills = connected => {
        document.querySelectorAll('.js-live-pill').forEach(el => {
            el.classList.toggle('pill-live', connected);
            el.classList.toggle('pill-offline', !connected);
            el.innerHTML = `<span class="pill-dot"></span> ${connected ? 'LIVE' : 'OFFLINE'}`;
        });
    };
    const logTs = ms => {
        if(!ms) return '';
        const d=new Date(ms), t=d.toTimeString().slice(0,8), r=fmtRel(ms);
        const today=new Date(); today.setHours(0,0,0,0);
        const day=new Date(ms); day.setHours(0,0,0,0);
        const ts = day.getTime()===today.getTime() ? t : fmtDate(ms);
        return `<span title="${fmtDate(ms)}">${ts}</span> <span style="color:var(--text-4);font-size:0.6rem">${r}</span>`;
    };
    const hdrs = () => ({'Authorization':'Bearer '+token});
    async function api(p) { const r = await fetch(API+p,{headers:hdrs()}); if(r.status===401){localStorage.removeItem('admin_token');location.reload();throw new Error('401');} return r.json(); }
    document.addEventListener('click', e => {
        const actionEl = e.target.closest('[data-action]');
        if (!actionEl) return;
        const action = actionEl.dataset.action;
        if (!action) return;
        e.preventDefault();
        switch (action) {
            case 'login':
                doLogin();
                break;
            case 'toggle-sidebar':
                toggleSidebar();
                break;
            case 'close-sidebar':
                closeSidebar();
                break;
            case 'nav-to':
                navTo(actionEl.dataset.page || 'overview');
                break;
            case 'logout':
                doLogout();
                break;
            case 'topology-zoom':
                topoZoom(Number(actionEl.dataset.factor || 1));
                break;
            case 'topology-reset':
                topoReset();
                break;
            case 'set-topology-mode':
                setTopologyMode(actionEl.dataset.mode || 'all');
                break;
            case 'toggle-topology-heat-mode':
                toggleTopologyHeatMode();
                break;
            case 'reset-topology-focus':
                resetTopologyFocus();
                break;
            case 'toggle-target-issues':
                toggleTargetIssues();
                break;
            case 'toggle-target-hot':
                toggleTargetHot();
                break;
            case 'reset-target-filters':
                resetTargetFilters();
                break;
            case 'toggle-target-quick-filter':
                toggleTargetQuickFilter(actionEl.dataset.filter || '');
                break;
            case 'export-filtered-logs':
                exportFilteredLogs();
                break;
            case 'toggle-log-level':
                toggleLevel(actionEl);
                break;
            case 'set-log-preset':
                setLogPreset(actionEl.dataset.preset || 'all');
                break;
            case 'toggle-log-stream':
                toggleStream();
                break;
            case 'toggle-log-stream-pause':
                toggleStreamPause();
                break;
            case 'clear-logs':
                clearLogs();
                break;
            case 'export-routes':
                exportRoutes();
                break;
            case 'toggle-route-issues':
                toggleRouteIssues();
                break;
            case 'toggle-route-hot':
                toggleRouteHot();
                break;
            case 'reset-route-filters':
                resetRouteFilters();
                break;
            case 'toggle-route-quick-filter':
                toggleRouteQuickFilter(actionEl.dataset.filter || '');
                break;
            case 'toggle-dns-negatives':
                toggleDnsNegatives();
                break;
            case 'reset-dns-filters':
                resetDnsFilters();
                break;
            case 'export-certs':
                exportCerts();
                break;
            case 'toggle-cert-default-only':
                toggleCertDefaultOnly();
                break;
            case 'toggle-cert-client-ca-only':
                toggleCertClientCaOnly();
                break;
            case 'reset-cert-filters':
                resetCertFilters();
                break;
            case 'export-config':
                exportConfig();
                break;
            case 'apply-runtime-config':
                applyRuntimeConfig();
                break;
            case 'revert-config-draft':
                revertConfigDraft();
                break;
            case 'reset-runtime-config-to-startup':
                resetRuntimeConfigToStartup();
                break;
            case 'toggle-config-diffs':
                toggleConfigDiffs();
                break;
            case 'reset-config-filters':
                resetConfigFilters();
                break;
            case 'toggle-target-detail':
                toggleDetail(Number(actionEl.dataset.index || -1));
                break;
            case 'focus-target-topology':
                focusTargetInTopology(Number(actionEl.dataset.index || -1));
                break;
            case 'close-target-detail':
                closeTargetDetail();
                break;
            case 'set-topology-host-filter':
                setTopologyHostFilter(attrDec(actionEl.dataset.host));
                break;
            case 'select-topology-target':
                selectTopologyTarget(attrDec(actionEl.dataset.key));
                break;
            case 'set-route-host-filter':
                setRouteHostFilter(attrDec(actionEl.dataset.host));
                break;
            case 'focus-route-topology':
                focusRouteInTopology(attrDec(actionEl.dataset.key));
                break;
            case 'select-route':
                selectRoute(attrDec(actionEl.dataset.key));
                break;
            case 'focus-log-target':
                focusLogTarget(attrDec(actionEl.dataset.target));
                break;
            case 'copy-log':
                copyLog(attrDec(actionEl.dataset.text));
                break;
            case 'copy-data':
                copyFromData(actionEl, attrDec(actionEl.dataset.label) || 'Copied');
                break;
            case 'focus-config-field':
                focusConfigField(attrDec(actionEl.dataset.path));
                break;
            case 'toggle-config-section':
                toggleConfigSectionCollapse(attrDec(actionEl.dataset.section));
                break;
            case 'select-cert':
                selectCert(attrDec(actionEl.dataset.entry));
                break;
        }
    });
    document.addEventListener('input', e => {
        if (e.target.matches('.js-config-input:not(select)')) {
            updateConfigDraft(attrDec(e.target.dataset.path), e.target.dataset.type || 'text', e.target.value);
            return;
        }
        switch (e.target.id) {
            case 'target-search':
                filterTargets();
                break;
            case 'log-search':
                filterLogs();
                break;
            case 'route-search':
                filterRoutes();
                break;
            case 'dns-search':
                filterDns();
                break;
            case 'cert-search':
                filterCerts();
                break;
            case 'config-search':
                filterConfig();
                break;
        }
    });
    document.addEventListener('change', e => {
        if (e.target.matches('.js-config-input')) {
            updateConfigDraft(attrDec(e.target.dataset.path), e.target.dataset.type || 'text', e.target.value);
            return;
        }
        switch (e.target.id) {
            case 'target-sort':
                changeTargetSort();
                break;
            case 'route-sort':
                changeRouteSort();
                break;
            case 'route-protocol':
                changeRouteProtocol();
                break;
            case 'cert-risk':
                changeCertRisk();
                break;
        }
    });

    // ===== MOBILE SIDEBAR =====
    function toggleSidebar() { sidebarOpen=!sidebarOpen; document.getElementById('sidebar').classList.toggle('open',sidebarOpen); document.getElementById('sidebar-overlay').classList.toggle('active',sidebarOpen); }
    function closeSidebar() { sidebarOpen=false; document.getElementById('sidebar').classList.remove('open'); document.getElementById('sidebar-overlay').classList.remove('active'); }

    // ===== AUTH =====
    async function doLogin() {
        const u=document.getElementById('username-input').value.trim(), p=document.getElementById('password-input').value;
        try { const r=await fetch(API+'/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,password:p})}); const d=await r.json(); if(d.success&&d.token){token=d.token;username=d.user||u;localStorage.setItem('admin_token',token);localStorage.setItem('admin_user',username);showApp();}else document.getElementById('login-error').style.display='block'; } catch(e){document.getElementById('login-error').style.display='block';}
    }
    async function doLogout() {
        try{await fetch(API+'/logout',{method:'POST',headers:hdrs()});}catch(e){}
        if (staticRefreshTimer) clearTimeout(staticRefreshTimer);
        if (metricsSse) metricsSse.close();
        stopLogStream();
        localStorage.removeItem('admin_token');localStorage.removeItem('admin_user');location.reload();
    }
    function showApp() {
        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('app').classList.add('active');
        document.getElementById('user-name').textContent = username;
        document.getElementById('user-avatar').textContent = (username[0] || '?').toUpperCase();
        if (!charts.latency || !charts.status) initCharts();
        startMetrics();
        refreshStatic();
    }

    // ===== NAVIGATION =====
    function showPage(p) {
        document.querySelectorAll('.nav-item').forEach(a=>a.classList.remove('active'));
        document.querySelector(`[data-page="${p}"]`).classList.add('active');
        document.querySelectorAll('.page').forEach(e=>e.classList.remove('active'));
        document.getElementById('page-'+p).classList.add('active');
        if (p !== 'topology') { stopTopoAnimation(); hideTopoTooltip(); }
        if(p==='overview') renderOverview();
        if(p==='topology') { renderTopologyPanels(topoData); drawTopo(); scheduleTopoFrame(); }
        if(p==='targets') renderTargets(getVisibleTargets(), false);
        if(p==='logs') renderLogs();
        if(p==='routes') renderRoutes(cachedRoutes || { routes: [] });
        if(p==='consul') renderConsul(cachedConsul || {});
        if(p==='dns') renderDns(cachedDns || { stats:{}, entries:[] });
        if(p==='certs') renderCerts(cachedCerts || { certificates: [] });
        if(p==='config') renderConfig(cachedConfig || {});
    }
    function navTo(p) { showPage(p); closeSidebar(); }
    document.addEventListener('keydown', e => { if (e.key === 'Escape' && sidebarOpen) closeSidebar(); });

    // ===== SSE METRICS =====
    function startMetrics() {
        if(metricsSse) metricsSse.close();
        metricsSse = new EventSource(API+'/metrics/stream?token='+encodeURIComponent(token));
        metricsSse.onmessage = e => {
            if (e.data === 'connected') { setErr(false); return; }
            try { const s = JSON.parse(e.data); processSnap(s); setErr(false); } catch(err){}
        };
        metricsSse.onerror = () => setErr(true);
    }
    function pruneTargetCaches(activeTargets, nowMs = Date.now()) {
        const activeKeys = new Set((activeTargets || []).map(targetKey));
        Object.keys(targetHist).forEach(key => {
            const last = targetHist[key]?.ts?.[targetHist[key].ts.length - 1];
            if (!activeKeys.has(key) && (!last || nowMs - tsToMs(last) > TARGET_HISTORY_TTL_MS)) delete targetHist[key];
        });
        Object.keys(prevTargets).forEach(key => {
            const last = prevTargets[key]?.ts;
            if (!activeKeys.has(key) && (!last || nowMs - tsToMs(last) > TARGET_HISTORY_TTL_MS)) delete prevTargets[key];
        });
    }
    function processSnap(s) {
        if (!s.targets && !s.requests_total && s.requests_total !== 0) return;
        const dt = prevSnap ? Math.max(s.timestamp - prevSnap.timestamp, 1) : 1;
        const rps = prevSnap ? ((s.requests_total - prevSnap.requests_total) / dt).toFixed(1) : '0';
        const errRate = s.requests_total > 0 ? ((s.requests_error_total / s.requests_total) * 100).toFixed(1) + '%' : '0%';
        const errPct = s.requests_total > 0 ? s.requests_error_total / s.requests_total : 0;
        currentMetricSnapshot = { ...s, rps: Number(rps), errRateText: errRate, errPct };
        document.getElementById('s-rps').textContent = rps;
        document.getElementById('s-err').textContent = errRate;
        document.getElementById('s-err').className = 'stat-value' + (errPct > 0.05 ? ' red' : errPct > 0.01 ? ' yellow' : '');
        document.getElementById('s-conn').textContent = s.active_connections;
        document.getElementById('s-total').textContent = fmt(s.requests_total);
        document.getElementById('s-rt').textContent = s.route_count + ' / ' + s.target_count;
        if (s.targets && s.targets.length > 0) {
            const avg = s.targets.reduce((a, t) => a + t.avg_latency_us, 0) / s.targets.length;
            document.getElementById('s-lat').textContent = fmtLat(Math.round(avg));
        }
        // Update target history and delta tracking
        if (s.targets) s.targets.forEach(t => {
            const key = targetKey(t);
            if (!targetHist[key]) targetHist[key] = { req: [], err: [], errPct: [], lat: [], bytesRate: [], ts: [] };
            const h = targetHist[key];
            const prevReq = h.req.length > 0 ? h.req[h.req.length - 1] : 0;
            h.req.push(t.requests); h.err.push(t.errors); h.errPct.push(t.requests > 0 ? (t.errors / t.requests) * 100 : 0); h.lat.push(t.avg_latency_us || 0); h.ts.push(s.timestamp);
            if (h.req.length > HIST) { h.req.shift(); h.err.shift(); h.errPct.shift(); h.lat.shift(); h.ts.shift(); }
            h.rate = prevSnap ? (t.requests - prevReq) / dt : 0;
            const prev = prevTargets[key];
            prevTargets[key] = {
                requests: t.requests,
                errors: t.errors,
                latency: t.avg_latency_us,
                connections: t.active_connections,
                ts: s.timestamp,
                deltaReq: prev ? t.requests - prev.requests : 0,
                deltaErr: prev ? t.errors - prev.errors : 0,
                deltaLat: prev ? t.avg_latency_us - prev.latency : 0,
                deltaConn: prev ? t.active_connections - prev.connections : 0,
            };
        });
        const overviewAvgLatency = s.targets && s.targets.length > 0
            ? Math.round(s.targets.reduce((a, t) => a + t.avg_latency_us, 0) / s.targets.length)
            : 0;
        overviewHistory.rps.push(Number(rps));
        overviewHistory.err.push(errPct * 100);
        overviewHistory.conn.push(s.active_connections || 0);
        overviewHistory.lat.push(overviewAvgLatency);
        overviewHistory.ts.push(s.timestamp);
        if (overviewHistory.rps.length > HIST) {
            overviewHistory.rps.shift(); overviewHistory.err.shift(); overviewHistory.conn.shift(); overviewHistory.lat.shift(); overviewHistory.ts.shift();
        }
        if (s.targets) pruneTargetCaches(s.targets, tsToMs(s.timestamp) || Date.now());
        if (s.targets && s.targets.length > 0 && allTargets.length > 0) {
            const byKey = new Map(s.targets.map(t => [targetKey(t), t]));
            allTargets = allTargets.map(t => {
                const live = byKey.get(targetKey(t));
                if (!live) return t;
                const requests = live.requests ?? t.stats?.requests ?? 0;
                const errors = live.errors ?? t.stats?.errors ?? 0;
                return {
                    ...t,
                    protocol: live.protocol || t.protocol,
                    circuit_breaker: live.circuit_breaker || t.circuit_breaker,
                    active_connections: live.active_connections ?? t.active_connections,
                    stats: {
                        ...(t.stats || {}),
                        requests,
                        errors,
                        avg_latency_us: live.avg_latency_us ?? t.stats?.avg_latency_us ?? 0,
                        error_rate_pct: requests > 0 ? Math.round((errors / requests) * 100) : 0,
                    },
                };
            });
        }
        prevSnap = s;
        if (document.getElementById('page-overview').classList.contains('active')) {
            renderOverview();
        }
        if (document.getElementById('page-targets').classList.contains('active')) {
            renderTargets(getVisibleTargets(), true);
        }
    }
    // Update only the changing cells in targets table (delta arrows + colors)
    function updateTargetDeltas() {
        const rows = document.querySelectorAll('#targets-tbody tr');
        const tgts = window._tgts || [];
        rows.forEach((row, i) => {
            const t = tgts[i]; if (!t) return;
            const key = targetKey(t);
            const d = prevTargets[key]; if (!d) return;
            const rpsCell = row.cells[5]; if (rpsCell) {
                const h = targetHist[key], rate = h ? h.rate : 0;
                const arrow = trendArrow(d.deltaReq, 0);
                rpsCell.innerHTML = spark((h ? h.req.slice(-20) : []), 40, 13, rate > 0 ? 'var(--accent)' : 'var(--text-4)') + ' <span style="font-size:0.76rem">' + rate.toFixed(1) + '</span> ' + arrow;
            }
            // Error % cell (index 6)
            const errCell = row.cells[6]; if (errCell) {
                const errPct = t.stats?.error_rate_pct || 0;
                errCell.innerHTML = trendVal(errPct, d.deltaErr, [0.5, 2, 5], true) + ' ' + trendArrow(d.deltaErr, 0);
            }
            // Latency cell (index 7)
            const latCell = row.cells[7]; if (latCell) {
                const lat = t.stats?.avg_latency_us ? fmtLat(t.stats.avg_latency_us) : '-';
                latCell.innerHTML = trendLat(t.stats?.avg_latency_us || 0, d.deltaLat);
            }
            // Connections cell (index 8)
            const connCell = row.cells[8]; if (connCell) {
                connCell.innerHTML = trendConn(t.active_connections || 0, d.deltaConn);
            }
        });
    }
    // Trend arrow HTML: ▲ increase ▼ decrease — when delta exceeds threshold
    function trendArrow(delta, threshold) {
        const abs = Math.abs(delta);
        if (abs <= threshold) return '<span style="color:var(--text-4);font-size:0.7rem">&mdash;</span>';
        if (delta > 0) return '<span style="color:var(--yellow);font-size:0.7rem">&#x25B2;</span>';
        return '<span style="color:var(--green);font-size:0.7rem">&#x25BC;</span>';
    }
    // Colored value with thresholds [green_thresh, yellow_thresh, red_thresh]
    function trendVal(val, delta, thresholds, invert) {
        const [g, y, r] = thresholds;
        let cls = 'color:var(--text-3)';
        if (invert) { if (val > r) cls = 'color:var(--red)'; else if (val > y) cls = 'color:var(--yellow)'; else if (val > g) cls = 'color:var(--green)'; }
        else { if (val > r) cls = 'color:var(--green)'; else if (val > y) cls = 'color:var(--yellow)'; else cls = 'color:var(--text-3)'; }
        return `<span style="${cls}">${val}%</span>`;
    }
    // Latency with color + trend arrow
    function trendLat(latUs, delta) {
        let cls = 'var(--green)'; // < 10ms
        if (latUs > 500000) cls = 'var(--red)';      // > 500ms
        else if (latUs > 100000) cls = 'var(--yellow)'; // > 100ms
        else if (latUs > 10000) cls = 'var(--text-2)';  // > 10ms
        const txt = latUs ? fmtLat(Math.round(latUs)) : '-';
        const arr = trendArrow(delta, 0);
        return `<span style="color:${cls}">${txt}</span> ${arr}`;
    }
    // Connections with color + trend arrow
    function trendConn(conn, delta) {
        let cls = 'var(--text-3)';
        if (conn > 100) cls = 'var(--red)';
        else if (conn > 50) cls = 'var(--yellow)';
        else if (conn > 0) cls = 'var(--green)';
        const arr = trendArrow(delta, 0);
        return `<span style="color:${cls}">${conn}</span> ${arr}`;
    }
    function updateTargetHistoriesFromStaticTargets(targets) {
        const now = Date.now();
        (targets || []).forEach(t => {
            const key = targetKey(t);
            if (!targetHist[key]) targetHist[key] = { req: [], err: [], errPct: [], lat: [], bytesRate: [], ts: [] };
            const h = targetHist[key];
            h.errPct.push(Number(t.stats?.error_rate_pct || 0));
            h.lat.push(Number(t.stats?.avg_latency_us || 0));
            h.bytesRate.push(targetThroughput(t));
            h.ts.push(now);
            if (h.errPct.length > HIST) h.errPct.shift();
            if (h.lat.length > HIST) h.lat.shift();
            if (h.bytesRate.length > HIST) h.bytesRate.shift();
            if (h.ts.length > HIST) h.ts.shift();
        });
        pruneTargetCaches(targets, now);
    }

    // ===== STATIC REFRESH =====
    async function refreshStatic() {
        if(!token) return;
        const safe=(p,fb)=>p.catch(()=>fb);
        const [routes,targets,dns,consul,config,logs,certs,health] = await Promise.all([
            safe(api('/routes'),{route_count:0,target_count:0,routes:[]}),
            safe(api('/targets'),{targets:[]}),
            safe(api('/dns-cache'),{stats:{},entries:[]}),
            safe(api('/consul-status'),{}),
            safe(api('/config'),{}),
            safe(api('/logs?limit=200'),[]),
            safe(api('/certs'),{certificates:[]}),
            safe(api('/health'),{})
        ]);
        cachedLogs=logs||[];
        cachedConfig=config;
        cachedConfigStartup=config?.meta?.startup || null;
        cachedConfigRuntime=config?.meta?.runtime || null;
        if (!configDraft || !configDraftIsDirty()) configDraft = buildConfigDraft(config);
        cachedCerts=certs;
        cachedRoutes=routes;
        cachedConsul=consul;
        cachedDns=dns;
        allTargets = targets.targets || [];
        updateTargetHistoriesFromStaticTargets(allTargets);
        renderTargets(getVisibleTargets(), true);
        renderDns(cachedDns); renderConsul(cachedConsul); renderRoutes(routes); renderOverview();
        renderLogs(); renderCerts(certs); renderConfig(config);
        refreshMetrics();
        if(config?.proxy?.strategy) document.getElementById('status-strategy').textContent = config.proxy.strategy;
        if(config?.proxy?.matcher) document.getElementById('status-matcher').textContent = config.proxy.matcher;
        if(health?.version) document.getElementById('status-version').textContent = `${health.service || 'sentirum-lb'} v${health.version}`;
        try { topoData=await api('/topology'); updateTopologyHistories(topoData); renderTopologyPanels(topoData); if(document.getElementById('page-topology').classList.contains('active')) { drawTopo(); scheduleTopoFrame(); } } catch(e){}
        scheduleStaticRefresh(10000);
    }
    async function refreshMetrics() {
        try {
            const r = await fetch(API+'/metrics', {headers:hdrs()});
            const t = await r.text();
            // Parse Prometheus exposition format properly
            // Histogram buckets: sentirum_lb_request_duration_seconds_bucket{le="0.001"} 37
            // Counters/Gauges: sentirum_lb_active_connections 0
            // Labeled: sentirum_lb_response_status_total{code="2xx"} 96
            const buckets = {}; // le -> value
            const statusCodes = {}; // code -> value
            const gauges = {}; // simple name -> value
            for (const line of t.split('\n')) {
                if (line.startsWith('#') || !line.trim()) continue;
                const parts = line.trim().split(' ');
                if (parts.length < 2) continue;
                const rawName = parts[0];
                const val = parseFloat(parts[parts.length - 1]);
                if (isNaN(val)) continue;
                const baseName = rawName.replace(/\{.*?\}/, '').replace(/^sentirum_lb_/, '');
                // Parse histogram bucket labels
                const leMatch = rawName.match(/\{le="([^"]+)"\}/);
                if (leMatch) {
                    buckets[leMatch[1]] = val;
                    continue;
                }
                // Parse status code labels
                const codeMatch = rawName.match(/\{code="([^"]+)"\}/);
                if (codeMatch) {
                    statusCodes[codeMatch[1]] = val;
                    continue;
                }
                gauges[baseName] = val;
            }
            // Latency distribution histogram
            if (charts.latency) {
                charts.latency.data.labels = ['<1ms','<5ms','<10ms','<25ms','<50ms','<100ms','<250ms','<500ms','<1s','<5s','>5s'];
                // Compute deltas between buckets for bar chart
                const bKeys = ['0.001','0.005','0.01','0.025','0.05','0.1','0.25','0.5','1','5','+Inf'];
                const bVals = bKeys.map(k => buckets[k] || 0);
                // Convert cumulative to per-bucket deltas
                const deltas = bVals.map((v, i) => i === 0 ? v : v - bVals[i - 1]);
                charts.latency.data.datasets[0].data = deltas;
                charts.latency.update('none');
            }
            // Status code doughnut
            if (charts.status) {
                charts.status.data.datasets[0].data = [
                    statusCodes['2xx'] || 0,
                    statusCodes['3xx'] || 0,
                    statusCodes['4xx'] || 0,
                    statusCodes['5xx'] || 0
                ];
                charts.status.update('none');
            }
        } catch(e) { /* metrics endpoint unavailable */ }
    }
    function setErr(yes) {
        const b=document.getElementById('error-banner'), d=document.getElementById('status-dot'), t=document.getElementById('status-text');
        if(yes){b.classList.add('visible');if(d)d.style.background='var(--red)';if(t)t.textContent='Disconnected'; updateLivePills(false);}
        else{b.classList.remove('visible');if(d)d.style.background='var(--green)';if(t)t.textContent='Connected'; updateLivePills(true);}
    }

    // ===== CHARTS =====
    function initCharts() {
        const base={responsive:true,maintainAspectRatio:true,plugins:{legend:{display:false}},scales:{y:{ticks:{color:'#52525b',font:{size:10}},grid:{color:'#1e1e22'}},x:{ticks:{color:'#52525b',font:{size:10}},grid:{display:false}}}};
        charts.latency=new Chart(document.getElementById('lat-chart'),{type:'bar',data:{labels:[],datasets:[{data:[],backgroundColor:'#818cf8',borderRadius:3,barPercentage:0.8}]},options:base});
        charts.status=new Chart(document.getElementById('status-chart'),{type:'doughnut',data:{labels:['2xx','3xx','4xx','5xx'],datasets:[{data:[0,0,0,0],backgroundColor:['#34d399','#fbbf24','#f97316','#f87171'],borderWidth:0}]},options:{responsive:true,maintainAspectRatio:true,cutout:'65%',plugins:{legend:{position:'bottom',labels:{color:'#71717a',padding:10,font:{size:11}}}}}});
    }

    // ===== SPARKLINE =====
    function spark(data,w,h,color) {
        if(!data||data.length<2) return '';
        const max=Math.max(...data,1), step=w/(data.length-1);
        const pts=data.map((v,i)=>`${(i*step).toFixed(1)},${(h-(v/max)*h).toFixed(1)}`).join(' ');
        return `<svg class="spark" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}"><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linejoin="round"/></svg>`;
    }

    // ===== CB TIMELINE =====
    function cbTL(hist) {
        if(!hist?.length) return '<span style="color:var(--text-4)">-</span>';
        const segs=hist.slice(-6); let h='<div class="cbtl" title="';
        segs.forEach(s=>{h+=`${s.from}→${s.to} ${fmtTime(s.timestamp_ms)}  `;});
        h+='">'; segs.forEach(s=>{h+=`<div class="cbtl-s ${s.to==='closed'?'closed':s.to==='open'?'open':'halfopen'}" style="width:${Math.max(5,100/segs.length)}%"></div>`;});
        return h+'</div>';
    }

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
        return (allTargets || [])
            .filter(x => x.url === t.url && x.service === t.service)
            .sort((a, b) => String(a.host || '').localeCompare(String(b.host || '')) || String(a.path || '').localeCompare(String(b.path || '')));
    }
    function focusTargetInTopology(i) {
        const t = window._tgts?.[i];
        if (!t) return;
        topologyMode = 'all';
        topologyHostFilter = t.host || '*';
        topologySelectedTargetKey = targetKey(t);
        ['all','issues','hot'].forEach(name => document.getElementById(`topo-mode-${name}`)?.classList.toggle('on', name === 'all'));
        document.getElementById('topo-heat-btn')?.classList.toggle('on', topologyHeatMode);
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
        selectedTarget = null;
        selectedTargetKey = null;
        renderTargetDetailEmpty();
    }
    function getVisibleTargets() {
        const query = targetSearch.trim().toLowerCase();
        const filtered = allTargets.filter(t => {
            if (targetIssuesOnly) {
                const errPct = t.stats?.error_rate_pct || 0;
                if (!(errPct > 0 || t.circuit_breaker === 'open' || t.circuit_breaker === 'halfopen' || !t.probe_healthy)) return false;
            }
            if (targetHotOnly && !targetIsHot(t)) return false;
            if (targetQuickFilters.open && t.circuit_breaker !== 'open') return false;
            if (targetQuickFilters.probe && t.probe_healthy) return false;
            if (targetQuickFilters.latency && !targetIsHighLatency(t)) return false;
            if (targetQuickFilters.throughput && !targetIsHighThroughput(t)) return false;
            if (!query) return true;
            const haystack = `${t.service||''} ${t.host||''} ${t.path||''} ${t.url||''} ${t.protocol||''} ${t.source||''}`.toLowerCase();
            return haystack.includes(query);
        });
        filtered.sort((a, b) => {
            switch (targetSort) {
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
        const highestRps = [...targets].sort((a, b) => (targetHist[targetKey(b)]?.rate || 0) - (targetHist[targetKey(a)]?.rate || 0))[0];
        const highestThroughput = [...targets].sort((a, b) => targetThroughput(b) - targetThroughput(a))[0];
        const slowest = [...targets].sort((a, b) => (b.stats?.avg_latency_us || 0) - (a.stats?.avg_latency_us || 0))[0];
        document.getElementById('targets-summary').innerHTML = `
            <div class="summary-card"><div class="k">Visible targets</div><div class="v">${targets.length}</div></div>
            <div class="summary-card"><div class="k">Open / half-open</div><div class="v">${openCount} / ${halfOpenCount}</div><div class="subtle">probe unhealthy ${unhealthyCount}</div></div>
            <div class="summary-card"><div class="k">Hot targets</div><div class="v">${hotCount}</div><div class="subtle">flow or connection activity</div></div>
            <div class="summary-card"><div class="k">Highest req/s</div><div class="v">${esc(highestRps?.service || '—')}</div><div class="subtle">${fmtRate(targetHist[targetKey(highestRps || {})]?.rate || 0)}</div></div>
            <div class="summary-card"><div class="k">Highest throughput</div><div class="v">${esc(highestThroughput?.service || '—')}</div><div class="subtle">${fmtBps(targetThroughput(highestThroughput || {}))}</div></div>
            <div class="summary-card"><div class="k">Slowest</div><div class="v">${esc(slowest?.service || '—')}</div><div class="subtle">${fmtLat(slowest?.stats?.avg_latency_us || 0)}</div></div>
        `;
    }
    function updateTargetsMeta(totalVisible) {
        const quickOn = Object.entries(targetQuickFilters).filter(([, on]) => on).map(([name]) => name).join(', ');
        document.getElementById('targets-meta').textContent = `${totalVisible} shown · ${allTargets.length} total${targetHotOnly ? ' · hot only' : ''}${targetIssuesOnly ? ' · issues only' : ''}${quickOn ? ` · ${quickOn}` : ''}`;
    }
    function syncTargetQuickFilters() {
        Object.entries(targetQuickFilters).forEach(([name, on]) => {
            document.getElementById(`target-chip-${name}`)?.classList.toggle('on', on);
        });
    }
    function filterTargets() { targetSearch = document.getElementById('target-search').value || ''; renderTargets(getVisibleTargets(), false); }
    function changeTargetSort() { targetSort = document.getElementById('target-sort').value || 'risk'; renderTargets(getVisibleTargets(), false); }
    function toggleTargetIssues() {
        targetIssuesOnly = !targetIssuesOnly;
        document.getElementById('target-issues-btn').classList.toggle('on', targetIssuesOnly);
        renderTargets(getVisibleTargets(), false);
    }
    function toggleTargetHot() {
        targetHotOnly = !targetHotOnly;
        document.getElementById('target-hot-btn').classList.toggle('on', targetHotOnly);
        renderTargets(getVisibleTargets(), false);
    }
    function toggleTargetQuickFilter(name) {
        targetQuickFilters[name] = !targetQuickFilters[name];
        syncTargetQuickFilters();
        renderTargets(getVisibleTargets(), false);
    }
    function resetTargetFilters() {
        targetSearch = ''; targetSort = 'risk'; targetIssuesOnly = false; targetHotOnly = false;
        targetQuickFilters = { open: false, probe: false, latency: false, throughput: false };
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
                const h = targetHist[key], rate = h ? h.rate : 0;
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
                    const d = prevTargets[key];
                    const arrow = d ? trendArrow(d.deltaReq, 0) : '';
                    rc.innerHTML = `<div class="target-rate-cell">${spark(h ? h.req.slice(-20) : [], 48, 14, sc)}<div><span style="font-size:0.76rem">${rate.toFixed(1)}</span> ${arrow} <span class="subtle">5s ${fmtRate(topoReqRateStable(topoFlow(t)))}</span></div></div>`;
                }
                const tc = row.cells[6];
                if (tc) {
                    tc.innerHTML = `<div class="target-throughput-cell"><span class="target-flowbar"><span class="target-flowbar-fill" style="width:${Math.max(6, Math.min(100, targetHeat(t) * 100))}%"></span></span><span>${fmtBps(throughput)}</span><span class="subtle">${fmtAgoMs(targetLastActive(t))}</span></div>`;
                }
                const ec = row.cells[7];
                if (ec) {
                    const d = prevTargets[key];
                    const arrow = d ? trendArrow(d.deltaErr, 0) : '';
                    ec.innerHTML = trendVal(errPct, d?.deltaErr || 0, [0.5, 2, 5], true) + ' ' + arrow;
                }
                const lc = row.cells[8];
                if (lc) {
                    const d = prevTargets[key];
                    lc.innerHTML = trendLat(t.stats?.avg_latency_us || 0, d?.deltaLat || 0);
                }
                const cc = row.cells[9];
                if (cc) {
                    const d = prevTargets[key];
                    cc.innerHTML = trendConn(t.active_connections || 0, d?.deltaConn || 0);
                }
                const bc = row.cells[10];
                if (bc) bc.innerHTML = `<div class="cell-stack"><div class="target-badges tight">${targetHeatChip(t)} <span class="target-health-badge ${healthClass}">${esc(targetHealthLabel(t))}</span></div><span>${cbTL(t.circuit_breaker_history)} <span class="cb cb-${esc(t.circuit_breaker)}">${esc(t.circuit_breaker)}</span></span></div>`;
            });
        } else {
            tbody.innerHTML = targets.map((t, i) => {
                const key = targetKey(t);
                const h = targetHist[key], rate = h ? h.rate : 0, reqD = h ? h.req.slice(-20) : [];
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
        if (selectedTargetKey) {
            const idx = targets.findIndex(t => targetKey(t) === selectedTargetKey);
            if (idx >= 0) toggleDetail(idx, true);
            else closeTargetDetail();
        }
    }
    function toggleDetail(i, forceOpen = false) {
        const p=document.getElementById('target-detail');
        const t=window._tgts[i]; if(!t)return;
        const key = targetKey(t);
        if(!forceOpen && selectedTarget===i && selectedTargetKey===key){closeTargetDetail();return;}
        selectedTarget=i;
        selectedTargetKey=key;
        const h=targetHist[key]||{req:[],err:[],errPct:[],lat:[],bytesRate:[],rate:0};
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

    // ===== TOPOLOGY =====
    function topologyTargets(hosts) {
        return (hosts || []).flatMap(host =>
            (host.routes || []).flatMap(route =>
                (route.targets || []).map(t => ({ ...t, host: host.host || '', path: route.path || '/' }))
            )
        );
    }
    function topologyNeedsAnimation(data = topoData) {
        if (!data) return false;
        return topologyTargets(topologyVisibleHosts(data)).some(t => topoFlowHot(topoFlow(t)));
    }
    function scheduleTopoFrame() {
        if (topoAnimFrame) return;
        topoAnimFrame = requestAnimationFrame(ts => {
            topoAnimFrame = null;
            if (!document.getElementById('page-topology')?.classList.contains('active')) return;
            drawTopo(ts);
            if (topologyNeedsAnimation()) scheduleTopoFrame();
        });
    }
    function stopTopoAnimation() {
        if (!topoAnimFrame) return;
        cancelAnimationFrame(topoAnimFrame);
        topoAnimFrame = null;
    }
    function hideTopoTooltip() {
        topoHoverItem = null;
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
        const nodeHit = topoNodeRects.find(n => ((point.x - n.x) ** 2) + ((point.y - n.y) ** 2) <= n.r ** 2);
        if (nodeHit) return nodeHit;
        return topoHitAreas.find(area => topoPointSegDist(point.x, point.y, area.x1, area.y1, area.x2, area.y2) <= area.pad);
    }
    function updateTopologyHistories(data) {
        if (!data?.hosts) return;
        const seen = new Set();
        data.hosts.forEach(host => {
            (host.routes || []).forEach(route => {
                const key = topologyRouteKey(host.host || '*', route.path || '/');
                seen.add(key);
                if (!topoRouteHist[key]) topoRouteHist[key] = { req: [], bytes: [], errPct: [], lat: [], ts: [] };
                const h = topoRouteHist[key];
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
        Object.keys(topoRouteHist).forEach(key => {
            if (!seen.has(key) && topoRouteHist[key].ts?.length && (Date.now() - topoRouteHist[key].ts[topoRouteHist[key].ts.length - 1] > 10 * 60 * 1000)) {
                delete topoRouteHist[key];
            }
        });
    }
    function topologyVisibleHosts(data = topoData) {
        if (!data) return [];
        let hosts = [...(data.hosts || [])];
        if (topologyHostFilter !== '*') hosts = hosts.filter(host => (host.host || '*') === topologyHostFilter);
        if (topologyMode === 'issues') {
            hosts = hosts.filter(host => (host.routes || []).some(route => (route.targets || []).some(t => t.circuit_breaker !== 'closed' || (t.stats?.error_rate_pct || 0) > 0)));
        } else if (topologyMode === 'hot') {
            hosts = hosts.filter(host => (host.routes || []).some(route => topoFlowHot(topoFlow(route)) || (route.targets || []).some(t => topoFlowHot(topoFlow(t)) || (t.active_connections || 0) > 0)));
        }
        return hosts;
    }
    function setTopologyMode(mode) {
        topologyMode = mode;
        ['all','issues','hot'].forEach(name => document.getElementById(`topo-mode-${name}`).classList.toggle('on', name === mode));
        topologySelectedTargetKey = null;
        hideTopoTooltip();
        renderTopologyPanels(topoData);
        drawTopo();
        scheduleTopoFrame();
    }
    function toggleTopologyHeatMode() {
        topologyHeatMode = !topologyHeatMode;
        document.getElementById('topo-heat-btn')?.classList.toggle('on', topologyHeatMode);
        hideTopoTooltip();
        renderTopologyPanels(topoData);
        drawTopo();
        scheduleTopoFrame();
    }
    function setTopologyHostFilter(host) {
        topologyHostFilter = host;
        topologySelectedTargetKey = null;
        hideTopoTooltip();
        renderTopologyPanels(topoData);
        drawTopo();
        scheduleTopoFrame();
    }
    function selectTopologyTarget(key) {
        topologySelectedTargetKey = key;
        hideTopoTooltip();
        renderTopologyPanels(topoData);
        drawTopo();
        scheduleTopoFrame();
    }
    function resetTopologyFocus() {
        topologyMode = 'all';
        topologyHeatMode = false;
        topologyHostFilter = '*';
        topologySelectedTargetKey = null;
        hideTopoTooltip();
        topoScale = 1;
        topoPan = { x: 0, y: 0 };
        ['all','issues','hot'].forEach(name => document.getElementById(`topo-mode-${name}`).classList.toggle('on', name === 'all'));
        document.getElementById('topo-heat-btn')?.classList.remove('on');
        renderTopologyPanels(topoData);
        drawTopo();
        scheduleTopoFrame();
    }
    function renderTopologyPanels(data) {
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
        document.getElementById('topology-hosts').innerHTML = [`<button class="topo-host-btn ${topologyHostFilter === '*' ? 'on' : ''}" data-action="set-topology-host-filter" data-host="${attrEnc('*')}">All hosts</button>`]
            .concat(allHosts.map(host => {
                const name = host.host || '*';
                const flow = topoFlow(host);
                return `<button class="topo-host-btn ${topologyHostFilter === name ? 'on' : ''}" data-action="set-topology-host-filter" data-host="${attrEnc(name)}">${esc(name)} <span class="subtle">${fmtRate(topoReqRate(flow))}</span></button>`;
            }))
            .join('');
        document.getElementById('topology-meta').textContent = `${visibleHosts.length} host lane(s) · mode: ${topologyMode}${topologyHeatMode ? ' · heat map on' : ''}${topologySelectedTargetKey ? ' · target selected' : ''}`;

        const selected = targets.find(t => targetKey(t) === topologySelectedTargetKey);

        const routeItems = visibleHosts.map(host => {
            const routes = host.routes || [];
            return routes.map(route => {
                const hostLabel = host.host || '*';
                const flow = topoFlow(route);
                const routeHist = topoRouteHist[topologyRouteKey(hostLabel, route.path || '/')] || { req: [], bytes: [] };
                const routeErr = Math.max(...(route.targets || []).map(t => t.stats?.error_rate_pct || 0), 0);
                const routeHeat = topoHeatLevel(flow);
                const routeSparkColor = topologyHeatMode
                    ? routeHeat >= 0.82 ? '#fb923c' : routeHeat >= 0.58 ? '#d946ef' : routeHeat >= 0.34 ? '#60a5fa' : '#22d3ee'
                    : 'var(--accent)';
                const targetChips = (route.targets || []).map(t => {
                    const key = targetKey({ host: hostLabel, path: route.path, service: t.service, url: t.url });
                    const targetFlow = topoFlow(t);
                    const cls = topologySelectedTargetKey === key ? 'active' : t.circuit_breaker === 'open' ? 'danger' : topoFlowHot(targetFlow) || (t.stats?.error_rate_pct || 0) > 0 || (t.active_connections || 0) > 0 ? 'hot' : '';
                    return `<button class="topo-target-chip ${cls}" data-action="select-topology-target" data-key="${attrEnc(key)}">${esc(t.service)} · ${fmtRate(topoReqRate(targetFlow))}</button>`;
                }).join('');
                return `<div class="topo-route-item"><div class="topo-route-head"><div><div class="panel-item-title">${esc(hostLabel)} ${esc(route.path)}</div><div class="panel-item-sub">${esc(route.matcher || 'prefix')} matcher · ${(route.targets || []).length} target(s) · ${fmtBps(topoByteRateStable(flow))}</div></div><div class="topo-route-metrics"><div class="topo-route-trend">${spark(routeHist.req.slice(-20), 68, 16, routeSparkColor) || '<span class="subtle">no trend</span>'}<span class="subtle">${fmtRate(topoReqRateStable(flow))}</span></div>${topologyHeatMode ? `<span class="topo-heat-badge">heat ${(routeHeat * 100).toFixed(0)}%</span>` : ''}<span class="metric-chip">${fmtRate(topoReqRateStable(flow))} · ${routeErr}% err</span></div></div><div class="topo-route-targets">${targetChips}</div></div>`;
            }).join('');
        }).join('') || '<div class="empty">No routes match the current topology filters</div>';

        const selectedFlow = topoFlow(selected);
        const focusCard = selected
            ? `<div class="topo-focus-card"><div class="panel-item-title">Selected target</div><div class="panel-item-sub">${esc(selected.service)} · ${esc(selected.url)}${topologyHeatMode ? ' · heat-aware view' : ''}</div><dl class="topo-kv" style="margin-top:0.65rem"><dt>Route</dt><dd>${esc((selected.host || '*') + (selected.path || ''))}</dd><dt>Protocol</dt><dd>${esc(selected.protocol || 'http')}</dd><dt>Circuit</dt><dd>${esc(selected.circuit_breaker || 'closed')}</dd><dt>Live req/s</dt><dd>${fmtRate(topoReqRate(selectedFlow))}</dd><dt>Throughput</dt><dd>${fmtBps(topoByteRate(selectedFlow))}</dd><dt>Heat level</dt><dd>${(topoHeatLevel(selectedFlow) * 100).toFixed(0)}%</dd><dt>Requests</dt><dd>${fmt(selected.stats?.requests || 0)}</dd><dt>Error rate</dt><dd>${selected.stats?.error_rate_pct || 0}%</dd><dt>Latency</dt><dd>${fmtLat(selected.stats?.avg_latency_us || 0)}</dd><dt>Connections</dt><dd>${selected.active_connections || 0}</dd><dt>Last active</dt><dd>${fmtAgoMs(selectedFlow?.last_active_ms_ago)}</dd></dl></div>`
            : `<div class="topo-focus-card"><div class="panel-item-title">How to use this map</div><div class="panel-item-sub">Flow dots reflect short-window traffic. Hover edges for live metrics, use Heat map to bias colors by traffic intensity, and click any target node to inspect req/s and throughput.</div></div>`;

        document.getElementById('topology-inspector').innerHTML = `
            <div class="panel-head"><div><div class="panel-title">Topology inspector</div><div class="subtle">Actionable route lanes instead of a passive graph</div></div></div>
            <div class="panel-body">
                <dl class="mini-kv" style="margin-bottom:0.9rem">
                    <dt>Load balancer requests</dt><dd>${fmt(data.lb?.requests || 0)}</dd>
                    <dt>Live req/s</dt><dd>${fmtRate(topoReqRate(topoFlow(data.lb)))}</dd>
                    <dt>Throughput</dt><dd>${fmtBps(topoByteRate(topoFlow(data.lb)))}</dd>
                    <dt>Active connections</dt><dd>${fmt(data.lb?.active_connections || 0)}</dd>
                    <dt>Error rate</dt><dd>${data.lb?.error_rate || 0}%</dd>
                    <dt>Filter mode</dt><dd>${esc(topologyMode)}</dd>
                    <dt>Heat map</dt><dd>${topologyHeatMode ? 'Enabled' : 'Off'}</dd>
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
        if(!topoData)return;
        const c=document.getElementById('topo-canvas'); if(!c)return;
        const ctx=c.getContext('2d'), dpr=devicePixelRatio||1, r=c.getBoundingClientRect();
        c.width=r.width*dpr; c.height=r.height*dpr; ctx.scale(dpr,dpr);
        const W=r.width, H=r.height;
        const visibleHosts = topologyVisibleHosts(topoData);
        const phase = nowTs / 1000;
        topoNodeRects = [];
        topoHitAreas = [];
        ctx.clearRect(0,0,W,H);
        ctx.save();
        ctx.translate(80 + topoPan.x, 36 + topoPan.y);
        ctx.scale(topoScale, topoScale);

        const laneGap = 28;
        const routeGap = 78;
        const lanePadding = 18;
        const hostHeights = visibleHosts.map(host => Math.max(96, (host.routes?.length || 1) * routeGap + lanePadding));
        const totalHeight = hostHeights.reduce((a, b) => a + b, 0) + Math.max(0, visibleHosts.length - 1) * laneGap;
        const lbX = 78;
        const lbY = totalHeight > 0 ? totalHeight / 2 : 120;
        const lbFlow = topoFlow(topoData.lb);
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
        topoNodeRects.push({ id: 'lb', kind: 'lb', x: lbX, y: lbY, r: lbPulse + 10, data: { title: 'Sentirum LB', subtitle: 'Ingress load balancer', flow: lbFlow } });

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
                const routeHover = topoHoverItem?.id === routeEdgeId;
                const routeLineWidth = 1.5 + clamp(Math.log10(1 + routeByteRate), 0, 3.6) + (routeHover ? 0.8 : 0);
                const routeStartX = lbX + lbPulse;
                const routeEndX = routeX - routeLabelWidth / 2 - 14;

                ctx.strokeStyle = topoStrokeGradient(ctx, routeStartX, lbY, routeEndX, routeY, routePalette);
                ctx.lineWidth = routeLineWidth;
                ctx.beginPath(); ctx.moveTo(routeStartX, lbY); ctx.lineTo(routeEndX, routeY); ctx.stroke();
                drawTopoArrowheads(ctx, routeStartX, lbY, routeEndX, routeY, routePalette.byte, topoActivityRank(routeFlow) + (routeHover ? 1 : 0));
                drawTopoFlowDots(ctx, routeStartX, lbY, routeEndX, routeY, routePalette.dot, routeFlow, phase, topoActivityRank(routeFlow) + (routeHover ? 1 : 0));
                drawTopoEdgeLabel(ctx, routeStartX, lbY, routeEndX, routeY, `${fmtRate(routeReqRate)} → ${fmtBps(routeByteRate)}`, routePalette.edge, routeHover || routeReqRate >= 10);
                topoHitAreas.push({
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
                    const selected = topologySelectedTargetKey === key;
                    const edgeId = `route-target|${key}`;
                    const hover = topoHoverItem?.id === edgeId || topoHoverItem?.key === key;
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
                    topoHitAreas.push({
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
                    topoNodeRects.push({
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
                    x: (clientX - rect.left - (80 + topoPan.x)) / topoScale,
                    y: (clientY - rect.top - (36 + topoPan.y)) / topoScale,
                };
            };
            const hoverAt = e => {
                const point = worldPoint(e);
                const hit = topoHitAt(point) || null;
                const prev = topoHoverItem?.id || topoHoverItem?.key || null;
                const next = hit?.id || hit?.key || null;
                topoHoverItem = hit;
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
            c.addEventListener('mousemove', e=>{if(drag){const dx=e.clientX-lx, dy=e.clientY-ly; if(Math.abs(dx)+Math.abs(dy)>2)moved=true; topoPan.x+=dx;topoPan.y+=dy;lx=e.clientX;ly=e.clientY;hideTopoTooltip();drawTopo();scheduleTopoFrame();} else { hoverAt(e); }});
            c.addEventListener('mouseup', e=>{drag=false; trySelect(e);});
            c.addEventListener('mouseleave', ()=>{drag=false;c.style.cursor='grab';hideTopoTooltip();drawTopo();});
            c.addEventListener('touchstart', e=>{const t=e.touches[0];drag=true;moved=false;lx=t.clientX;ly=t.clientY;hideTopoTooltip();}, { passive: true });
            c.addEventListener('touchmove', e=>{if(drag){e.preventDefault();const t=e.touches[0];const dx=t.clientX-lx, dy=t.clientY-ly; if(Math.abs(dx)+Math.abs(dy)>2)moved=true; topoPan.x+=dx;topoPan.y+=dy;lx=t.clientX;ly=t.clientY;drawTopo();scheduleTopoFrame();}}, { passive: false });
            c.addEventListener('touchend', ()=>{drag=false;hideTopoTooltip();}, { passive: true });
            c.addEventListener('click', e=>{if(!drag) trySelect(e);});
            c.addEventListener('wheel', e=>{e.preventDefault();topoScale=Math.max(0.5,Math.min(2.25,topoScale*(e.deltaY<0?1.08:0.92)));hideTopoTooltip();drawTopo();scheduleTopoFrame();}, { passive: false });
        }
        c.style.cursor = topoHoverItem?.selectKey ? 'pointer' : topoHoverItem ? 'crosshair' : 'grab';
    }
    function topoZoom(f){topoScale=Math.max(0.5,Math.min(2.25,topoScale*f));hideTopoTooltip();drawTopo();scheduleTopoFrame();}
    function topoReset(){topologySelectedTargetKey = null; topoScale=1;topoPan={x:0,y:0};hideTopoTooltip();renderTopologyPanels(topoData);drawTopo();scheduleTopoFrame();}

    // ===== DNS =====
    function filterDns() { dnsSearch = document.getElementById('dns-search').value || ''; renderDns(cachedDns || { stats:{}, entries:[] }); }
    function toggleDnsNegatives() {
        dnsNegativesOnly = !dnsNegativesOnly;
        document.getElementById('dns-negatives-btn').classList.toggle('on', dnsNegativesOnly);
        renderDns(cachedDns || { stats:{}, entries:[] });
    }
    function resetDnsFilters() {
        dnsSearch = ''; dnsNegativesOnly = false;
        document.getElementById('dns-search').value = '';
        document.getElementById('dns-negatives-btn').classList.remove('on');
        renderDns(cachedDns || { stats:{}, entries:[] });
    }
    function renderDns(d) {
        const entries = d.entries || [];
        const query = dnsSearch.trim().toLowerCase();
        const filtered = entries.filter(e => {
            if (dnsNegativesOnly && !e.is_negative) return false;
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

    // ===== CONSUL =====
    function renderConsul(c) {
        const watchers = ['services','kv','tls','client_ca'].map(w => {
            const d=c[w]||{}, errs=d.errors||0, backoff=d.backoff_secs||0;
            const state = errs > 10 ? 'degraded' : errs > 0 || backoff > 0 ? 'recovering' : 'healthy';
            return { name: w, data: d, errs, backoff, state };
        });
        const healthy = watchers.filter(w => w.state === 'healthy').length;
        const recovering = watchers.filter(w => w.state === 'recovering').length;
        const degraded = watchers.filter(w => w.state === 'degraded').length;
        const hottest = [...watchers].sort((a, b) => (b.errs + b.backoff) - (a.errs + a.backoff))[0];
        const watcherCards = watchers.map(({ name, data, errs, backoff, state })=>{
            const col=state==='degraded'?'var(--red)':state==='recovering'?'var(--yellow)':'var(--green)';
            const dot=state==='degraded'?'err':state==='recovering'?'warn':'ok';
            const hint = state === 'degraded' ? 'Check connectivity, ACL token, or long-poll failures.' : state === 'recovering' ? 'Watcher is backing off; verify recent Consul health.' : 'Watcher is healthy and advancing.';
            return `<div class="panel-item"><div class="panel-item-head"><div><div class="panel-item-title">${name.toUpperCase()} <span class="node-dot ${dot}"></span></div><div class="panel-item-sub">${hint}</div></div><span class="metric-chip">idx ${data.last_index||0}</span></div><div class="mini-kv" style="margin-top:0.55rem"><dt>State</dt><dd style="color:${col}">${state}</dd><dt>Backoff</dt><dd>${backoff}s</dd><dt>Errors</dt><dd>${errs}</dd></div></div>`;
        }).join('');
        document.getElementById('consul-grid').innerHTML=`
            <div class="summary-grid">
                <div class="summary-card"><div class="k">Healthy</div><div class="v">${healthy}</div></div>
                <div class="summary-card"><div class="k">Recovering</div><div class="v">${recovering}</div></div>
                <div class="summary-card"><div class="k">Degraded</div><div class="v">${degraded}</div></div>
                <div class="summary-card"><div class="k">Total watcher errors</div><div class="v">${watchers.reduce((n, w) => n + w.errs, 0)}</div></div>
                <div class="summary-card"><div class="k">Needs attention</div><div class="v">${esc(hottest?.name?.toUpperCase() || '—')}</div></div>
            </div>
            <div class="split-grid">
                <div class="panel"><div class="panel-head"><div><div class="panel-title">Watcher health matrix</div><div class="subtle">Backoff, errors and index advancement for each Consul integration path</div></div></div><div class="panel-body"><div class="panel-list">${watcherCards}</div></div></div>
                <div class="panel"><div class="panel-head"><div><div class="panel-title">Operational guide</div><div class="subtle">Quick interpretation hints for on-call use</div></div></div><div class="panel-body"><div class="help-list"><div class="help-item"><strong>Recovering watcher</strong> Backoff > 0 means recent failures; if index is still advancing, recovery is likely already in progress.</div><div class="help-item"><strong>Degraded watcher</strong> High cumulative errors without index movement usually indicates ACL, network, or blocking-query failures.</div><div class="help-item"><strong>TLS / Client CA</strong> If these watchers degrade while routes remain healthy, certificate rotation path may be the root cause rather than service discovery.</div></div></div></div>
            </div>`;
    }

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
        const runtime = new Map((allTargets || []).map(t => [routeRuntimeKey(t.host, t.path, t), t]));
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
                score: (openCount * 1000000000) + (halfOpenCount * 500000000) + (errorRatePct * 1000000) + avgLatencyUs + totalRequests + Math.round(topoByteRateStable(flow) / 1024) + (targets.length * 100),
            };
        });
    }
    const routeIsHot = route => topoFlowHot(route.flow) || route.heat >= 0.34 || route.activeConnections > 0;
    const routeHasRewrite = route => route.optionSummary.parts.some(part => part.startsWith('strip ') || part.startsWith('prepend ') || part.startsWith('host '));
    const routeHighThroughput = route => route.throughput >= 128 * 1024 || route.heat >= 0.58;
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
        const route = buildRouteModels(cachedRoutes || { routes: [] }).find(r => r.key === routeKey);
        if (!route) return;
        topologyMode = 'all';
        topologyHostFilter = route.host || '*';
        topologySelectedTargetKey = null;
        ['all','issues','hot'].forEach(name => document.getElementById(`topo-mode-${name}`)?.classList.toggle('on', name === 'all'));
        showPage('topology');
    }
    function syncRouteQuickFilters() {
        Object.entries(routeQuickFilters).forEach(([name, on]) => document.getElementById(`route-chip-${name}`)?.classList.toggle('on', on));
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
        if (routeHostFilter !== '__all__' && counts[routeHostFilter] == null) routeHostFilter = '__all__';
        const entries = Object.keys(counts).sort((a, b) => routeHostLabel(a).localeCompare(routeHostLabel(b)));
        document.getElementById('route-hosts').innerHTML = [
            `<button class="topo-host-btn ${routeHostFilter === '__all__' ? 'on' : ''}" data-action="set-route-host-filter" data-host="${attrEnc('__all__')}">All scopes <span style="color:var(--text-4)">(${baseRoutes.length})</span></button>`,
            ...entries.map(host => `<button class="topo-host-btn ${routeHostFilter === host ? 'on' : ''}" data-action="set-route-host-filter" data-host="${attrEnc(host)}">${esc(routeHostLabel(host))} <span style="color:var(--text-4)">(${counts[host]})</span></button>`)
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
        const routeHist = topoRouteHist[topologyRouteKey(route.host, route.path)] || { req: [], bytes: [], errPct: [], lat: [] };
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
    function filterRoutes() { routeSearch = document.getElementById('route-search').value || ''; renderRoutes(cachedRoutes || { routes: [] }); }
    function changeRouteSort() { routeSort = document.getElementById('route-sort').value || 'attention'; renderRoutes(cachedRoutes || { routes: [] }); }
    function changeRouteProtocol() { routeProtocol = document.getElementById('route-protocol').value || 'all'; renderRoutes(cachedRoutes || { routes: [] }); }
    function toggleRouteIssues() {
        routeIssuesOnly = !routeIssuesOnly;
        document.getElementById('route-issues-btn').classList.toggle('on', routeIssuesOnly);
        renderRoutes(cachedRoutes || { routes: [] });
    }
    function toggleRouteHot() {
        routeHotOnly = !routeHotOnly;
        document.getElementById('route-hot-btn').classList.toggle('on', routeHotOnly);
        renderRoutes(cachedRoutes || { routes: [] });
    }
    function toggleRouteQuickFilter(name) {
        routeQuickFilters[name] = !routeQuickFilters[name];
        syncRouteQuickFilters();
        renderRoutes(cachedRoutes || { routes: [] });
    }
    function setRouteHostFilter(host) { routeHostFilter = host; renderRoutes(cachedRoutes || { routes: [] }); }
    function selectRoute(key) { selectedRouteKey = key; renderRoutes(cachedRoutes || { routes: [] }); }
    function resetRouteFilters() {
        routeSearch = '';
        routeSort = 'attention';
        routeProtocol = 'all';
        routeIssuesOnly = false;
        routeHotOnly = false;
        routeQuickFilters = { open: false, rewrite: false, multi: false, throughput: false };
        routeHostFilter = '__all__';
        document.getElementById('route-search').value = '';
        document.getElementById('route-sort').value = 'attention';
        document.getElementById('route-protocol').value = 'all';
        document.getElementById('route-issues-btn').classList.remove('on');
        document.getElementById('route-hot-btn').classList.remove('on');
        syncRouteQuickFilters();
        renderRoutes(cachedRoutes || { routes: [] });
    }
    function renderRoutes(data) {
        cachedRoutes = data;
        const models = buildRouteModels(data);
        const query = routeSearch.trim().toLowerCase();
        const baseRoutes = models.filter(route => {
            const matchesIssues = !routeIssuesOnly || route.openCount > 0 || route.halfOpenCount > 0 || route.errorRatePct > 0;
            const matchesProtocol = routeProtocol === 'all' || route.protocolGroups.includes(routeProtocol);
            const matchesHot = !routeHotOnly || routeIsHot(route);
            const matchesQuick = (!routeQuickFilters.open || route.openCount > 0)
                && (!routeQuickFilters.rewrite || routeHasRewrite(route))
                && (!routeQuickFilters.multi || route.multiTarget)
                && (!routeQuickFilters.throughput || routeHighThroughput(route));
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
        const filtered = baseRoutes.filter(route => routeHostFilter === '__all__' || route.host === routeHostFilter);
        filtered.sort((a, b) => {
            switch (routeSort) {
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
        const quickOn = Object.entries(routeQuickFilters).filter(([, on]) => on).map(([name]) => name).join(', ');
        document.getElementById('routes-meta').textContent = `${filtered.length} shown · ${models.length} total${routeHotOnly ? ' · hot only' : ''}${routeIssuesOnly ? ' · issues only' : ''}${quickOn ? ` · ${quickOn}` : ''}`;
        if (!filtered.some(route => route.key === selectedRouteKey)) selectedRouteKey = filtered[0]?.key || null;
        if (!filtered.length) {
            document.getElementById('routes-list').innerHTML = '<div class="empty">No routes match the current filter</div>';
            renderRouteInspector(null);
            return;
        }
        const listHtml = filtered.map(route => {
            const tone = routeToneClass(route);
            const routeHist = topoRouteHist[topologyRouteKey(route.host, route.path)] || { req: [], bytes: [], errPct: [], lat: [] };
            const previewTargets = route.targets.slice(0, 3).map(target => {
                const targetTone = routeTargetToneClass(target);
                return `<div class="route-target ${targetTone}">
                    <div class="route-target-head"><span class="cell-main">${esc(target.service || 'unknown')}</span><span class="metric-chip">${fmtPct((target.weight || 0) * 100)}</span></div>
                    <div class="route-target-url">${esc(target.url || '—')}</div>
                    <div class="route-target-meta"><span class="tag ${target.protocol === 'tcp' ? 'tag-tcp' : target.http2 ? 'tag-grpc' : ''}">${esc(target.protocol || 'http')}</span>${target.tls ? '<span class="tag tag-tls">TLS</span>' : ''}${target.http2 ? '<span class="tag tag-grpc">H2</span>' : ''}${(target.circuit_breaker && target.circuit_breaker !== 'closed') ? `<span class="cb cb-${esc(target.circuit_breaker)}">${esc(target.circuit_breaker)}</span>` : ''}</div>
                </div>`;
            }).join('');
            const moreCount = Math.max(0, route.targets.length - 3);
            return `<div class="route-card ${tone}${route.key === selectedRouteKey ? ' active' : ''}" data-action="select-route" data-key="${attrEnc(route.key)}">
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
        renderRouteInspector(filtered.find(route => route.key === selectedRouteKey) || filtered[0]);
    }

    // ===== OVERVIEW =====
    function renderOverview() {
        const routes = buildRouteModels(cachedRoutes || { routes: [] });
        const targets = allTargets || [];
        const logs = cachedLogs || [];
        const dnsEntries = cachedDns?.entries || [];
        const certs = cachedCerts?.certificates || [];
        const clientAuth = cachedCerts?.client_auth || {};
        const watchers = ['services','kv','tls','client_ca'].map(name => {
            const data = cachedConsul?.[name] || {};
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
            currentMetricSnapshot ? `${currentMetricSnapshot.rps.toFixed(1)} req/s live traffic` : 'Live metrics warming up',
            `${routes.length} routes across ${new Set(routes.map(r => r.host)).size} host scopes`,
            `${activeTargets.length}/${targets.length || 0} targets are currently active`
        ];
        if (cachedConfig?.proxy?.strategy) subtitleBits.push(`strategy ${cachedConfig.proxy.strategy}`);
        if (cachedConfig?.proxy?.matcher) subtitleBits.push(`matcher ${cachedConfig.proxy.matcher}`);
        document.getElementById('overview-title').textContent = title;
        document.getElementById('overview-subtitle').textContent = subtitleBits.join(' · ');

        // Build rich summary chips
        const tlsListeners = cachedConfig?.tls_listeners || [];
        const totalTlsListeners = (cachedConfig?.tls?.listen ? 1 : 0) + tlsListeners.length;
        const mtlsListeners = tlsListeners.filter(l => l.client_auth === 'required' || l.client_auth === 'optional').length;
        const hcEnabled = cachedConfig?.proxy?.health_check_interval && cachedConfig.proxy.health_check_interval !== '0s';
        const rlEnabled = cachedConfig?.proxy?.rate_limit_per_target > 0;
        const cbEnabled = cachedConfig?.proxy?.circuit_breaker_enabled;
        const protoBits = [];
        if (cachedConfig?.proxy?.enable_h2c) protoBits.push('h2c');
        if (cachedConfig?.tls?.listen) protoBits.push('https');
        if (mtlsListeners > 0) protoBits.push('mtls');
        const totalLogs = logs.length;
        const healthChecks = cachedCerts ? undefined : 0; // TODO: from metrics

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
                value: currentMetricSnapshot ? `${currentMetricSnapshot.rps.toFixed(1)}` : '0.0',
                sub: `${overviewHistory.rps.length} samples`,
                data: overviewHistory.rps.slice(-20),
                color: 'var(--accent)'
            },
            {
                key: 'Error trend',
                value: currentMetricSnapshot ? currentMetricSnapshot.errRateText : '0%',
                sub: `${errorLogs} recent error log(s)`,
                data: overviewHistory.err.slice(-20),
                color: 'var(--red)'
            },
            {
                key: 'Connections',
                value: `${currentMetricSnapshot?.active_connections || 0}`,
                sub: `${activeTargets.length} active target(s)`,
                data: overviewHistory.conn.slice(-20),
                color: 'var(--green)'
            },
            {
                key: 'Latency trend',
                value: currentMetricSnapshot?.targets?.length ? fmtLat(Math.round(overviewHistory.lat[overviewHistory.lat.length - 1] || 0)) : '0µs',
                sub: `${slowestTarget ? `slowest ${esc(slowestTarget.service || 'target')}` : 'No latency outlier'}`,
                data: overviewHistory.lat.slice(-20),
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
                    <div class="overview-mini-card actionable" data-action="focus-config-field" data-path="${attrEnc('proxy.health_check_interval')}"><div class="k">Health checks</div><div class="v">${hcEnabled ? 'active' : 'off'}</div><div class="s">${hcEnabled ? cachedConfig.proxy.health_check_interval + ' interval' : 'click to configure'}</div></div>
                    <div class="overview-mini-card actionable" data-action="focus-config-field" data-path="${attrEnc('proxy.rate_limit_per_target')}"><div class="k">Rate limiting</div><div class="v">${rlEnabled ? cachedConfig.proxy.rate_limit_per_target + '/s' : 'off'}</div><div class="s">${rlEnabled ? 'burst ' + cachedConfig.proxy.rate_limit_burst : 'click to configure'}</div></div>
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
            cachedCerts?.last_reload_unix ? {
                title: 'TLS runtime reload',
                sub: `Last certificate reload ${fmtDate(cachedCerts.last_reload_unix * 1000)}`,
                meta: expiringCerts.length ? `${expiringCerts.length} cert(s) expiring <30d` : 'No immediate expiry pressure',
                chips: ['tls']
            } : null,
            clientAuth?.last_reload_unix ? {
                title: 'Client CA reload',
                sub: `Client CA refreshed ${fmtDate(clientAuth.last_reload_unix * 1000)}`,
                meta: `${(clientAuth.certificates || []).length} CA certificate(s) loaded`,
                chips: ['mTLS']
            } : null,
            cachedConfig ? {
                title: 'Runtime posture',
                sub: `strategy ${cachedConfig.proxy?.strategy || 'unknown'} · matcher ${cachedConfig.proxy?.matcher || 'unknown'} · no-route ${cachedConfig.proxy?.no_route_status || 'n/a'}`,
                meta: `request-id ${cachedConfig.proxy?.request_id_header || 'disabled'}`,
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

    // ===== LOGS =====
    function renderLogRow(l) {
        const c=(l.level||'INFO')[0] || 'I';
        const hl=logSearch && logHaystack(l).includes(logSearch);
        const copyText = `${l.level || 'INFO'} ${l.target || ''} ${l.message || ''}`.trim();
        return `<div class="log-row${hl?' hl':''}"><span class="log-ts">${logTs(l.ts)}</span><span class="log-lvl ${c}">${esc(logLevelShort(l.level))}</span><div class="log-body"><div class="log-msg">${esc(l.message)}</div><div class="log-target" title="${esc(l.target||'')}">${esc(l.target||'')}</div></div><div class="log-actions"><button class="btn btn-sm" data-action="focus-log-target" data-target="${attrEnc(l.target || '')}">Module</button><button class="btn btn-sm" data-action="copy-log" data-text="${attrEnc(copyText)}">Copy</button></div></div>`;
    }
    function renderLogsSummary(entries) {
        const counts = { ERROR: 0, WARN: 0, INFO: 0, DEBUG: 0, TRACE: 0 };
        entries.forEach(l => { counts[l.level] = (counts[l.level] || 0) + 1; });
        const latest = entries[0];
        const topTarget = Object.entries(entries.reduce((acc, l) => { const key = l.target || 'unknown'; acc[key] = (acc[key] || 0) + 1; return acc; }, {})).sort((a, b) => b[1] - a[1])[0];
        document.getElementById('logs-summary').innerHTML = `
            <div class="log-summary-card"><div class="k">Errors</div><div class="v" style="color:var(--red)">${counts.ERROR || 0}</div></div>
            <div class="log-summary-card"><div class="k">Warnings</div><div class="v" style="color:var(--yellow)">${counts.WARN || 0}</div></div>
            <div class="log-summary-card"><div class="k">Info</div><div class="v" style="color:var(--green)">${counts.INFO || 0}</div></div>
            <div class="log-summary-card"><div class="k">Top module</div><div class="v" style="font-size:0.82rem">${esc(topTarget?.[0] || '—')}</div></div>
            <div class="log-summary-card"><div class="k">Latest event</div><div class="v" style="font-size:0.82rem">${esc(latest?.level || '—')}</div><div class="subtle">${latest ? fmtRel(latest.ts) : 'No entries'}</div></div>
        `;
    }
    function syncLogStreamControls() {
        const streamBtn = document.getElementById('stream-btn');
        const pauseBtn = document.getElementById('stream-pause-btn');
        if (streamBtn) {
            const reconnecting = !!logStreamDesired && !logSse;
            streamBtn.classList.toggle('on', !!logStreamDesired);
            streamBtn.classList.toggle('warn', reconnecting);
            streamBtn.textContent = !logStreamDesired ? 'Stream: OFF' : (logSse ? 'Stream: ON' : 'Stream: RETRY');
        }
        if (pauseBtn) {
            pauseBtn.disabled = !logSse;
            pauseBtn.classList.toggle('warn', logStreamPaused);
            pauseBtn.textContent = logStreamPaused ? `Resume (${pendingStreamEntries})` : 'Pause';
        }
    }
    function updateLogsMeta(visibleCount) {
        const total = cachedLogs.length;
        const bits = [`${visibleCount} shown`, `${total} buffered`];
        if (pendingStreamEntries > 0) bits.push(`${pendingStreamEntries} queued`);
        if (logStreamDesired && !logSse) bits.push('reconnecting');
        document.getElementById('logs-meta').textContent = bits.join(' · ');
        syncLogStreamControls();
    }
    function renderLogs() {
        const allFiltered=filterCached();
        const f=allFiltered.slice(0,500);
        document.getElementById('logs-box').innerHTML=f.length ? f.map(renderLogRow).join('') : '<div class="log-empty">No log entries match the current filters</div>';
        renderLogsSummary(allFiltered);
        updateLogsMeta(f.length);
    }
    function filterCached(){return cachedLogs.filter(logMatches);}
    function filterLogs(){logSearch=(document.getElementById('log-search').value||'').toLowerCase();renderLogs();}
    function focusLogTarget(target) { document.getElementById('log-search').value = target || ''; logSearch = (target || '').toLowerCase(); renderLogs(); }
    async function copyLog(text) { try { await navigator.clipboard.writeText(text || ''); } catch(_) {} }
    function setLogPreset(preset) {
        logPreset = preset;
        ['all','app','infra'].forEach(name => document.getElementById(`log-preset-${name}`).classList.toggle('on', name === preset));
        renderLogs();
    }
    function toggleLevel(b){const l=b.dataset.level;if(activeLevels.has(l)){activeLevels.delete(l);b.classList.remove('on');}else{activeLevels.add(l);b.classList.add('on');}renderLogs();}
    function exportFilteredLogs(){dl(filterCached(),'sentirum-logs-filtered.json');}
    function clearLogs(){cachedLogs=[];pendingStreamEntries=0;renderLogs();}
    function toggleStreamPause(){if(!logSse)return;logStreamPaused=!logStreamPaused;if(!logStreamPaused) pendingStreamEntries=0;renderLogs();}
    function clearLogStreamReconnect() {
        if (logStreamReconnectTimer) {
            clearTimeout(logStreamReconnectTimer);
            logStreamReconnectTimer = null;
        }
    }
    function scheduleLogStreamReconnect() {
        if (!logStreamDesired || logSse || logStreamReconnectTimer) return;
        const delay = logStreamReconnectDelay;
        logStreamReconnectTimer = setTimeout(() => {
            logStreamReconnectTimer = null;
            openLogStream();
        }, delay);
        logStreamReconnectDelay = Math.min(logStreamReconnectDelay * 2, LOG_STREAM_RECONNECT_MAX_MS);
        updateLogsMeta(filterCached().slice(0,500).length);
    }
    function stopLogStream() {
        logStreamDesired = false;
        clearLogStreamReconnect();
        if (logSse) {
            logSse.close();
            logSse = null;
        }
        logStreamPaused = false;
        pendingStreamEntries = 0;
        updateLogsMeta(filterCached().slice(0,500).length);
    }
    function openLogStream() {
        if (!token || !logStreamDesired || logSse) return;
        try {
            logSse = new EventSource(API+'/logs/stream?token='+encodeURIComponent(token));
        } catch (_) {
            logSse = null;
            scheduleLogStreamReconnect();
            return;
        }
        syncLogStreamControls();
        logSse.onopen = () => {
            logStreamReconnectDelay = LOG_STREAM_RECONNECT_MIN_MS;
            updateLogsMeta(filterCached().slice(0,500).length);
        };
        logSse.onmessage=e=>{try{
            const l=JSON.parse(e.data);
            cachedLogs.unshift(l);
            if(cachedLogs.length>2000)cachedLogs.length=2000;
            if(logStreamPaused){ pendingStreamEntries++; updateLogsMeta(filterCached().slice(0,500).length); return; }
            if(logMatches(l)){
                const c=document.getElementById('logs-box');
                if(c.querySelector('.log-empty')) c.innerHTML='';
                const d=document.createElement('div');
                d.innerHTML=renderLogRow(l);
                c.insertAdjacentElement('afterbegin', d.firstChild);
                if(c.children.length>500)c.removeChild(c.lastChild);
            }
            updateLogsMeta(filterCached().slice(0,500).length);
        }catch(e){}};
        logSse.onerror=()=>{
            if (logSse) {
                logSse.close();
                logSse = null;
            }
            if (!logStreamDesired) {
                updateLogsMeta(filterCached().slice(0,500).length);
                return;
            }
            scheduleLogStreamReconnect();
        };
    }
    function toggleStream(){
        if(logStreamDesired) stopLogStream();
        else{
            logStreamDesired=true;
            logStreamReconnectDelay=LOG_STREAM_RECONNECT_MIN_MS;
            clearLogStreamReconnect();
            openLogStream();
            updateLogsMeta(filterCached().slice(0,500).length);
        }
    }

    // ===== CONFIG =====
    function cloneJson(v) { return JSON.parse(JSON.stringify(v || {})); }
    function getPath(obj, path) { return path.split('.').reduce((acc, key) => acc == null ? undefined : acc[key], obj); }
    function setPath(obj, path, value) {
        const parts = path.split('.');
        let cur = obj;
        for (let i = 0; i < parts.length - 1; i++) {
            const key = parts[i];
            if (!cur[key] || typeof cur[key] !== 'object') cur[key] = {};
            cur = cur[key];
        }
        cur[parts[parts.length - 1]] = value;
    }
    function configFieldId(path) { return `config-field-${path.replace(/[^a-z0-9]+/gi, '-')}`; }
    function configSectionId(title) { return `config-section-${String(title || '').replace(/[^a-z0-9]+/gi, '-').toLowerCase()}`; }
    async function copyToClipboard(text, label = 'Copied') {
        try {
            await navigator.clipboard.writeText(String(text ?? ''));
            showToast('ok', label);
        } catch (_) {
            showToast('err', 'Clipboard copy failed');
        }
    }
    function copyFromData(button, label = 'Copied') {
        return copyToClipboard(attrDec(button?.dataset?.copy ?? ''), label);
    }
    function showToast(tone, text) {
        const root = document.getElementById('toast-root');
        if (!root || !text) return;
        const item = document.createElement('div');
        item.className = `toast${tone ? ` ${tone}` : ''}`;
        item.textContent = text;
        root.appendChild(item);
        setTimeout(() => item.remove(), 2800);
    }
    function findConfigField(path) {
        for (const section of CONFIG_EDITOR_FIELDS) {
            const field = section.fields.find(f => f.path === path);
            if (field) return field;
        }
        return null;
    }
    function buildConfigDraft(cfg) {
        const draft = {};
        CONFIG_EDITOR_FIELDS.forEach(section => section.fields.forEach(field => {
            setPath(draft, field.path, getPath(cfg || {}, field.path));
        }));
        return draft;
    }
    function configDraftIsDirty() {
        if (!configDraft || !cachedConfig) return false;
        return CONFIG_EDITOR_FIELDS.some(section => section.fields.some(field => JSON.stringify(getPath(configDraft, field.path)) !== JSON.stringify(getPath(cachedConfig, field.path))));
    }
    function validateConfigField(field, value) {
        if (field.type === 'select') {
            return field.options.includes(String(value)) ? '' : `Allowed values: ${field.options.join(', ')}`;
        }
        if (field.type === 'boolean') {
            return typeof value === 'boolean' ? '' : 'Value must be true or false';
        }
        if (field.type === 'number') {
            if (value == null || value === '' || Number.isNaN(value)) return 'Numeric value is required';
            if (!Number.isFinite(Number(value))) return 'Numeric value is required';
            if (field.min != null && Number(value) < field.min) return `Minimum is ${field.min}`;
            if (field.max != null && Number(value) > field.max) return `Maximum is ${field.max}`;
            return '';
        }
        const text = String(value ?? '').trim();
        if (!field.allowEmpty && !text) return 'This field cannot be empty';
        if ((field.path.includes('timeout') || field.path.includes('interval')) && text && !DURATION_RE.test(text)) return 'Use a duration like 250ms, 5s, 1m or 1h';
        return '';
    }
    function collectConfigValidationErrors() {
        const errors = {};
        if (!configDraft) return errors;
        CONFIG_EDITOR_FIELDS.forEach(section => section.fields.forEach(field => {
            const error = validateConfigField(field, getPath(configDraft, field.path));
            if (error) errors[field.path] = error;
        }));
        return errors;
    }
    function listChangedConfigFields() {
        if (!configDraft || !cachedConfig) return [];
        const changes = [];
        CONFIG_EDITOR_FIELDS.forEach(section => section.fields.forEach(field => {
            const before = getPath(cachedConfig, field.path);
            const after = getPath(configDraft, field.path);
            if (JSON.stringify(before) === JSON.stringify(after)) return;
            changes.push({ path: field.path, label: field.label, before, after, section: section.title });
        }));
        return changes;
    }
    function listRuntimeVsStartupConfigFields() {
        if (!cachedConfig || !cachedConfigStartup) return [];
        const changes = [];
        CONFIG_EDITOR_FIELDS.forEach(section => section.fields.forEach(field => {
            const runtime = getPath(cachedConfig, field.path);
            const startup = getPath(cachedConfigStartup, field.path);
            if (JSON.stringify(runtime) === JSON.stringify(startup)) return;
            changes.push({ path: field.path, label: field.label, before: startup, after: runtime, section: section.title });
        }));
        return changes;
    }
    function focusConfigField(path) {
        configFocusPath = path;
        const field = findConfigField(path);
        if (field) {
            for (const section of CONFIG_EDITOR_FIELDS) {
                if (section.fields.some(f => f.path === path)) configCollapsedSections[configSectionId(section.title)] = false;
            }
        }
        navTo('config');
        setTimeout(() => {
            renderConfig(cachedConfig || {});
            const root = document.getElementById(configFieldId(path));
            if (!root) return;
            root.scrollIntoView({ behavior: 'smooth', block: 'center' });
            const input = root.querySelector('input, select');
            if (input) input.focus();
        }, 30);
    }
    function setConfigStatus(tone, text, notify = true) {
        configStatus = { tone: tone || '', text: text || '' };
        if (text && tone && notify) showToast(tone, text);
        const el = document.getElementById('config-status');
        if (!el) return;
        el.className = `config-status${tone ? ` ${tone}` : ''}`;
        el.textContent = text || '';
    }
    function toggleConfigSectionCollapse(sectionId) {
        configCollapsedSections[sectionId] = !configCollapsedSections[sectionId];
        renderConfig(cachedConfig || {});
    }
    function renderConfigSummary(cfg) {
        const root = document.getElementById('config-summary');
        if (!root) return;
        const draftChanges = listChangedConfigFields();
        const runtimeChanges = listRuntimeVsStartupConfigFields();
        const validationErrors = Object.keys(collectConfigValidationErrors()).length;
        const editableCount = CONFIG_EDITOR_FIELDS.reduce((n, section) => n + section.fields.length, 0);
        root.innerHTML = `
            <div class="summary-card"><div class="k">Editable fields</div><div class="v">${editableCount}</div><div class="subtle">Runtime-safe controls only</div></div>
            <div class="summary-card"><div class="k">Draft changes</div><div class="v">${draftChanges.length}</div><div class="subtle">Pending before apply</div></div>
            <div class="summary-card"><div class="k">Runtime drift</div><div class="v">${runtimeChanges.length}</div><div class="subtle">Fields differing from startup</div></div>
            <div class="summary-card"><div class="k">Validation issues</div><div class="v">${validationErrors}</div><div class="subtle">Must be zero to apply</div></div>`;
    }
    function renderConfigDiffDrawer() {
        const drawer = document.getElementById('config-diff-drawer');
        if (!drawer) return;
        const draftChanges = listChangedConfigFields();
        const runtimeChanges = listRuntimeVsStartupConfigFields();
        if (!draftChanges.length && !runtimeChanges.length) {
            drawer.innerHTML = '';
            return;
        }
        const renderItems = (items, actionLabel) => items.length ? `<div class="config-diff-list">${items.map(item => `
            <div class="config-diff-item">
                <div class="t">${esc(item.label)} <span style="color:var(--text-4);font-weight:500">· ${esc(item.section)}</span></div>
                <div class="s mono">${esc(item.path)}</div>
                <div class="s">${esc(String(item.before))} → ${esc(String(item.after))}</div>
                ${actionLabel ? `<div class="route-inline-meta" style="margin-top:0.45rem"><button class="config-mini-btn" data-action="focus-config-field" data-path="${attrEnc(item.path)}">${actionLabel}</button></div>` : ''}
            </div>`).join('')}</div>` : '<div class="empty">No differences</div>';
        drawer.innerHTML = `
            <div class="config-diff-drawer">
                <div class="panel-head"><div><div class="panel-title">Config diff drawer</div><div class="subtle">Draft deltas and live runtime drift versus startup snapshot</div></div></div>
                <div class="panel-body config-diff-grid">
                    <div>
                        <div class="panel-title" style="margin-bottom:0.6rem">Draft changes</div>
                        ${renderItems(draftChanges, 'Focus field')}
                    </div>
                    <div>
                        <div class="panel-title" style="margin-bottom:0.6rem">Runtime vs startup</div>
                        ${renderItems(runtimeChanges, 'Inspect')}
                    </div>
                </div>
            </div>`;
    }
    function renderConfigEditor(cfg) {
        if (!cfg || typeof cfg !== 'object') {
            document.getElementById('config-editor').innerHTML = '<div class="empty">No runtime configuration available</div>';
            return;
        }
        if (!configDraft) configDraft = buildConfigDraft(cfg);
        const dirty = configDraftIsDirty();
        const errors = collectConfigValidationErrors();
        const hasErrors = Object.keys(errors).length > 0;
        document.getElementById('config-apply-btn').disabled = !dirty || hasErrors;
        const query = configSearch.trim().toLowerCase();
        const html = `<div class="config-editor-grid">${CONFIG_EDITOR_FIELDS.map(section => {
            const sectionId = configSectionId(section.title);
            const matchCount = section.fields.filter(field => {
                const current = getPath(cfg, field.path);
                const startup = getPath(cachedConfigStartup || {}, field.path);
                return !query || `${section.title} ${field.label} ${field.path} ${current ?? ''} ${startup ?? ''}`.toLowerCase().includes(query);
            }).length;
            const forceOpenForQuery = !!query && matchCount > 0;
            const collapsed = !forceOpenForQuery && !!configCollapsedSections[sectionId] && !(configFocusPath && section.fields.some(field => field.path === configFocusPath));
            return `
            <div id="${sectionId}" class="config-section${matchCount && query ? ' match' : ''}${collapsed ? ' collapsed' : ''}">
                <div class="config-section-head"><div><div class="config-section-title">${esc(section.title)}</div><div class="config-section-sub">${esc(section.subtitle)}${query ? ` · ${matchCount} match` : ''}</div></div><button class="config-collapse-btn" data-action="toggle-config-section" data-section="${attrEnc(sectionId)}">${collapsed ? 'Expand' : 'Collapse'}</button></div>
                <div class="config-form">${section.fields.map(field => {
                    const value = getPath(configDraft, field.path);
                    const current = getPath(cfg, field.path);
                    const startup = getPath(cachedConfigStartup || {}, field.path);
                    const changed = JSON.stringify(value) !== JSON.stringify(current);
                    const startupChanged = cachedConfigStartup && JSON.stringify(current) !== JSON.stringify(startup);
                    const error = errors[field.path] || '';
                    const fieldClass = `config-field${changed ? ' changed' : ''}${error ? ' invalid' : ''}${configFocusPath === field.path ? ' focused' : ''}`;
                    let input = '';
                    if (field.type === 'select') {
                        input = `<select class="config-select js-config-input" data-path="${attrEnc(field.path)}" data-type="select">${field.options.map(opt => `<option value="${esc(opt)}" ${String(value)===String(opt)?'selected':''}>${esc(opt)}</option>`).join('')}</select>`;
                    } else if (field.type === 'boolean') {
                        input = `<select class="config-select js-config-input" data-path="${attrEnc(field.path)}" data-type="boolean"><option value="true" ${value===true?'selected':''}>true</option><option value="false" ${value===false?'selected':''}>false</option></select>`;
                    } else {
                        input = `<input class="config-input js-config-input" data-path="${attrEnc(field.path)}" data-type="${esc(field.type)}" type="${field.type === 'number' ? 'number' : 'text'}" value="${esc(value ?? '')}" ${field.min != null ? `min="${field.min}"` : ''} ${field.max != null ? `max="${field.max}"` : ''} />`;
                    }
                    const notes = [field.hint || ''];
                    if (startup !== undefined) notes.push(`startup: ${String(startup)}`);
                    if (changed) notes.push('draft modified');
                    if (startupChanged) notes.push('runtime differs from startup');
                    if (error) notes.push(error);
                    return `<div id="${configFieldId(field.path)}" class="${fieldClass}"><div class="config-field-head"><label>${esc(field.label)}</label><div class="config-field-tools"><button class="config-mini-btn" data-action="copy-data" data-copy="${attrEnc(String(current ?? ''))}" data-label="${attrEnc('Current value copied')}">Copy current</button>${startup !== undefined ? `<button class="config-mini-btn" data-action="copy-data" data-copy="${attrEnc(String(startup ?? ''))}" data-label="${attrEnc('Startup value copied')}">Copy startup</button>` : ''}</div></div>${input}<small>${notes.map((note, idx) => idx === notes.length - 1 && error ? `<span class="config-note-error">${esc(note)}</span>` : esc(note)).join(' · ')}</small></div>`;
                }).join('')}</div>
            </div>`;
        }).join('')}</div>`;
        document.getElementById('config-editor').innerHTML = html;
        renderConfigSummary(cfg);
        renderConfigDiffDrawer();
        setConfigStatus(configStatus.tone, configStatus.text || (hasErrors ? 'Fix validation errors before applying runtime changes.' : dirty ? 'Draft has unapplied runtime changes.' : 'Only runtime-safe fields are editable here.'), false);
    }
    function updateConfigDraft(path, type, raw) {
        if (!configDraft) configDraft = buildConfigDraft(cachedConfig || {});
        let value = raw;
        if (type === 'number') value = raw === '' ? null : Number(raw);
        if (type === 'boolean') value = raw === 'true';
        setPath(configDraft, path, value);
        configFocusPath = path;
        renderConfig(cachedConfig || {});
    }
    function revertConfigDraft() {
        configDraft = buildConfigDraft(cachedConfig || {});
        setConfigStatus('warn', 'Draft reverted to the current live runtime config.');
        renderConfig(cachedConfig || {});
    }
    async function applyRuntimeConfig() {
        if (!cachedConfig || !configDraft || !configDraftIsDirty()) return;
        const errors = collectConfigValidationErrors();
        if (Object.keys(errors).length > 0) {
            setConfigStatus('err', 'Fix validation errors before applying runtime changes.');
            renderConfig(cachedConfig || {});
            return;
        }
        const changes = listChangedConfigFields();
        const preview = changes.slice(0, 8).map(change => `• ${change.label}: ${String(change.before)} → ${String(change.after)}`).join('\n');
        const more = changes.length > 8 ? `\n… +${changes.length - 8} more field(s)` : '';
        if (!confirm(`Apply ${changes.length} runtime config change(s)?\n\n${preview}${more}`)) {
            setConfigStatus('warn', 'Apply cancelled.');
            return;
        }
        setConfigStatus('', 'Applying runtime configuration…');
        try {
            const response = await fetch(API + '/config', {
                method: 'PUT',
                headers: { ...hdrs(), 'Content-Type': 'application/json' },
                body: JSON.stringify(configDraft)
            });
            const data = await response.json();
            if (!data.success) {
                setConfigStatus('err', data.error || 'Runtime config update failed.');
                return;
            }
            configDraft = null;
            setConfigStatus('ok', data.message || 'Runtime configuration updated.');
            await refreshStatic();
        } catch (_) {
            setConfigStatus('err', 'Runtime config update failed.');
        }
    }
    async function resetRuntimeConfigToStartup() {
        if (!confirm('Reset all live runtime-editable settings back to the startup snapshot?')) return;
        setConfigStatus('', 'Resetting runtime configuration to startup snapshot…');
        try {
            const response = await fetch(API + '/config/reset', { method: 'POST', headers: hdrs() });
            const data = await response.json();
            if (data.success === false) {
                setConfigStatus('err', data.error || 'Reset failed.');
                return;
            }
            configDraft = null;
            setConfigStatus('ok', data.message || 'Runtime configuration reset to startup snapshot.');
            await refreshStatic();
        } catch (_) {
            setConfigStatus('err', 'Reset failed.');
        }
    }
    window.addEventListener('beforeunload', e => {
        if (!configDraftIsDirty()) return;
        e.preventDefault();
        e.returnValue = '';
    });
    document.addEventListener('keydown', e => {
        const applyCombo = (e.ctrlKey || e.metaKey) && e.key === 'Enter';
        if (applyCombo && document.getElementById('page-config')?.classList.contains('active')) {
            if (!document.getElementById('config-apply-btn')?.disabled) {
                e.preventDefault();
                applyRuntimeConfig();
            }
        }
        if (e.key === 'Escape' && document.getElementById('page-config')?.classList.contains('active') && configFocusPath) {
            configFocusPath = '';
            renderConfig(cachedConfig || {});
        }
    });
    function filterConfig() { configSearch = document.getElementById('config-search').value || ''; renderConfig(cachedConfig || {}); }
    function toggleConfigDiffs() {
        configDiffOnly = !configDiffOnly;
        document.getElementById('config-diff-btn').classList.toggle('on', configDiffOnly);
        renderConfig(cachedConfig || {});
    }
    function resetConfigFilters() {
        configSearch = ''; configDiffOnly = false;
        document.getElementById('config-search').value = '';
        document.getElementById('config-diff-btn').classList.remove('on');
        renderConfig(cachedConfig || {});
    }
    function renderConfig(cfg) {
        renderConfigEditor(cfg);
        if(!cfg||typeof cfg!=='object'){document.getElementById('config-meta').textContent='0 entries';document.getElementById('config-list').innerHTML='<div class="empty">No config loaded</div>';return;}
        const sens=['admin_token','token','password'];
        const baseline = cachedConfigStartup || {};
        const rows=[];
        (function walk(o,pfx){Object.keys(o).sort().forEach(k=>{
            if (k === 'meta') return;
            const fk=pfx?pfx+'.'+k:k, v=o[k];
            const isSens=sens.some(s=>k.toLowerCase().includes(s));
            if(Array.isArray(v)){
                if(!v.length){ rows.push({ fk, value: '[]', isSens, isDiff: JSON.stringify(v)!==JSON.stringify(getPath(baseline, fk)) }); return; }
                if(v.every(x=>x==null || typeof x!=='object')){ rows.push({ fk, value: JSON.stringify(v), isSens, isDiff: JSON.stringify(v)!==JSON.stringify(getPath(baseline, fk)) }); return; }
                v.forEach((item, idx) => walk(item, `${fk}[${idx}]`));
                return;
            }
            if(v&&typeof v==='object'){walk(v,fk);return;}
            const value = typeof v==='boolean'?(v?'true':'false'):String(v);
            rows.push({ fk, value, isSens, isDiff: JSON.stringify(v)!==JSON.stringify(getPath(baseline, fk)) });
        });})(cfg,'');
        const query = configSearch.trim().toLowerCase();
        const visible = rows.filter(row => {
            if (configDiffOnly && !row.isDiff) return false;
            if (!query) return true;
            return `${row.fk} ${row.value}`.toLowerCase().includes(query);
        });
        let h='<div class="config-pre">';
        visible.forEach(row => {
            const cls=row.isSens?'mask':row.isDiff?'diff':'';
            const disp=row.isSens?'••••••••':row.value;
            h+=`<span class="ck">${esc(row.fk)}</span>: <span class="cv ${cls}">${esc(disp)}</span>\n`;
        });
        h+='</div>';
        document.getElementById('config-meta').textContent = `${visible.length} shown · ${rows.length} entries`;
        document.getElementById('config-list').innerHTML=visible.length ? h : '<div class="empty">No config entries match the current filter</div>';
    }

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
        if (certRisk === 'all') return true;
        if (certRisk === 'critical') return tone === 'err';
        if (certRisk === 'warning') return tone === 'warn';
        if (certRisk === 'healthy') return tone === 'ok';
        return true;
    }
    function certExpiryWidth(days) {
        if (days == null) return 15;
        if (days < 0) return 100;
        return Math.max(8, Math.min(100, Math.round((days / 90) * 100)));
    }
    function selectCert(entryName) { selectedCertEntry = entryName || null; renderCerts(cachedCerts || { certificates: [] }); }
    function filterCerts() { certSearch = document.getElementById('cert-search').value || ''; renderCerts(cachedCerts || { certificates: [] }); }
    function changeCertRisk() { certRisk = document.getElementById('cert-risk').value || 'all'; renderCerts(cachedCerts || { certificates: [] }); }
    function toggleCertDefaultOnly() {
        certDefaultOnly = !certDefaultOnly;
        document.getElementById('cert-default-btn').classList.toggle('on', certDefaultOnly);
        renderCerts(cachedCerts || { certificates: [] });
    }
    function toggleCertClientCaOnly() {
        certClientCaOnly = !certClientCaOnly;
        document.getElementById('cert-client-ca-btn').classList.toggle('on', certClientCaOnly);
        renderCerts(cachedCerts || { certificates: [] });
    }
    function resetCertFilters() {
        certSearch = ''; certRisk = 'all'; certDefaultOnly = false; certClientCaOnly = false;
        document.getElementById('cert-search').value = '';
        document.getElementById('cert-risk').value = 'all';
        document.getElementById('cert-default-btn').classList.remove('on');
        document.getElementById('cert-client-ca-btn').classList.remove('on');
        renderCerts(cachedCerts || { certificates: [] });
    }
    function renderCerts(d) {
        cachedCerts = d;
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
        const query = certSearch.trim().toLowerCase();
        const caList = (clientAuth.certificates || []).filter(ca => !query || `${ca.common_name || ''} ${ca.subject || ''} ${ca.entry_name || ''}`.toLowerCase().includes(query));
        const filtered = certClientCaOnly ? [] : certs.filter(cert => {
            if (certDefaultOnly && d?.default_certificate !== cert.entry_name) return false;
            if (!certMatchesRisk(cert)) return false;
            if (!query) return true;
            return `${cert.primary_name || ''} ${cert.entry_name || ''} ${d?.source || ''}`.toLowerCase().includes(query);
        }).sort((a, b) => {
            const ad = a.days_remaining == null ? Number.MAX_SAFE_INTEGER : a.days_remaining;
            const bd = b.days_remaining == null ? Number.MAX_SAFE_INTEGER : b.days_remaining;
            return ad - bd;
        });
        const critical = certs.filter(cert => (cert.days_remaining ?? 999999) < 7).length;
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
        document.getElementById('certs-meta').textContent = `${certClientCaOnly ? caList.length : filtered.length} shown · ${certClientCaOnly ? (clientAuth.certificates || []).length : certs.length} total`;
        if (!filtered.some(cert => cert.entry_name === selectedCertEntry)) selectedCertEntry = filtered[0]?.entry_name || null;
        const groups = certClientCaOnly ? [] : [
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
            return `<div class="cert-card ${tone}${selectedCertEntry === cert.entry_name ? ' active' : ''}" data-action="select-cert" data-entry="${attrEnc(cert.entry_name)}">
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
        if (certClientCaOnly) {
            listHtml = '<div class="empty">Client CA only filter is enabled. Review the inspector panel for CA details.</div>';
        } else if (!filtered.length) {
            listHtml = d?.source === 'disabled' && !fileListeners.length ? '<div class="empty">TLS is disabled. Enable a TLS source to inspect runtime certificates here.</div>' : '<div class="empty">No certificates match the current filters</div>';
        } else {
            listHtml = groups.map(group => `<div class="cert-group"><div class="cert-group-title">${group.title}</div><div class="cert-list">${group.items.map(renderCertCard).join('')}</div></div>`).join('');
        }
        document.getElementById('certs-list').innerHTML = listHtml;
        const selected = filtered.find(cert => cert.entry_name === selectedCertEntry) || (certClientCaOnly ? null : defaultCert || filtered[0] || certs[0] || null);
        const lastError = d?.last_error || clientAuth?.last_error || '';
        document.getElementById('certs-inspector').innerHTML = `
            <div class="panel-head"><div><div class="panel-title">Certificate inspector</div><div class="subtle">Operational detail for TLS and client CA runtime state</div></div></div>
            <div class="panel-body cert-inspector-grid">
                ${selected ? `<div class="topo-focus-card"><div class="cert-card-title">${esc(selected.primary_name || selected.entry_name || 'Unknown')}</div><div class="route-inline-meta" style="margin-top:0.45rem"><span class="tag ${certTone(selected)==='err'?'tag-tcp':certTone(selected)==='warn'?'tag-grpc':certTone(selected)==='ok'?'tag-tls':'tag'}">${certToneLabel(certTone(selected))}</span>${d?.default_certificate===selected.entry_name?'<span class="tag tag-tls">default</span>':''}<span class="metric-chip">${esc(d?.source || 'runtime')}</span></div><div class="cert-tools" style="margin-top:0.55rem"><button class="config-mini-btn" data-action="copy-data" data-copy="${attrEnc(selected.entry_name || '')}" data-label="${attrEnc('Certificate entry copied')}">Copy entry</button><button class="config-mini-btn" data-action="copy-data" data-copy="${attrEnc(selected.primary_name || '')}" data-label="${attrEnc('Primary name copied')}">Copy name</button></div><dl class="cert-kv" style="margin-top:0.75rem"><dt>Entry</dt><dd class="mono">${esc(selected.entry_name || '—')}</dd><dt>Primary name</dt><dd>${esc(selected.primary_name || '—')}</dd><dt>Expires</dt><dd>${esc(fmtExpiry(selected.not_after_unix))}</dd><dt>Days remaining</dt><dd>${certRelativeText(selected.days_remaining)}</dd><dt>Default cert</dt><dd>${d?.default_certificate===selected.entry_name ? 'Yes' : 'No'}</dd></dl></div>` : '<div class="empty">No certificate selected</div>'}
                <div class="panel-item"><div class="panel-item-head"><div class="panel-item-title">Runtime state</div><span class="metric-chip">index ${d?.last_consul_index || 0}</span></div><div class="cert-runtime-list" style="margin-top:0.7rem"><div class="overview-row"><div class="overview-row-main"><div class="overview-row-title">TLS runtime</div><div class="overview-row-sub">last reload ${d?.last_reload_unix ? fmtDate(d.last_reload_unix * 1000) : 'never'}</div></div><div class="overview-row-side"><span class="metric-chip">${fmt(certs.length)} loaded</span></div></div><div class="overview-row"><div class="overview-row-main"><div class="overview-row-title">Client CA runtime</div><div class="overview-row-sub">last reload ${clientAuth?.last_reload_unix ? fmtDate(clientAuth.last_reload_unix * 1000) : 'never'}</div></div><div class="overview-row-side"><span class="metric-chip">${fmt((clientAuth.certificates || []).length)} CA certs</span></div></div>${lastError ? `<div class="help-item"><strong>Last error</strong>${esc(lastError)}</div>` : '<div class="help-item"><strong>Last error</strong>No runtime TLS / client CA error recorded</div>'}</div></div>
                <div class="panel-item"><div class="panel-item-head"><div class="panel-item-title">Client CA certificates</div><span class="metric-chip">${esc(clientAuth.mode || 'off')}</span></div><div class="cert-runtime-list" style="margin-top:0.7rem">${caList.length ? caList.map(ca => `<div class="cert-ca-item"><div class="cert-card-title">${esc(ca.common_name || ca.subject || ca.entry_name || 'unknown')}</div><div class="cert-card-sub">${esc(ca.entry_name || '?')}</div><div class="cert-tools" style="margin-top:0.45rem"><button class="config-mini-btn" data-action="copy-data" data-copy="${attrEnc(ca.subject || '')}" data-label="${attrEnc('CA subject copied')}">Copy subject</button><button class="config-mini-btn" data-action="copy-data" data-copy="${attrEnc(ca.common_name || '')}" data-label="${attrEnc('CA common name copied')}">Copy CN</button></div><dl class="cert-kv" style="margin-top:0.55rem"><dt>Subject</dt><dd>${esc(ca.subject || '—')}</dd><dt>Organization</dt><dd>${esc(ca.organization || '—')}</dd><dt>Org unit</dt><dd>${esc(ca.organizational_unit || '—')}</dd></dl></div>`).join('') : `<div class="empty">${clientAuth.mode && clientAuth.mode !== 'off' ? 'No client CA certificates loaded' : 'Client authentication is off'}</div>`}</div></div>
                <div class="panel-item"><div class="panel-item-head"><div class="panel-item-title">Operator hints</div><span class="metric-chip">certs</span></div><div class="help-list" style="margin-top:0.7rem"><div class="help-item"><strong>Critical expiry</strong> Anything under 7 days should be treated as a rotation incident candidate.</div><div class="help-item"><strong>Default certificate</strong> Verify the default entry first if clients hit unexpected SNI fallbacks.</div><div class="help-item"><strong>Client CA mode</strong> If mTLS is required but no CA certs are loaded, handshake failures will look like client-side TLS errors.</div></div></div>
            </div>`;
    }

    // ===== EXPORT =====
    function exportRoutes(){dl(cachedRoutes||{},'sentirum-routes.json');}
    function exportConfig(){const data=cloneJson(cachedConfig||{});if(data&&typeof data==='object') delete data.meta;dl(data,'sentirum-config.json');}
    function exportCerts(){dl(cachedCerts||{},'sentirum-certs.json');}
    function dl(d,f){const b=new Blob([JSON.stringify(d,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=f;a.click();}

    // ===== INIT =====
    renderTargetDetailEmpty();
    syncTargetQuickFilters();
    syncRouteQuickFilters();
    if(token&&username){
        fetch(API+'/me',{headers:hdrs()}).then(r=>r.json()).then(d=>{if(d.authenticated)showApp();else{localStorage.removeItem('admin_token');localStorage.removeItem('admin_user');}}).catch(()=>{localStorage.removeItem('admin_token');localStorage.removeItem('admin_user');});
    }
    document.getElementById('password-input').addEventListener('keypress',e=>{if(e.key==='Enter')doLogin();});
