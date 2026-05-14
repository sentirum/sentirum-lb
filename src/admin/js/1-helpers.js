// ===== HELPERS =====
// Pure functions, formatters, constants, API wrapper, topology math.
// No DOM mutations, no state mutations — only reads state via closures.

const esc = s => s == null ? '' : String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const attrEnc = value => encodeURIComponent(value == null ? '' : String(value));
const attrDec = value => { try { return decodeURIComponent(value || ''); } catch (_) { return value || ''; } };
const tsToMs = ts => !ts ? 0 : (ts > 1e12 ? ts : ts * MS_PER_SEC);
const fmt = n => n >= 1e9 ? (n/1e9).toFixed(1)+'B' : n >= 1e6 ? (n/1e6).toFixed(1)+'M' : n >= 1e3 ? (n/1e3).toFixed(1)+'K' : String(n);
const fmtLat = us => us < US_PER_MS ? us+'µs' : us < US_PER_S ? (us/US_PER_MS).toFixed(1)+'ms' : (us/US_PER_S).toFixed(2)+'s';
const fmtPct = n => { const v = Number(n || 0); return v >= 10 ? v.toFixed(0)+'%' : v >= 1 ? v.toFixed(1)+'%' : v > 0 ? v.toFixed(2)+'%' : '0%'; };
const fmtTime = ms => new Date(ms).toISOString().slice(11,19);
const fmtDate = ms => new Date(ms).toISOString().slice(0,19).replace('T',' ');
const fmtRel = ms => { const d=Date.now()-ms; if(d<MS_PER_MIN)return Math.floor(d/MS_PER_SEC)+'s ago'; if(d<MS_PER_HOUR)return Math.floor(d/MS_PER_MIN)+'m ago'; if(d<MS_PER_DAY)return Math.floor(d/MS_PER_HOUR)+'h ago'; return Math.floor(d/MS_PER_DAY)+'d ago'; };
const fmtExpiry = unix => unix ? fmtDate(unix * MS_PER_SEC) : 'Unknown';
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
    if (v >= BYTES_PER_GB) return (v / BYTES_PER_GB).toFixed(1) + ' GB/s';
    if (v >= BYTES_PER_MB) return (v / BYTES_PER_MB).toFixed(1) + ' MB/s';
    if (v >= BYTES_PER_KB) return (v / BYTES_PER_KB).toFixed(1) + ' KB/s';
    return Math.round(v) + ' B/s';
};
const fmtAgoMs = ms => ms == null ? '—' : ms < MS_PER_SEC ? ms + 'ms ago' : ms < MS_PER_MIN ? (ms / MS_PER_SEC).toFixed(ms < 10_000 ? 1 : 0) + 's ago' : ms < MS_PER_HOUR ? Math.floor(ms / MS_PER_MIN) + 'm ago' : Math.floor(ms / MS_PER_HOUR) + 'h ago';
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
const topoResolvePalette = (cb, flow, selected = false) => (S.topologyHeatMode && cb === 'closed') ? topoHeatPalette(flow, selected) : topoPalette(cb, flow, selected);
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
const targetIsHot = t => topoFlowHot(topoFlow(t)) || targetHeat(t) >= TARGET_HEAT_THRESHOLD || (t.active_connections || 0) > 0;
const TARGET_LATENCY_HIGH_US = 250_000;
const TARGET_THROUGHPUT_HIGH_BPS = 128 * BYTES_PER_KB;
const TARGET_HEAT_THRESHOLD = 0.34;
const TARGET_HEAT_HIGH = 0.58;
const targetIsHighLatency = t => (t.stats?.avg_latency_us || 0) >= TARGET_LATENCY_HIGH_US;
const targetIsHighThroughput = t => targetThroughput(t) >= TARGET_THROUGHPUT_HIGH_BPS || targetHeat(t) >= TARGET_HEAT_HIGH;
const targetHealthClass = t => t.circuit_breaker === 'open' ? 'danger' : t.circuit_breaker === 'halfopen' || !t.probe_healthy || (t.stats?.error_rate_pct || 0) > 0 ? 'warn' : 'ok';
const targetHealthLabel = t => t.circuit_breaker === 'open' ? 'CB open' : t.circuit_breaker === 'halfopen' ? 'Half-open' : !t.probe_healthy ? 'Probe down' : 'Healthy';
const targetRiskScore = t => ((t.stats?.error_rate_pct || 0) * RISK_ERROR_MULT) + (t.circuit_breaker === 'open' ? RISK_CB_OPEN : t.circuit_breaker === 'halfopen' ? RISK_CB_HALF_OPEN : 0) + (t.stats?.avg_latency_us || 0) + ((t.active_connections || 0) * 100) + Math.round(targetThroughput(t) / BYTES_PER_KB);
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
    if (S.logPreset === 'app') return target.startsWith('sentirum_lb');
    if (S.logPreset === 'infra') return !target.startsWith('sentirum_lb');
    return true;
};
const logMatches = l => S.activeLevels.has(l.level) && logMatchesPreset(l) && (!S.logSearch || logHaystack(l).includes(S.logSearch));
const logLevelShort = l => ({ERROR:'ERR', WARN:'WRN', INFO:'INF', DEBUG:'DBG', TRACE:'TRC'}[l] || l || 'LOG');
const scheduleStaticRefresh = (delay = STATIC_REFRESH_MS) => {
    if (S.staticRefreshTimer) clearTimeout(S.staticRefreshTimer);
    S.staticRefreshTimer = setTimeout(refreshStatic, delay);
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
const hdrs = () => ({'Authorization':'Bearer '+S.token});
async function api(p) { const r = await fetch(API+p,{headers:hdrs()}); if(r.status===401){localStorage.removeItem('admin_token');location.reload();throw new Error('401');} return r.json(); }
