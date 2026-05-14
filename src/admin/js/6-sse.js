// ===== SSE METRICS =====
function startMetrics() {
    if(S.metricsSse) S.metricsSse.close();
    S.metricsSse = new EventSource(API+'/metrics/stream?token='+encodeURIComponent(S.token));
    S.metricsSse.onmessage = e => {
        if (e.data === 'connected') { setErr(false); return; }
        try { const s = JSON.parse(e.data); processSnap(s); setErr(false); } catch(err){}
    };
    S.metricsSse.onerror = () => setErr(true);
}
function pruneTargetCaches(activeTargets, nowMs = Date.now()) {
    const activeKeys = new Set((activeTargets || []).map(targetKey));
    Object.keys(S.targetHist).forEach(key => {
        const last = S.targetHist[key]?.ts?.[S.targetHist[key].ts.length - 1];
        if (!activeKeys.has(key) && (!last || nowMs - tsToMs(last) > TARGET_HISTORY_TTL_MS)) delete S.targetHist[key];
    });
    Object.keys(S.prevTargets).forEach(key => {
        const last = S.prevTargets[key]?.ts;
        if (!activeKeys.has(key) && (!last || nowMs - tsToMs(last) > TARGET_HISTORY_TTL_MS)) delete S.prevTargets[key];
    });
}
function processSnap(s) {
    if (!s.targets && !s.requests_total && s.requests_total !== 0) return;
    const dt = S.prevSnap ? Math.max(s.timestamp - S.prevSnap.timestamp, 1) : 1;
    const rps = S.prevSnap ? ((s.requests_total - S.prevSnap.requests_total) / dt).toFixed(1) : '0';
    const errRate = s.requests_total > 0 ? ((s.requests_error_total / s.requests_total) * 100).toFixed(1) + '%' : '0%';
    const errPct = s.requests_total > 0 ? s.requests_error_total / s.requests_total : 0;
    S.currentMetricSnapshot = { ...s, rps: Number(rps), errRateText: errRate, errPct };
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
        if (!S.targetHist[key]) S.targetHist[key] = { req: [], err: [], errPct: [], lat: [], bytesRate: [], ts: [], rate: 0 };
        const h = S.targetHist[key];
        const prevReq = h.req.length > 0 ? h.req[h.req.length - 1] : 0;
        h.req.push(t.requests);
        h.err.push(t.errors);
        h.errPct.push(t.requests > 0 ? (t.errors / t.requests) * 100 : 0);
        h.lat.push(t.avg_latency_us || 0);
        h.bytesRate.push(Number(t.flow?.bps_5s || t.flow?.bps_1s || 0));
        h.ts.push(s.timestamp);
        if (h.req.length > HIST) { h.req.shift(); h.err.shift(); h.errPct.shift(); h.lat.shift(); h.bytesRate.shift(); h.ts.shift(); }
        h.rate = S.prevSnap ? (t.requests - prevReq) / dt : 0;
        const prev = S.prevTargets[key];
        S.prevTargets[key] = {
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
    S.overviewHistory.rps.push(Number(rps));
    S.overviewHistory.err.push(errPct * 100);
    S.overviewHistory.conn.push(s.active_connections || 0);
    S.overviewHistory.lat.push(overviewAvgLatency);
    S.overviewHistory.ts.push(s.timestamp);
    if (S.overviewHistory.rps.length > HIST) {
        S.overviewHistory.rps.shift(); S.overviewHistory.err.shift(); S.overviewHistory.conn.shift(); S.overviewHistory.lat.shift(); S.overviewHistory.ts.shift();
    }
    if (s.targets) pruneTargetCaches(s.targets, tsToMs(s.timestamp) || Date.now());
    if (s.targets && s.targets.length > 0 && S.allTargets.length > 0) {
        const byKey = new Map(s.targets.map(t => [targetKey(t), t]));
        S.allTargets = S.allTargets.map(t => {
            const live = byKey.get(targetKey(t));
            if (!live) return t;
            const requests = live.requests ?? t.stats?.requests ?? 0;
            const errors = live.errors ?? t.stats?.errors ?? 0;
            return {
                ...t,
                protocol: live.protocol || t.protocol,
                circuit_breaker: live.circuit_breaker || t.circuit_breaker,
                active_connections: live.active_connections ?? t.active_connections,
                flow: live.flow || t.flow,
                stats: {
                    ...(t.stats || {}),
                    requests,
                    errors,
                    avg_latency_us: live.avg_latency_us ?? t.stats?.avg_latency_us ?? 0,
                    error_rate_pct: requests > 0 ? Math.round((errors / requests) * 100) : 0,
                    bytes_total: live.bytes_total ?? t.stats?.bytes_total ?? 0,
                },
            };
        });
    }
    S.prevSnap = s;
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
        const d = S.prevTargets[key]; if (!d) return;
        const rpsCell = row.cells[5]; if (rpsCell) {
            const h = S.targetHist[key], rate = h ? h.rate : 0;
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
    if (latUs > LAT_RED_US) cls = 'var(--red)';
    else if (latUs > LAT_YELLOW_US) cls = 'var(--yellow)';
    else if (latUs > LAT_DIM_US) cls = 'var(--text-2)';
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
        if (!S.targetHist[key]) S.targetHist[key] = { req: [], err: [], errPct: [], lat: [], bytesRate: [], ts: [], rate: 0 };
        const h = S.targetHist[key];
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

