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

