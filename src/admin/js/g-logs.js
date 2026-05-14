// ===== LOGS =====
function renderLogRow(l) {
    const c=(l.level||'INFO')[0] || 'I';
    const hl=S.logSearch && logHaystack(l).includes(S.logSearch);
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
        const reconnecting = !!S.logStreamDesired && !S.logSse;
        streamBtn.classList.toggle('on', !!S.logStreamDesired);
        streamBtn.classList.toggle('warn', reconnecting);
        streamBtn.textContent = !S.logStreamDesired ? 'Stream: OFF' : (S.logSse ? 'Stream: ON' : 'Stream: RETRY');
    }
    if (pauseBtn) {
        pauseBtn.disabled = !S.logSse;
        pauseBtn.classList.toggle('warn', S.logStreamPaused);
        pauseBtn.textContent = S.logStreamPaused ? `Resume (${S.pendingStreamEntries})` : 'Pause';
    }
}
function updateLogsMeta(visibleCount) {
    const total = S.cachedLogs.length;
    const bits = [`${visibleCount} shown`, `${total} buffered`];
    if (S.pendingStreamEntries > 0) bits.push(`${S.pendingStreamEntries} queued`);
    if (S.logStreamDesired && !S.logSse) bits.push('reconnecting');
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
function filterCached(){return S.cachedLogs.filter(logMatches);}
function filterLogs(){S.logSearch=(document.getElementById('log-search').value||'').toLowerCase();renderLogs();}
function focusLogTarget(target) { document.getElementById('log-search').value = target || ''; S.logSearch = (target || '').toLowerCase(); renderLogs(); }
async function copyLog(text) { try { await navigator.clipboard.writeText(text || ''); } catch(_) {} }
function setLogPreset(preset) {
    S.logPreset = preset;
    ['all','app','infra'].forEach(name => document.getElementById(`log-preset-${name}`).classList.toggle('on', name === preset));
    renderLogs();
}
function toggleLevel(b){const l=b.dataset.level;if(S.activeLevels.has(l)){S.activeLevels.delete(l);b.classList.remove('on');}else{S.activeLevels.add(l);b.classList.add('on');}renderLogs();}
function exportFilteredLogs(){dl(filterCached(),'sentirum-logs-filtered.json');}
function clearLogs(){S.cachedLogs=[];S.pendingStreamEntries=0;renderLogs();}
function toggleStreamPause(){if(!S.logSse)return;S.logStreamPaused=!S.logStreamPaused;if(!S.logStreamPaused) S.pendingStreamEntries=0;renderLogs();}
function clearLogStreamReconnect() {
    if (S.logStreamReconnectTimer) {
        clearTimeout(S.logStreamReconnectTimer);
        S.logStreamReconnectTimer = null;
    }
}
function scheduleLogStreamReconnect() {
    if (!S.logStreamDesired || S.logSse || S.logStreamReconnectTimer) return;
    const delay = S.logStreamReconnectDelay;
    S.logStreamReconnectTimer = setTimeout(() => {
        S.logStreamReconnectTimer = null;
        openLogStream();
    }, delay);
    S.logStreamReconnectDelay = Math.min(S.logStreamReconnectDelay * 2, LOG_STREAM_RECONNECT_MAX_MS);
    updateLogsMeta(filterCached().slice(0,500).length);
}
function stopLogStream() {
    S.logStreamDesired = false;
    clearLogStreamReconnect();
    if (S.logSse) {
        S.logSse.close();
        S.logSse = null;
    }
    S.logStreamPaused = false;
    S.pendingStreamEntries = 0;
    updateLogsMeta(filterCached().slice(0,500).length);
}
function openLogStream() {
    if (!S.token || !S.logStreamDesired || S.logSse) return;
    try {
        S.logSse = new EventSource(API+'/logs/stream?token='+encodeURIComponent(S.token));
    } catch (_) {
        S.logSse = null;
        scheduleLogStreamReconnect();
        return;
    }
    syncLogStreamControls();
    S.logSse.onopen = () => {
        S.logStreamReconnectDelay = LOG_STREAM_RECONNECT_MIN_MS;
        updateLogsMeta(filterCached().slice(0,500).length);
    };
    S.logSse.onmessage=e=>{try{
        const l=JSON.parse(e.data);
        S.cachedLogs.unshift(l);
        if(S.cachedLogs.length>LOG_BATCH_SIZE)S.cachedLogs.length=LOG_BATCH_SIZE;
        if(S.logStreamPaused){ S.pendingStreamEntries++; updateLogsMeta(filterCached().slice(0,500).length); return; }
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
    S.logSse.onerror=()=>{
        if (S.logSse) {
            S.logSse.close();
            S.logSse = null;
        }
        if (!S.logStreamDesired) {
            updateLogsMeta(filterCached().slice(0,500).length);
            return;
        }
        scheduleLogStreamReconnect();
    };
}
function toggleStream(){
    if(S.logStreamDesired) stopLogStream();
    else{
        S.logStreamDesired=true;
        S.logStreamReconnectDelay=LOG_STREAM_RECONNECT_MIN_MS;
        clearLogStreamReconnect();
        openLogStream();
        updateLogsMeta(filterCached().slice(0,500).length);
    }
}

