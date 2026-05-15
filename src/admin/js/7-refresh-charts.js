// ===== STATIC REFRESH =====
async function refreshStatic() {
    if(!S.token) return;
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
    S.cachedLogs=logs||[];
    S.cachedConfig=config;
    S.cachedConfigStartup=config?.meta?.startup || null;
    S.cachedConfigRuntime=config?.meta?.runtime || null;
    if (!S.configDraft || !configDraftIsDirty()) S.configDraft = buildConfigDraft(config);
    S.cachedCerts=certs;
    S.cachedRoutes=routes;
    S.cachedConsul=consul;
    S.cachedDns=dns;
    S.allTargets = targets.targets || [];
    updateTargetHistoriesFromStaticTargets(S.allTargets);
    renderTargets(getVisibleTargets(), true);
    renderDns(S.cachedDns); renderConsul(S.cachedConsul); renderRoutes(routes); renderOverview();
    renderLogs(); renderCerts(certs); renderConfig(config);
    refreshMetrics();
    if(config?.proxy?.strategy) document.getElementById('status-strategy').textContent = config.proxy.strategy;
    if(config?.proxy?.matcher) document.getElementById('status-matcher').textContent = config.proxy.matcher;
    if(health?.version) document.getElementById('status-version').textContent = `${health.service || 'sentirum-lb'} v${health.version}`;
    try { S.topoData=await api('/topology'); updateTopologyHistories(S.topoData); renderTopologyPanels(S.topoData); if(document.getElementById('page-topology').classList.contains('active')) { drawTopo(); scheduleTopoFrame(); } } catch(e){}
    scheduleStaticRefresh(STATIC_REFRESH_MS);
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
        if (S.charts.latency) {
            S.charts.latency.data.labels = ['<1ms','<5ms','<10ms','<25ms','<50ms','<100ms','<250ms','<500ms','<1s','<5s','>5s'];
            // Compute deltas between buckets for bar chart
            const bKeys = ['0.001','0.005','0.01','0.025','0.05','0.1','0.25','0.5','1','5','+Inf'];
            const bVals = bKeys.map(k => buckets[k] || 0);
            // Convert cumulative to per-bucket deltas
            const deltas = bVals.map((v, i) => i === 0 ? v : v - bVals[i - 1]);
            S.charts.latency.data.datasets[0].data = deltas;
            S.charts.latency.update('none');
        }
        // Status code doughnut
        if (S.charts.status) {
            S.charts.status.data.datasets[0].data = [
                statusCodes['2xx'] || 0,
                statusCodes['3xx'] || 0,
                statusCodes['4xx'] || 0,
                statusCodes['5xx'] || 0
            ];
            S.charts.status.update('none');
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
    S.charts.latency=new Chart(document.getElementById('lat-chart'),{type:'bar',data:{labels:[],datasets:[{data:[],backgroundColor:'#818cf8',borderRadius:3,barPercentage:0.8}]},options:base});
    S.charts.status=new Chart(document.getElementById('status-chart'),{type:'doughnut',data:{labels:['2xx','3xx','4xx','5xx'],datasets:[{data:[0,0,0,0],backgroundColor:['#34d399','#fbbf24','#f97316','#f87171'],borderWidth:0}]},options:{responsive:true,maintainAspectRatio:true,cutout:'65%',plugins:{legend:{position:'bottom',labels:{color:'#71717a',padding:10,font:{size:11}}}}}});
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

