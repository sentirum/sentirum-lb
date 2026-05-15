// ===== NAVIGATION =====
function showPage(p) {
    document.querySelectorAll('.nav-item').forEach(a=>a.classList.remove('active'));
    document.querySelector(`[data-page="${p}"]`).classList.add('active');
    document.querySelectorAll('.page').forEach(e=>e.classList.remove('active'));
    document.getElementById('page-'+p).classList.add('active');
    if (p !== 'topology') { stopTopoAnimation(); hideTopoTooltip(); }
    if(p==='overview') renderOverview();
    if(p==='topology') { renderTopologyPanels(S.topoData); drawTopo(); scheduleTopoFrame(); }
    if(p==='targets') renderTargets(getVisibleTargets(), false);
    if(p==='logs') renderLogs();
    if(p==='routes') renderRoutes(S.cachedRoutes || { routes: [] });
    if(p==='consul') renderConsul(S.cachedConsul || {});
    if(p==='dns') renderDns(S.cachedDns || { stats:{}, entries:[] });
    if(p==='certs') renderCerts(S.cachedCerts || { certificates: [] });
    if(p==='config') renderConfig(S.cachedConfig || {});
}
function navTo(p) { showPage(p); closeSidebar(); }
document.addEventListener('keydown', e => { if (e.key === 'Escape' && S.sidebarOpen) closeSidebar(); });

