// ===== EVENTS =====
// Centralized event delegation — single listener per event type.
// O(1) action dispatch via lookup map instead of switch/case.

const clickHandlers = {
    login: () => doLogin(),
    'toggle-sidebar': () => toggleSidebar(),
    'close-sidebar': () => closeSidebar(),
    'nav-to': el => navTo(el.dataset.page || 'overview'),
    logout: () => doLogout(),
    'topology-zoom': el => topoZoom(Number(el.dataset.factor || 1)),
    'topology-reset': () => topoReset(),
    'set-topology-mode': el => setTopologyMode(el.dataset.mode || 'all'),
    'toggle-topology-heat-mode': () => toggleTopologyHeatMode(),
    'reset-topology-focus': () => resetTopologyFocus(),
    'toggle-target-issues': () => toggleTargetIssues(),
    'toggle-target-hot': () => toggleTargetHot(),
    'reset-target-filters': () => resetTargetFilters(),
    'toggle-target-quick-filter': el => toggleTargetQuickFilter(el.dataset.filter || ''),
    'export-filtered-logs': () => exportFilteredLogs(),
    'toggle-log-level': el => toggleLevel(el),
    'set-log-preset': el => setLogPreset(el.dataset.preset || 'all'),
    'toggle-log-stream': () => toggleStream(),
    'toggle-log-stream-pause': () => toggleStreamPause(),
    'clear-logs': () => clearLogs(),
    'export-routes': () => exportRoutes(),
    'toggle-route-issues': () => toggleRouteIssues(),
    'toggle-route-hot': () => toggleRouteHot(),
    'reset-route-filters': () => resetRouteFilters(),
    'toggle-route-quick-filter': el => toggleRouteQuickFilter(el.dataset.filter || ''),
    'toggle-dns-negatives': () => toggleDnsNegatives(),
    'reset-dns-filters': () => resetDnsFilters(),
    'export-certs': () => exportCerts(),
    'toggle-cert-default-only': () => toggleCertDefaultOnly(),
    'toggle-cert-client-ca-only': () => toggleCertClientCaOnly(),
    'reset-cert-filters': () => resetCertFilters(),
    'export-config': () => exportConfig(),
    'apply-runtime-config': () => applyRuntimeConfig(),
    'revert-config-draft': () => revertConfigDraft(),
    'reset-runtime-config-to-startup': () => resetRuntimeConfigToStartup(),
    'toggle-config-diffs': () => toggleConfigDiffs(),
    'reset-config-filters': () => resetConfigFilters(),
    'toggle-target-detail': el => toggleDetail(Number(el.dataset.index || -1)),
    'focus-target-topology': el => focusTargetInTopology(Number(el.dataset.index || -1)),
    'close-target-detail': () => closeTargetDetail(),
    'set-topology-host-filter': el => setTopologyHostFilter(attrDec(el.dataset.host)),
    'select-topology-target': el => selectTopologyTarget(attrDec(el.dataset.key)),
    'set-route-host-filter': el => setRouteHostFilter(attrDec(el.dataset.host)),
    'focus-route-topology': el => focusRouteInTopology(attrDec(el.dataset.key)),
    'select-route': el => selectRoute(attrDec(el.dataset.key)),
    'focus-log-target': el => focusLogTarget(attrDec(el.dataset.target)),
    'copy-log': el => copyLog(attrDec(el.dataset.text)),
    'copy-data': (el) => copyFromData(el, attrDec(el.dataset.label) || 'Copied'),
    'focus-config-field': el => focusConfigField(attrDec(el.dataset.path)),
    'toggle-config-section': el => toggleConfigSectionCollapse(attrDec(el.dataset.section)),
    'select-cert': el => selectCert(attrDec(el.dataset.entry)),
};

const inputHandlers = {
    'target-search': () => filterTargets(),
    'log-search': () => filterLogs(),
    'route-search': () => filterRoutes(),
    'dns-search': () => filterDns(),
    'cert-search': () => filterCerts(),
    'config-search': () => filterConfig(),
};

const changeHandlers = {
    'target-sort': () => changeTargetSort(),
    'route-sort': () => changeRouteSort(),
    'route-protocol': () => changeRouteProtocol(),
    'cert-risk': () => changeCertRisk(),
};

document.addEventListener('click', e => {
    const el = e.target.closest('[data-action]');
    if (!el) return;
    const action = el.dataset.action;
    const handler = clickHandlers[action];
    if (!handler) return;
    e.preventDefault();
    handler(el);
});

document.addEventListener('input', e => {
    if (e.target.matches('.js-config-input:not(select)')) {
        updateConfigDraft(attrDec(e.target.dataset.path), e.target.dataset.type || 'text', e.target.value);
        return;
    }
    const handler = inputHandlers[e.target.id];
    if (handler) handler();
});

document.addEventListener('change', e => {
    if (e.target.matches('.js-config-input')) {
        updateConfigDraft(attrDec(e.target.dataset.path), e.target.dataset.type || 'text', e.target.value);
        return;
    }
    const handler = changeHandlers[e.target.id];
    if (handler) handler();
});
