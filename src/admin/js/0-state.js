// ===== STATE =====
// Single source of truth — domain-grouped, const object (properties mutated in place).
// No wrappers, no namespace — concat merges into single scope.

const API = '/admin';

// Named constants — no magic numbers scattered in modules.
const HIST = 60;
const TARGET_HISTORY_TTL_MS = 10 * 60 * 1000;
const LOG_STREAM_RECONNECT_MIN_MS = 1_000;
const LOG_STREAM_RECONNECT_MAX_MS = 15_000;
const STATIC_REFRESH_MS = 10_000;
const LOG_BATCH_SIZE = 2_000;
const CERT_EXPIRY_WARN_DAYS = 30;
const CERT_EXPIRY_CRIT_DAYS = 7;
const CERT_MAX_DAYS = 999_999;
const LAT_RED_US = 500_000;
const LAT_YELLOW_US = 100_000;
const LAT_DIM_US = 10_000;
const RISK_CB_OPEN = 500_000;
const RISK_CB_HALF_OPEN = 250_000;
const RISK_ERROR_MULT = 1_000_000;
const RISK_THROUGHPUT_DIV = 1_024;
const TOPO_HIT_TOLERANCE = 1_000;
const ROUTE_RISK_CB_OPEN = 500_000_000;
const ROUTE_RISK_CB_HALF_OPEN = 100_000_000;
const ROUTE_RISK_ERROR_MULT = 1_000_000;
const ROUTE_RISK_THROUGHPUT_DIV = 1_024;
const OVERVIEW_ATTENTION_LIMIT = 1_000;
const TOAST_TIMEOUT_MS = 2_800;
const MS_PER_SEC = 1_000;
const MS_PER_MIN = 60_000;
const MS_PER_HOUR = 3_600_000;
const MS_PER_DAY = 86_400_000;
const BYTES_PER_KB = 1_024;
const BYTES_PER_MB = 1_048_576;
const BYTES_PER_GB = 1_073_741_824;
const US_PER_MS = 1_000;
const US_PER_S = 1_000_000;

const S = {
    // Auth
    token: localStorage.getItem('admin_token') || '',
    username: localStorage.getItem('admin_user') || '',

    // SSE connections
    logSse: null,
    metricsSse: null,
    logStreamDesired: false,
    logStreamReconnectTimer: null,
    logStreamReconnectDelay: 1000,

    // Metrics & history
    prevSnap: null,
    currentMetricSnapshot: null,
    charts: {},
    overviewHistory: { rps: [], err: [], conn: [], lat: [], ts: [] },

    // Targets
    allTargets: [],
    targetSearch: '',
    targetSort: 'risk',
    targetIssuesOnly: false,
    targetHotOnly: false,
    targetQuickFilters: { open: false, probe: false, latency: false, throughput: false },
    targetHist: {},
    prevTargets: {},
    selectedTarget: null,
    selectedTargetKey: null,

    // Routes
    cachedRoutes: null,
    routeSearch: '',
    routeSort: 'attention',
    routeProtocol: 'all',
    routeIssuesOnly: false,
    routeHotOnly: false,
    routeQuickFilters: { open: false, rewrite: false, multi: false, throughput: false },
    routeHostFilter: '__all__',
    selectedRouteKey: null,

    // Topology
    topoData: null,
    topoScale: 1,
    topoPan: { x: 0, y: 0 },
    topologyMode: 'all',
    topologyHeatMode: false,
    topologyHostFilter: '*',
    topologySelectedTargetKey: null,
    topoRouteHist: {},
    topoNodeRects: [],
    topoHitAreas: [],
    topoHoverItem: null,
    topoAnimFrame: null,

    // Logs
    cachedLogs: [],
    activeLevels: new Set(['ERROR', 'WARN', 'INFO']),
    logSearch: '',
    logPreset: 'all',
    logStreamPaused: false,
    pendingStreamEntries: 0,

    // DNS
    cachedDns: null,
    dnsSearch: '',
    dnsNegativesOnly: false,

    // Consul
    cachedConsul: null,

    // Config
    cachedConfig: null,
    cachedConfigStartup: null,
    cachedConfigRuntime: null,
    configDraft: null,
    configCollapsedSections: {},
    configFocusPath: '',
    configSearch: '',
    configDiffOnly: false,
    configStatus: { tone: '', text: '' },

    // Certs
    cachedCerts: null,
    certSearch: '',
    certRisk: 'all',
    certDefaultOnly: false,
    certClientCaOnly: false,
    selectedCertEntry: null,

    // UI
    sidebarOpen: false,
    staticRefreshTimer: null,
};

// DOM element cache — queried once, reused.
// Populated lazily on first access.
const $ = id => document.getElementById(id);
