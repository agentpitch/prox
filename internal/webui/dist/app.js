let state = null;
let snapshot = { connections: [], new_connections: [], logs: [], traffic: [], traffic_totals: { up_bytes: 0, down_bytes: 0 }, traffic_bucket_seconds: 1, rule_stats: [], new_baseline_minutes: 7, new_recent_minutes: 1 };
let logEntries = [];
const rulesUI = window.PitchProxRulesUI;

function readStorage(storage, key, fallback) {
  try {
    const value = storage.getItem(key);
    return value == null ? fallback : value;
  } catch (_) {
    return fallback;
  }
}

function writeStorage(storage, key, value) {
  try { storage.setItem(key, String(value)); } catch (_) {}
}

const RULE_FILTER_VALUES = new Set(['all', 'enabled', 'disabled', 'proxy', 'chain', 'direct', 'block']);
const RULE_COLUMN_VALUES = new Set(['applications', 'hosts', 'ports', 'activity']);

function storedRuleFilter() {
  const value = String(readStorage(sessionStorage, 'pitchprox_rule_filter', 'all'));
  return RULE_FILTER_VALUES.has(value) ? value : 'all';
}

function storedRulePageSize() {
  return Number(readStorage(localStorage, 'pitchprox_rule_page_size', '25')) === 50 ? 50 : 25;
}

function storedRuleColumns() {
  return new Set(String(readStorage(localStorage, 'pitchprox_rule_columns', 'applications,hosts,ports,activity'))
    .split(',')
    .map((value) => value.trim())
    .filter((value) => RULE_COLUMN_VALUES.has(value)));
}

let ui = {
  route: 'rules',
  routeReady: false,
  liveGeneration: 0,
  version: 'dev',
  connFilter: sessionStorage.getItem('pitchprox_conn_filter') || 'all',
  connSearch: sessionStorage.getItem('pitchprox_conn_search') || '',
  rules: {
    query: readStorage(sessionStorage, 'pitchprox_rule_search', ''),
    filter: storedRuleFilter(),
    page: 1,
    pageSize: storedRulePageSize(),
    selected: new Set(),
    columns: storedRuleColumns(),
    activity: new Map(),
    activityTimer: null,
    activityLoading: false,
    activityRequest: null,
    activityGeneration: 0,
    activityVisible: null,
    lastEntries: [],
    lastPage: null,
  },
  dropped: {
    open: false,
    search: sessionStorage.getItem('pitchprox_dropped_search') || '',
    offset: 0,
    limit: 100,
    total: null,
    items: [],
    fileBytes: 0,
    maxBytes: 10 * 1024 * 1024,
    selected: new Set(),
    loading: false,
    error: '',
    searchTimer: null,
    request: null,
    generation: 0,
  },
  focus: { pid: null, exePath: '', ruleId: '', ruleName: '' },
  snapshotTimer: null,
  snapshotLoading: false,
  snapshotRequest: null,
  events: null,
  eventsWanted: false,
  eventsRetryTimer: null,
  eventsRetryAttempt: 0,
  logsInitialized: false,
  logRenderFrame: null,
  editorSave: null,
  editorSession: 0,
  editorSavingSession: 0,
  editorAnalysisTimer: null,
  editorConditionRequest: null,
  editorConditionGeneration: 0,
  saving: false,
  statusMessage: '',
  statusTone: 'muted',
  statusTimer: null,
  servicePaused: false,
  serviceBusy: false,
  webUIPaused: false,
  webUIAutoPaused: false,
  webUIDisabledReason: '',
  webUIIdleDeadlineAt: '',
  webUIIdleTimeoutSeconds: 3600,
  webUIIdleTimer: null,
  webUIStatusRequest: null,
  webUIStatusGeneration: 0,
  webUIStatusFailures: 0,
  refreshing: false,
  editorDirty: false,
  initialized: false,
  configLoadGeneration: 0,
  configSaveGeneration: 0,
  configLoadRequest: null,
  configReloadOnResume: false,
  visibilityRequest: null,
  pendingRouteListener: null,
  pendingRouteFrame: null,
  toastTimers: new Map(),
  resizeFrame: null,
};

const SNAPSHOT_POLL_MS = 15000;
const RULE_ACTIVITY_POLL_MS = 60000;
const MAX_UI_LOG_ENTRIES = 1000;
const MAX_UI_LOG_BUFFER = 1100;

function retentionMinutesFor(source = state) {
  const n = Number(source?.retention_minutes || snapshot?.retention_minutes || 7);
  return Number.isFinite(n) && n >= 1 ? Math.round(n) : 7;
}

function retentionMinutes() {
  return retentionMinutesFor(state);
}

function droppedLogMaxBytesFor(source = state) {
  const n = Number(source?.dropped_log_max_bytes || 0);
  return Number.isFinite(n) && n > 0 ? Math.round(n) : 10 * 1024 * 1024;
}

function droppedLogMaxMBFor(source = state) {
  return Math.max(1, Math.round(droppedLogMaxBytesFor(source) / (1024 * 1024)));
}

function retentionWindowMs() {
  return retentionMinutes() * 60 * 1000;
}

function newConnectionBaselineMinutes() {
  const n = Number(snapshot?.new_baseline_minutes || 0);
  if (Number.isFinite(n) && n >= 1) return Math.round(n);
  return retentionMinutes();
}

function newConnectionRecentMinutes() {
  const n = Number(snapshot?.new_recent_minutes || 0);
  if (Number.isFinite(n) && n >= 1) return Math.round(n);
  return Math.min(1, newConnectionBaselineMinutes());
}

function newConnectionWindowText() {
  const recent = newConnectionRecentMinutes();
  const recentText = recent === 1 ? 'последнюю минуту' : `последние ${formatMinutesRu(recent)}`;
  return `новые за ${recentText}; сравнение в окне истории ${formatMinutesRu(newConnectionBaselineMinutes())}`;
}

function formatMinutesRu(n = retentionMinutes()) {
  const v = Math.max(1, Number(n || 0));
  const mod10 = v % 10;
  const mod100 = v % 100;
  if (mod10 === 1 && mod100 !== 11) return `${v} минуту`;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return `${v} минуты`;
  return `${v} минут`;
}
const $ = (id) => document.getElementById(id);
const uid = (prefix) => `${prefix}_${Math.random().toString(36).slice(2, 10)}`;

const PAGE_META = Object.freeze({
  rules: { title: 'Правила' },
  monitor: { title: 'Мониторинг' },
  proxies: { title: 'Прокси' },
  chains: { title: 'Цепочки' },
  dropped: { title: 'Отброшенные соединения' },
  logs: { title: 'Журнал событий' },
});

function routeFromHash() {
  const value = String(location.hash || '').replace(/^#\/?/, '').split(/[?&]/, 1)[0].trim().toLowerCase();
  return PAGE_META[value] ? value : 'rules';
}

function routeNeedsLive(route = ui.route) {
  return route === 'monitor' || route === 'logs';
}

function routeNeedsSnapshot(route = ui.route) {
  return route === 'monitor';
}

function routeNeedsEvents(route = ui.route) {
  return route === 'logs';
}

function setMobileSidebarOpen(open, options = {}) {
  const expanded = !!open;
  document.body.classList.toggle('sidebar-open', expanded);
  const button = $('mobileMenuBtn');
  if (button) {
    button.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    button.setAttribute('aria-label', expanded ? 'Закрыть меню' : 'Открыть меню');
  }
  if (!expanded && options.restoreFocus) button?.focus();
}

function renderNavigationMeta() {
  const rulesCount = $('rulesNavCount');
  const proxiesCount = $('proxiesNavCount');
  const chainsCount = $('chainsNavCount');
  if (rulesCount) rulesCount.textContent = String(state?.rules?.length || 0);
  if (proxiesCount) proxiesCount.textContent = String(state?.proxies?.length || 0);
  if (chainsCount) chainsCount.textContent = String(state?.chains?.length || 0);
}

function setRoute(nextRoute, options = {}) {
  const route = PAGE_META[nextRoute] ? nextRoute : 'rules';
  if (options.updateHash !== false && routeFromHash() !== route) {
    location.hash = `#/${route}`;
    return;
  }
  const previous = ui.route;
  const routeChanged = previous !== route;
  ui.route = route;
  document.querySelectorAll('[data-page-panel]').forEach((panel) => {
    panel.hidden = panel.getAttribute('data-page-panel') !== route;
  });
  document.querySelectorAll('[data-page]').forEach((button) => {
    const active = button.getAttribute('data-page') === route;
    button.classList.toggle('active', active);
    if (active) button.setAttribute('aria-current', 'page');
    else button.removeAttribute('aria-current');
  });
  const title = $('pageTitle');
  if (title) title.textContent = PAGE_META[route].title;
  const mobileSidebarWasOpen = document.body.classList.contains('sidebar-open');
  setMobileSidebarOpen(false, { restoreFocus: mobileSidebarWasOpen });

  if (!ui.initialized || !state) return;
  const shouldEnter = !ui.routeReady || routeChanged;
  if (routeChanged && routeNeedsLive(previous)) leaveLiveMode(false, !routeNeedsLive(route));
  if (routeChanged && previous === 'rules') {
    stopRuleActivityPolling();
    releaseRulesView();
  }
  if (routeChanged && previous === 'monitor') releaseMonitorView();
  if (routeChanged && previous === 'dropped') closeDroppedDialog();
  if (routeChanged && previous === 'logs') releaseLogView();

  if (route === 'rules') {
    renderRules();
    if (shouldEnter) startRuleActivityPolling(true);
  } else if (route === 'monitor' || route === 'logs') {
    renderObservability();
    if (shouldEnter) void enterLiveMode(true);
  } else if (route === 'proxies') {
    renderProxies();
  } else if (route === 'chains') {
    renderChains();
  } else if (route === 'dropped') {
    if (shouldEnter) openDroppedDialog();
    else renderDroppedDialog();
  }
  ui.routeReady = true;
  scheduleWebUIIdleCheck();
}

function runAfterRoute(route, callback) {
  cancelPendingRouteTask();
  let completed = false;
  const cleanup = () => {
    if (ui.pendingRouteListener) {
      window.removeEventListener('hashchange', ui.pendingRouteListener);
      ui.pendingRouteListener = null;
    }
    if (ui.pendingRouteFrame != null) {
      cancelAnimationFrame(ui.pendingRouteFrame);
      ui.pendingRouteFrame = null;
    }
  };
  const finish = () => {
    if (completed || ui.route !== route) return;
    completed = true;
    cleanup();
    callback();
  };
  if (ui.route === route && routeFromHash() === route) {
    finish();
    return;
  }
  const onHashChange = () => {
    if (routeFromHash() !== route) {
      cleanup();
      return;
    }
    if (ui.pendingRouteListener === onHashChange) {
      window.removeEventListener('hashchange', onHashChange);
      ui.pendingRouteListener = null;
    }
    ui.pendingRouteFrame = requestAnimationFrame(() => {
      ui.pendingRouteFrame = null;
      finish();
    });
  };
  ui.pendingRouteListener = onHashChange;
  window.addEventListener('hashchange', onHashChange);
  setRoute(route);
  if (ui.route === route) {
    window.removeEventListener('hashchange', onHashChange);
    ui.pendingRouteListener = null;
    ui.pendingRouteFrame = requestAnimationFrame(() => {
      ui.pendingRouteFrame = null;
      finish();
    });
  }
}

function cancelPendingRouteTask() {
  if (ui.pendingRouteListener) {
    window.removeEventListener('hashchange', ui.pendingRouteListener);
    ui.pendingRouteListener = null;
  }
  if (ui.pendingRouteFrame != null) {
    cancelAnimationFrame(ui.pendingRouteFrame);
    ui.pendingRouteFrame = null;
  }
}

function removeToast(toast) {
  const timer = ui.toastTimers.get(toast);
  if (timer != null) clearTimeout(timer);
  ui.toastTimers.delete(toast);
  toast.remove();
}

function clearToasts() {
  for (const toast of Array.from(ui.toastTimers.keys())) removeToast(toast);
  $('toastRegion')?.replaceChildren();
}

function showToast(message, tone = 'muted', ms = 3800) {
  const region = $('toastRegion');
  if (!region || !message) return;
  const toast = document.createElement('div');
  toast.className = `toast${tone === 'error' ? ' error' : (tone === 'warn' ? ' warn' : '')}`;
  toast.textContent = message;
  while (region.children.length >= 4) removeToast(region.firstElementChild);
  region.appendChild(toast);
  const timer = setTimeout(() => removeToast(toast), ms);
  ui.toastTimers.set(toast, timer);
}

async function loadHealth() {
  const data = await api('/api/health');
  ui.version = String(data?.version || 'dev');
  const version = $('appVersion');
  if (version) version.textContent = `Версия ${ui.version}`;
  return data;
}

async function api(path, opts = {}) {
  const headers = new Headers(opts.headers || {});
  if (!headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  headers.set('X-PitchProx-WebUI', '1');
  const res = await fetch(path, { ...opts, headers });
  if (!res.ok) {
    const error = new Error(await res.text());
    error.status = res.status;
    if (res.status === 503 && !String(path).startsWith('/api/control/webui/')) void loadWebUIStatus();
    throw error;
  }
  if (res.status === 204) return null;
  return res.json();
}

function clearWebUIIdleTimer() {
  if (ui.webUIIdleTimer != null) {
    clearTimeout(ui.webUIIdleTimer);
    ui.webUIIdleTimer = null;
  }
}

function cancelWebUIStatusRequest() {
  ui.webUIStatusGeneration += 1;
  if (ui.webUIStatusRequest) {
    ui.webUIStatusRequest.abort();
    ui.webUIStatusRequest = null;
  }
  renderWebUIStatus();
}

function stopWebUIBackgroundWork() {
  leaveLiveMode(false, false);
  stopRuleActivityPolling();
  suspendDroppedLoading();
  releaseCurrentViewForSuspension();
}

function renderWebUIStatus() {
  const banner = $('webUIIdleBanner');
  document.body.classList.toggle('webui-paused', !!ui.webUIPaused);
  if (!banner) return;
  banner.hidden = !ui.webUIPaused;
  const title = $('webUIIdleTitle');
  const text = $('webUIIdleText');
  const check = $('webUIStatusCheckBtn');
  if (title) title.textContent = ui.webUIAutoPaused ? 'WebUI автоматически приостановлен' : 'WebUI приостановлен';
  if (text) {
    const timeoutMinutes = Math.max(1, Math.round(Number(ui.webUIIdleTimeoutSeconds || 3600) / 60));
    text.textContent = ui.webUIAutoPaused
      ? `После ${timeoutMinutes} минут без обращений WebUI освободил ресурсы. Проксирование и правила продолжают работать. Возобновите WebUI через меню pitchProx в области уведомлений.`
      : 'Проксирование продолжает работать. Возобновите WebUI через меню pitchProx в области уведомлений.';
  }
  if (check) check.disabled = !!ui.webUIStatusRequest;
}

function scheduleWebUIIdleCheck(afterStatusCheck = false) {
  clearWebUIIdleTimer();
  if (ui.webUIPaused || document.hidden) return;
  const delay = rulesUI.nextWebUIIdleDelay(
    ui.webUIIdleDeadlineAt,
    Date.now(),
    ui.webUIStatusFailures,
    afterStatusCheck,
  );
  if (delay == null) return;
  ui.webUIIdleTimer = setTimeout(async () => {
    ui.webUIIdleTimer = null;
    await loadWebUIStatus();
    if (!ui.webUIPaused) scheduleWebUIIdleCheck(true);
  }, delay);
}

function applyWebUIStatus(data) {
  if (!data || typeof data !== 'object') return false;
  const status = rulesUI.normalizeWebUIStatus(data);
  ui.servicePaused = status.servicePaused;
  ui.webUIPaused = status.webUIPaused;
  ui.webUIAutoPaused = status.webUIAutoPaused;
  ui.webUIDisabledReason = status.disabledReason;
  ui.webUIIdleDeadlineAt = status.idleDeadlineAt;
  ui.webUIIdleTimeoutSeconds = status.idleTimeoutSeconds;
  renderServicePauseToggle();
  renderWebUIStatus();
  updateStatusLine();
  if (ui.webUIPaused) {
    clearWebUIIdleTimer();
    stopWebUIBackgroundWork();
  } else if (ui.servicePaused) {
    stopWebUIBackgroundWork();
    scheduleWebUIIdleCheck(true);
  } else {
    scheduleWebUIIdleCheck(true);
  }
  return true;
}

async function loadWebUIStatus() {
  if (ui.webUIStatusRequest) return false;
  const generation = ui.webUIStatusGeneration + 1;
  ui.webUIStatusGeneration = generation;
  const controller = new AbortController();
  ui.webUIStatusRequest = controller;
  renderWebUIStatus();
  try {
    const data = await api('/api/control/webui/status', { signal: controller.signal });
    if (ui.webUIStatusRequest !== controller || generation !== ui.webUIStatusGeneration) return false;
    ui.webUIStatusFailures = 0;
    return applyWebUIStatus(data);
  } catch (error) {
    if (!isAbortError(error)) {
      ui.webUIStatusFailures = Math.min(5, ui.webUIStatusFailures + 1);
      console.error(error);
    }
    return false;
  } finally {
    if (ui.webUIStatusRequest === controller) {
      ui.webUIStatusRequest = null;
      renderWebUIStatus();
    }
  }
}

async function recheckWebUIStatus() {
  const wasPaused = ui.webUIPaused;
  const checked = await loadWebUIStatus();
  if (!checked) {
    showToast('Не удалось проверить состояние WebUI', 'error');
    return false;
  }
  if (ui.webUIPaused) {
    showToast('WebUI всё ещё приостановлен. Возобновите его из меню pitchProx в трее.', 'warn', 6000);
    return false;
  }
  if (wasPaused || !state) {
    try {
      await loadConfig({ force: true });
      ui.initialized = true;
      setRoute(ui.route, { updateHash: false });
      await resumeCurrentRouteLifecycle(true);
      flashStatus('WebUI возобновлён');
    } catch (error) {
      console.error(error);
      flashStatus(`WebUI включён, но данные не загрузились: ${error.message}`, 'error', 7000);
      return false;
    }
  }
  return true;
}

function renderServicePauseToggle() {
  const toggle = $('servicePauseToggle');
  if (!toggle) return;
  toggle.checked = !!ui.servicePaused;
  toggle.disabled = !!ui.serviceBusy || !!ui.webUIPaused;
  const settings = $('settingsBtn');
  if (settings) settings.disabled = !!ui.webUIPaused;
  document.body.classList.toggle('service-paused', !!ui.servicePaused);
  const card = document.querySelector('.system-card');
  const text = $('systemStateText');
  if (card) {
    card.classList.toggle('paused', !!ui.servicePaused);
    card.classList.remove('error');
  }
  if (text) text.textContent = ui.servicePaused ? 'Система приостановлена' : 'Система активна';
}

async function loadServiceStatus() {
  const data = await api('/api/control/service/status');
  ui.servicePaused = !!data.paused;
  renderServicePauseToggle();
  updateStatusLine();
  return data;
}

async function resumeCurrentRouteLifecycle(forceRefresh = true) {
  if (!ui.initialized || document.hidden || ui.servicePaused || ui.webUIPaused) {
    void postUIVisibility(false);
    return false;
  }
  if (ui.configReloadOnResume || !state) {
    const loaded = await loadConfig();
    if (!loaded && !state) return false;
    if (loaded) ui.configReloadOnResume = false;
  }
  if (routeNeedsLive()) return enterLiveMode(forceRefresh);
  if (ui.route === 'rules') {
    renderRules();
    startRuleActivityPolling(true);
  }
  if (ui.route === 'dropped') {
    ui.dropped.open = true;
    await loadDropped();
  }
  void postUIVisibility(false);
  return true;
}

async function setServicePaused(paused) {
  ui.serviceBusy = true;
  renderServicePauseToggle();
  try {
    if (paused) {
      leaveLiveMode(false);
      stopRuleActivityPolling();
      releaseCurrentViewForSuspension();
    }
    const action = paused ? 'pause' : 'resume';
    const data = await api(`/api/control/service/${action}`, { method: 'POST', body: '{}' });
    ui.servicePaused = !!data.paused;
    renderServicePauseToggle();
    if (ui.servicePaused) {
      flashStatus('Сервис приостановлен', 'warn', 6000);
      return;
    }
    flashStatus('Сервис запущен', 'muted');
    await loadConfig();
    await resumeCurrentRouteLifecycle(true);
  } catch (e) {
    console.error(e);
    flashStatus(`Не удалось ${paused ? 'приостановить' : 'запустить'} сервис: ${e.message}`, 'error', 7000);
    await loadServiceStatus().catch(() => {});
    if (!ui.servicePaused && !ui.webUIPaused) await resumeCurrentRouteLifecycle(true);
  } finally {
    ui.serviceBusy = false;
    renderServicePauseToggle();
  }
}

function clone(v) { return JSON.parse(JSON.stringify(v)); }
function escapeHtml(s) { return String(s ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;'); }
function shortExe(path) { const parts = String(path || '').split('\\'); return parts[parts.length - 1] || ''; }
function ruleIDKey(value) { return String(value || '').trim(); }
function normalizeAction(action) { return String(action || '').toLowerCase(); }
function isProxyAction(action) { const a = normalizeAction(action); return a === 'proxy' || a === 'chain'; }
function truncate(s, n = 72) { s = String(s || ''); return s.length <= n ? s : `${s.slice(0, n - 1)}…`; }
function splitTokens(raw) {
  const out = [];
  let cur = '';
  let inQuotes = false;
  const flush = () => {
    let token = cur.trim();
    if (token.startsWith('"') && token.endsWith('"') && token.length >= 2) token = token.slice(1, -1).trim();
    if (token) out.push(token);
    cur = '';
  };
  for (const ch of String(raw || '')) {
    if (ch === '"') {
      inQuotes = !inQuotes;
      cur += ch;
      continue;
    }
    if (!inQuotes && (ch === ';' || ch === ',' || ch === '\n' || ch === '\r')) {
      flush();
      continue;
    }
    cur += ch;
  }
  flush();
  return out;
}
function formatDateTime(ts) { try { return new Date(ts).toLocaleTimeString(); } catch { return String(ts || ''); } }
function formatSavedAt(ts) {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return String(ts || '');
  }
}
function formatBytes(v) {
  let n = Number(v || 0);
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let idx = 0;
  while (n >= 1024 && idx < units.length - 1) { n /= 1024; idx++; }
  if (idx === 0) return `${Math.round(n)} ${units[idx]}`;
  if (n >= 100) return `${n.toFixed(0)} ${units[idx]}`;
  return `${n.toFixed(1)} ${units[idx]}`;
}
function formatRate(v) { return `${formatBytes(v)}/s`; }
function actionBadgeClass(action) {
  const a = normalizeAction(action);
  if (a === 'proxy' || a === 'chain') return 'action-proxy';
  if (a === 'block') return 'action-block';
  return 'action-direct';
}
function actionLabel(action) {
  const a = normalizeAction(action);
  if (a === 'chain') return 'Chain';
  if (a === 'proxy') return 'Proxy';
  if (a === 'block') return 'Block';
  if (a === 'more') return 'Ещё';
  if (a === 'new') return 'Новые';
  return 'Direct';
}
function actionFilterKey(action) {
  const a = normalizeAction(action);
  if (a === 'proxy' || a === 'chain') return 'proxy';
  if (a === 'block') return 'block';
  if (a === 'direct') return 'direct';
  return 'all';
}

function actionMatchesFilter(action, filter = ui.connFilter) {
  switch (filter) {
    case 'proxy': return isProxyAction(action);
    case 'direct': return normalizeAction(action) === 'direct';
    case 'block': return normalizeAction(action) === 'block';
    default: return true;
  }
}
function searchTokens(raw) {
  return String(raw || '').trim().toLowerCase().split(/\s+/).filter(Boolean);
}
function connectionSearchText(conn) {
  return [
    String(conn?.pid || ''),
    shortExe(conn?.exe_path || ''),
    conn?.exe_path || '',
    conn?.hostname || '',
    conn?.original_ip || '',
    String(conn?.original_port || ''),
    conn?.rule_name || '',
    conn?.rule_id || '',
    actionLabel(conn?.action || ''),
    conn?.state || '',
    conn?.proxy_id || '',
    conn?.chain_id || '',
  ].join('  ').toLowerCase();
}
function connectionMatchesSearch(conn) {
  const tokens = searchTokens(ui.connSearch);
  if (!tokens.length) return true;
  const haystack = connectionSearchText(conn);
  return tokens.every((token) => haystack.includes(token));
}
function isDefaultRuleRef(ruleID, ruleName) {
  const id = ruleIDKey(ruleID);
  const name = String(ruleName || '').trim().toLowerCase();
  return id ? id === 'default' : name === 'default';
}
function isMatchedRuleItem(item) {
  const id = String(item?.rule_id || item?.ruleID || '');
  const name = String(item?.rule_name || item?.ruleName || '');
  if (!id && !name) return false;
  return !isDefaultRuleRef(id, name);
}
function isMoreItem(item) {
  return !isMatchedRuleItem(item);
}
function scopeMatchesFilter(item, filter = ui.connFilter) {
  if (ui.focus?.ruleId || ui.focus?.ruleName) {
    if (filter === 'proxy' || filter === 'direct' || filter === 'block') return actionMatchesFilter(item.action, filter);
    return true;
  }
  switch (filter) {
    case 'all':
    case 'proxy':
    case 'direct':
    case 'block':
      return isMatchedRuleItem(item);
    case 'more':
      return isMoreItem(item);
    case 'new':
      return true;
    default:
      return true;
  }
}
function blankFocus() { return { pid: null, exePath: '', ruleId: '', ruleName: '' }; }
function hasFocus() { return !!(ui.focus && (ui.focus.pid || ui.focus.ruleId || ui.focus.ruleName)); }
function describeFocus() {
  const parts = [];
  if (ui.focus?.pid) parts.push(`Процесс: ${shortExe(ui.focus.exePath || '') || ui.focus.pid} · PID ${ui.focus.pid}`);
  if (ui.focus?.ruleId || ui.focus?.ruleName) parts.push(`Правило: ${ui.focus.ruleName || ui.focus.ruleId}`);
  if (ui.connFilter !== 'all') parts.push(`Режим: ${actionLabel(ui.connFilter)}`);
  return parts;
}
function clearProcessFocus() {
  ui.focus = { ...ui.focus, pid: null, exePath: '' };
  renderObservability();
}
function clearRuleFocus(options = {}) {
  ui.focus = { ...ui.focus, ruleId: '', ruleName: '' };
  if (options.render !== false) renderObservability();
}
function clearActionFilter() {
  ui.connFilter = 'all';
  sessionStorage.setItem('pitchprox_conn_filter', ui.connFilter);
  renderObservability();
}
function connectionMatchesFocus(conn) {
  if (ui.focus?.pid && Number(conn.pid || 0) !== Number(ui.focus.pid || 0)) return false;
  if (ui.focus?.ruleId) {
    const ruleID = String(conn.rule_id || '');
    const ruleName = String(conn.rule_name || '').toLowerCase();
    if (ruleID ? ruleID !== ui.focus.ruleId : ruleName !== String(ui.focus.ruleName || '').toLowerCase()) return false;
  }
  return true;
}
function logMatchesFocus(entry) {
  if (ui.focus?.pid && Number(entry.pid || 0) !== Number(ui.focus.pid || 0)) return false;
  if (ui.focus?.ruleId) {
    const ruleID = String(entry.rule_id || '');
    const ruleName = String(entry.rule_name || '').toLowerCase();
    if (ruleID ? ruleID !== ui.focus.ruleId : ruleName !== String(ui.focus.ruleName || '').toLowerCase()) return false;
  }
  return true;
}
function setProcessFocus(conn, options = {}) {
  ui.focus = { pid: Number(conn.pid || 0) || null, exePath: conn.exe_path || '', ruleId: '', ruleName: '' };
  if (options.syncAction) {
    clearRuleFocus({ render: false });
  }
  if (options.syncAction && conn.action) {
    ui.connFilter = actionFilterKey(conn.action);
    sessionStorage.setItem('pitchprox_conn_filter', ui.connFilter);
  }
  renderObservability();
  const card = $('connectionsCard');
  if (card) card.scrollIntoView({ behavior: 'smooth', block: 'start' });
}
function setRuleFocus(rule, options = {}) {
  const nextId = rule.id || '';
  const currentId = ui.focus?.ruleId || '';
  const currentName = ui.focus?.ruleName || '';
  if (!options.force && currentId === nextId && (currentName === (rule.name || '') || !rule.name)) {
    clearRuleFocus(options);
    return;
  }
  ui.focus = { ...ui.focus, ruleId: nextId, ruleName: rule.name || '' };
  if (options.clearAction !== false) {
    ui.connFilter = 'all';
    sessionStorage.setItem('pitchprox_conn_filter', ui.connFilter);
  }
  renderObservability();
  const card = $('connectionsCard');
  if (card && options.scroll !== false) card.scrollIntoView({ behavior: 'smooth', block: 'start' });
}
function clearFocus() {
  ui.focus = blankFocus();
  ui.connFilter = 'all';
  sessionStorage.setItem('pitchprox_conn_filter', ui.connFilter);
  renderObservability();
}
function makeProxyDraft(overrides = {}) {
  return {
    id: uid('proxy'),
    name: '',
    type: 'http',
    address: '',
    username: '',
    password: '',
    enabled: true,
    __test_target: 'www.google.com:443',
    ...clone(overrides || {}),
  };
}

function makeChainDraft(overrides = {}) {
  return {
    id: uid('chain'),
    name: '',
    proxy_ids: [],
    enabled: true,
    ...clone(overrides || {}),
  };
}

function makeRuleDraft(overrides = {}) {
  return {
    id: uid('rule'),
    name: 'New Rule',
    enabled: true,
    applications: '*',
    target_hosts: 'Any',
    target_ports: 'Any',
    action: 'direct',
    proxy_id: '',
    chain_id: '',
    notes: '',
    ...clone(overrides || {}),
  };
}

function defaultRuleInsertIndex(rules = state?.rules || []) {
  const defaultIdx = (rules || []).findIndex((r) => ruleIDKey(r.id) === 'default');
  return defaultIdx >= 0 ? defaultIdx : (rules || []).length;
}

function buildPidRuleFromFocus() {
  if (!ui.focus?.pid) return null;
  const relevant = filteredConnections();
  const sample = relevant.find((c) => Number(c.pid || 0) === Number(ui.focus.pid || 0)) || (snapshot.connections || []).find((c) => Number(c.pid || 0) === Number(ui.focus.pid || 0));
  const exe = ui.focus.exePath || sample?.exe_path || '';
  const preferredAction = sample?.action ? normalizeAction(sample.action) : 'direct';
  const action = ['direct', 'proxy', 'chain', 'block'].includes(preferredAction) ? preferredAction : 'direct';
  const firstProxy = (state.proxies || []).find((p) => p.enabled)?.id || '';
  const firstChain = (state.chains || []).find((c) => c.enabled)?.id || '';
  return makeRuleDraft({
    name: `${shortExe(exe) || 'Process'} PID ${ui.focus.pid}`,
    applications: String(ui.focus.pid),
    target_hosts: 'Any',
    target_ports: 'Any',
    action,
    proxy_id: action === 'proxy' ? (sample?.proxy_id || firstProxy) : '',
    chain_id: action === 'chain' ? (sample?.chain_id || firstChain) : '',
    notes: exe ? `Полный путь: ${exe}` : '',
  });
}

function createRuleFromFocus() {
  const draft = buildPidRuleFromFocus();
  if (!draft) return;
  openRuleEditor(draft, { isDraft: true, insertAt: defaultRuleInsertIndex() });
}

function logMetaText(entry) {
  const meta = [];
  if (entry.exe_path) meta.push(shortExe(entry.exe_path));
  if (entry.pid) meta.push(`#${entry.pid}`);
  if (entry.rule_name) meta.push(`rule=${entry.rule_name}`);
  if (entry.action) meta.push(actionLabel(entry.action));
  if (entry.host) meta.push(`${entry.host}${entry.port ? `:${entry.port}` : ''}`);
  return meta.length ? ` (${meta.join(' · ')})` : '';
}

function updateStatusLine() {
  const el = $('statusLine');
  if (!el) return;
  if (ui.saving) {
    el.textContent = 'Сохранение…';
    el.className = 'muted';
    return;
  }
  if (ui.statusMessage) {
    el.textContent = ui.statusMessage;
    el.className = ui.statusTone === 'error' ? 'status-error' : (ui.statusTone === 'warn' ? 'status-warn' : 'muted');
    return;
  }
  if (ui.webUIPaused) {
    el.textContent = ui.webUIAutoPaused
      ? 'WebUI автоматически приостановлен; проксирование продолжает работать.'
      : 'WebUI приостановлен; проксирование продолжает работать.';
    el.className = 'status-warn';
    return;
  }
  if (ui.servicePaused) {
    el.textContent = 'Сервис приостановлен. Слежение, правила и WebUI-обновления остановлены.';
    el.className = 'status-warn';
    return;
  }
  if (!state) {
    el.textContent = 'Загрузка…';
    el.className = 'muted';
    return;
  }
  const parts = ['Автосохранение включено', 'конфиг рядом с pitchProx.exe'];
  if (state.updated_at) parts.push(`сохранено ${formatSavedAt(state.updated_at)}`);
  el.textContent = parts.join(' · ');
  el.className = 'muted';
}

function flashStatus(message, tone = 'muted', ms = 3500) {
  ui.statusMessage = message;
  ui.statusTone = tone;
  updateStatusLine();
  showToast(message, tone, ms);
  if (ui.statusTimer) clearTimeout(ui.statusTimer);
  ui.statusTimer = setTimeout(() => {
    ui.statusMessage = '';
    ui.statusTone = 'muted';
    updateStatusLine();
  }, ms);
}

function stripUIFields(obj) {
  const out = {};
  Object.entries(obj || {}).forEach(([k, v]) => {
    if (!k.startsWith('__')) out[k] = v;
  });
  return out;
}

function collectConfig(source = state) {
  const src = source || {};
  return {
    version: src.version || 1,
    updated_at: src.updated_at,
    retention_minutes: retentionMinutesFor(src),
    dropped_log_max_bytes: droppedLogMaxBytesFor(src),
    http: stripUIFields(src.http || {}),
    transparent: stripUIFields(src.transparent || {}),
    proxies: (src.proxies || []).map(stripUIFields),
    chains: (src.chains || []).map(stripUIFields),
    rules: (src.rules || []).map(stripUIFields),
  };
}

function captureTransientState(src) {
  const out = { proxies: new Map() };
  for (const p of (src?.proxies || [])) {
    out.proxies.set(p.id, {
      __test_target: p.__test_target,
      __test_status: p.__test_status,
      __testing: p.__testing,
      __test_token: p.__test_token,
    });
  }
  return out;
}

function restoreTransientState(nextState, transient) {
  const out = clone(nextState || {});
  out.proxies = out.proxies || [];
  for (const p of out.proxies) {
    const saved = transient?.proxies?.get(p.id);
    if (!saved) continue;
    if (saved.__test_target) p.__test_target = saved.__test_target;
    if (saved.__test_status) p.__test_status = saved.__test_status;
    if (saved.__testing) p.__testing = saved.__testing;
    if (saved.__test_token) p.__test_token = saved.__test_token;
  }
  return out;
}

async function persistState(nextState, successMessage = 'Сохранено') {
  if (ui.saving) {
    showToast('Дождитесь завершения текущего сохранения', 'warn');
    return false;
  }
  const transient = captureTransientState(nextState);
  const saveGeneration = ui.configSaveGeneration + 1;
  ui.configSaveGeneration = saveGeneration;
  cancelConfigLoadRequest();
  ui.saving = true;
  updateStatusLine();
  try {
    const saved = await api('/api/config', { method: 'PUT', body: JSON.stringify(collectConfig(nextState)) });
    if (saveGeneration !== ui.configSaveGeneration) return false;
    state = restoreTransientState(saved, transient);
    pruneRuleSelection();
    renderAll();
    flashStatus(successMessage);
    return true;
  } catch (e) {
    console.error(e);
    if (e.status === 409) {
      const editorOpen = !!$('editorDialog')?.open;
      const editorWasDirty = ui.editorDirty;
      const reloaded = await loadConfig({ force: true, transient }).catch((loadError) => {
        console.error(loadError);
        return false;
      });
      ui.editorDirty = editorWasDirty;
      if (reloaded) {
        flashStatus(editorOpen
          ? 'Конфигурация уже изменилась. Загружена актуальная версия; редактор оставлен открытым — проверьте данные и повторите сохранение.'
          : 'Конфигурация уже изменилась. Загружена актуальная версия; повторите действие после проверки.', 'warn', 10000);
      } else {
        flashStatus(editorOpen
          ? 'Конфликт конфигурации. Не удалось загрузить актуальную версию; редактор оставлен открытым. Обновите страницу перед повторной попыткой.'
          : 'Конфликт конфигурации. Не удалось загрузить актуальную версию; обновите страницу перед повторной попыткой.', 'error', 10000);
      }
    } else {
      flashStatus(`Ошибка сохранения: ${e.message}`, 'error', 6000);
    }
    return false;
  } finally {
    ui.saving = false;
    updateStatusLine();
    if (state && ui.route === 'rules') renderRules();
    if (!routeNeedsLive()) void postUIVisibility(false);
  }
}

async function applyStateChange(mutator, successMessage = 'Сохранено') {
  const next = clone(state || {});
  try {
    mutator(next);
  } catch (e) {
    console.error(e);
    flashStatus(e.message || String(e), 'error', 6000);
    return false;
  }
  return persistState(next, successMessage);
}

async function loadConfig(options = {}) {
  if (ui.saving && !options.force) return false;
  if (ui.configLoadRequest) {
    ui.configLoadRequest.abort();
    ui.configLoadRequest = null;
  }
  const generation = ui.configLoadGeneration + 1;
  const saveGeneration = ui.configSaveGeneration;
  const transient = options.transient || captureTransientState(state);
  ui.configLoadGeneration = generation;
  const controller = new AbortController();
  ui.configLoadRequest = controller;
  try {
    const loaded = await api('/api/config', { signal: controller.signal });
    if (ui.configLoadRequest !== controller || generation !== ui.configLoadGeneration || saveGeneration !== ui.configSaveGeneration) return false;
    state = restoreTransientState(loaded, transient);
    pruneRuleSelection();
    renderAll();
    return true;
  } catch (error) {
    if (isAbortError(error) || generation !== ui.configLoadGeneration) return false;
    throw error;
  } finally {
    if (ui.configLoadRequest === controller) ui.configLoadRequest = null;
  }
}

function cancelConfigLoadRequest() {
  const cancelled = !!ui.configLoadRequest;
  ui.configLoadGeneration += 1;
  if (ui.configLoadRequest) {
    ui.configLoadRequest.abort();
    ui.configLoadRequest = null;
  }
  return cancelled;
}

function buildSnapshotURL(options = {}) {
  const params = new URLSearchParams();
  if (options.includeLogs === false) params.set('include_logs', '0');
  const query = params.toString();
  return query ? `/api/snapshot?${query}` : '/api/snapshot';
}

async function loadSnapshot(options = {}) {
  const data = await api(buildSnapshotURL(options), { signal: options.signal });
  if (options.generation != null && options.generation !== ui.liveGeneration) return false;
  if (options.route && options.route !== ui.route) return false;
  if (options.includeLogs !== false && (options.forceLogs || !ui.logsInitialized || !ui.events)) {
    const historyLogs = Array.isArray(data.logs) ? data.logs.slice(-MAX_UI_LOG_ENTRIES) : [];
    logEntries = options.mergeLogs
      ? rulesUI.mergeLogEntries(historyLogs, logEntries, MAX_UI_LOG_ENTRIES)
      : historyLogs;
    ui.logsInitialized = true;
  }
  if (routeNeedsSnapshot(options.route || ui.route)) {
    snapshot = data;
    if (data && data.retention_minutes && (!state || !state.retention_minutes)) {
      state = state || {};
      state.retention_minutes = Number(data.retention_minutes) || 7;
    }
  }
  renderObservability();
  if (ui.route === 'rules') renderRules();
  return true;
}

function isAbortError(error) {
  return error?.name === 'AbortError';
}

function cancelSnapshotRequest() {
  if (ui.snapshotRequest) {
    ui.snapshotRequest.abort();
    ui.snapshotRequest = null;
  }
  ui.snapshotLoading = false;
}

async function loadTrackedSnapshot(options = {}) {
  cancelSnapshotRequest();
  const controller = new AbortController();
  const generation = options.generation ?? ui.liveGeneration;
  const route = options.route || ui.route;
  ui.snapshotRequest = controller;
  ui.snapshotLoading = true;
  try {
    return await loadSnapshot({ ...options, signal: controller.signal, generation, route });
  } catch (error) {
    if (isAbortError(error) || generation !== ui.liveGeneration || route !== ui.route) return false;
    throw error;
  } finally {
    if (ui.snapshotRequest === controller) {
      ui.snapshotRequest = null;
      ui.snapshotLoading = false;
    }
  }
}

function renderAll() {
  renderServicePauseToggle();
  updateStatusLine();
  renderNavigationMeta();
  if (ui.route === 'rules') renderRules();
  else if (ui.route === 'proxies') renderProxies();
  else if (ui.route === 'chains') renderChains();
  else if (ui.route === 'dropped') renderDroppedDialog();
  renderObservability();
}

function renderProxies() {
  const box = $('proxies');
  const items = state.proxies || [];
  if (!items.length) {
    box.innerHTML = '<div class="empty-state">Прокси ещё не добавлены.</div>';
    return;
  }
  box.innerHTML = '';
  items.forEach((proxy, idx) => {
    const row = document.createElement('div');
    row.className = 'list-row proxy-row';
    const isTesting = !!proxy.__testing;
    const status = isTesting ? { message: 'Проверка…' } : (proxy.__test_status || null);
    const statusClass = !status ? 'muted' : isTesting ? 'muted' : status.ok ? 'status-ok' : (status.proxy_reachable || status.tunnel_reachable) ? 'status-warn' : 'status-error';
    row.innerHTML = `
      <div class="proxy-card">
        <div class="proxy-card-head">
          <div class="list-main">
            <div class="list-title">
              <span>${escapeHtml(proxy.name || proxy.id || 'Proxy')}</span>
            </div>
            <div class="proxy-meta">
              <span class="badge ${proxy.enabled ? '' : 'badge-muted'}">${proxy.enabled ? 'Включено' : 'Отключено'}</span>
              <span class="badge">${escapeHtml(String(proxy.type || 'http').toUpperCase())}</span>
              <span class="list-subtitle proxy-address">${escapeHtml(proxy.address || '')}</span>
            </div>
          </div>
        </div>
        <div class="proxy-controls">
          <div class="proxy-target">
            <input type="text" value="${escapeHtml(proxy.__test_target || 'www.google.com:443')}" data-role="target" placeholder="www.google.com:443">
            <button type="button" data-action="test" ${isTesting ? 'disabled' : ''}>${isTesting ? 'Проверка…' : 'Проверить'}</button>
          </div>
          <div class="proxy-buttons">
            <button type="button" data-action="edit">Изменить</button>
            <button type="button" data-action="delete">Удалить</button>
          </div>
        </div>
        <div class="status-line ${statusClass}" data-role="status">${escapeHtml(status ? status.message : '')}</div>
      </div>
    `;
    row.querySelector('[data-role="target"]').addEventListener('input', (e) => { proxy.__test_target = e.target.value; });
    row.querySelector('[data-action="edit"]').onclick = () => openProxyEditor(idx);
    row.querySelector('[data-action="delete"]').onclick = async () => {
      await applyStateChange((next) => {
        next.proxies = next.proxies || [];
        next.proxies.splice(idx, 1);
      }, 'Прокси удалён');
    };
    row.querySelector('[data-action="test"]').onclick = async () => {
      if (proxy.__testing) return;
      const proxyID = String(proxy.id || '');
      const target = (proxy.__test_target || '').trim() || 'www.google.com:443';
      const token = uid('proxy_test');
      proxy.__testing = true;
      proxy.__test_token = token;
      renderProxies();
      try {
        const result = await api('/api/proxy-test', { method: 'POST', body: JSON.stringify({ proxy: stripUIFields(proxy), target }) });
        const current = (state?.proxies || []).find((item) => String(item.id || '') === proxyID);
        if (current?.__test_token === token) current.__test_status = result;
      } catch (e) {
        const current = (state?.proxies || []).find((item) => String(item.id || '') === proxyID);
        if (current?.__test_token === token) current.__test_status = { ok: false, message: e.message || String(e) };
      } finally {
        const current = (state?.proxies || []).find((item) => String(item.id || '') === proxyID);
        if (current?.__test_token === token) {
          current.__testing = false;
          delete current.__test_token;
        }
        renderProxies();
      }
    };
    box.appendChild(row);
  });
}

function renderChains() {
  const box = $('chains');
  const items = state.chains || [];
  if (!items.length) {
    box.innerHTML = '<div class="empty-state">Цепочки ещё не добавлены.</div>';
    return;
  }
  box.innerHTML = '';
  items.forEach((chain, idx) => {
    const names = (chain.proxy_ids || []).map((id) => proxyNameById(id)).join(' → ');
    const row = document.createElement('div');
    row.className = 'list-row';
    row.innerHTML = `
      <div class="list-summary">
        <div class="list-main">
          <div class="list-title">
            <span>${escapeHtml(chain.name || chain.id || 'Chain')}</span>
            <span class="badge ${chain.enabled ? '' : 'badge-muted'}">${chain.enabled ? 'Включено' : 'Отключено'}</span>
          </div>
          <div class="list-subtitle">${escapeHtml(names || 'Пустая цепочка')}</div>
        </div>
        <div class="list-actions">
          <button type="button" data-action="edit">Изменить</button>
          <button type="button" data-action="delete">Удалить</button>
        </div>
      </div>
    `;
    row.querySelector('[data-action="edit"]').onclick = () => openChainEditor(idx);
    row.querySelector('[data-action="delete"]').onclick = async () => {
      await applyStateChange((next) => {
        next.chains = next.chains || [];
        next.chains.splice(idx, 1);
      }, 'Цепочка удалена');
    };
    box.appendChild(row);
  });
}

function ruleStatsMap() {
  const byID = new Map();
  const byName = new Map();
  for (const item of (snapshot.rule_stats || [])) {
    const id = String(item.rule_id || '');
    const name = String(item.rule_name || '').toLocaleLowerCase('ru');
    const target = id ? byID : byName;
    const key = id || name;
    if (!key) continue;
    const current = target.get(key) || { connections: 0, up_bytes: 0, down_bytes: 0 };
    current.connections += Number(item.connections || 0);
    current.up_bytes += Number(item.up_bytes || 0);
    current.down_bytes += Number(item.down_bytes || 0);
    target.set(key, current);
  }
  return { byID, byName };
}

function getRuleStats(rule, statsMaps) {
  return ui.rules.activity.get(String(rule.id || ''))
    || statsMaps.byID.get(rule.id)
    || statsMaps.byName.get(String(rule.name || '').toLocaleLowerCase('ru'))
    || { connections: 0, up_bytes: 0, down_bytes: 0, buckets: [] };
}

function routeLabelForRule(rule) {
  if (rule.action === 'proxy') return `${proxyNameById(rule.proxy_id)} ${rule.proxy_id || ''}`.trim();
  if (rule.action === 'chain') return `${chainNameById(rule.chain_id)} ${rule.chain_id || ''}`.trim();
  return actionLabel(rule.action);
}

function findRuleIndexByID(ruleID, source = state) {
  const key = ruleIDKey(ruleID);
  return (source?.rules || []).findIndex((rule) => ruleIDKey(rule.id) === key);
}

function pruneRuleSelection() {
  const existing = new Set((state?.rules || []).map((rule) => ruleIDKey(rule.id)));
  ui.rules.selected = new Set(Array.from(ui.rules.selected).filter((id) => existing.has(id)));
}

function filteredRuleEntries() {
  return rulesUI.filterRules(state?.rules || [], {
    query: ui.rules.query,
    filter: ui.rules.filter,
    routeLabel: routeLabelForRule,
  });
}

function currentRulePage() {
  const entries = filteredRuleEntries();
  const page = rulesUI.paginate(entries, ui.rules.page, ui.rules.pageSize);
  ui.rules.page = page.page;
  ui.rules.lastEntries = entries;
  ui.rules.lastPage = page;
  return { entries, page };
}

function ruleCountText(count) {
  const n = Math.max(0, Number(count || 0));
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return `${n} правило`;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return `${n} правила`;
  return `${n} правил`;
}

function activationCountText(count) {
  const n = Math.max(0, Number(count || 0));
  const mod10 = n % 10;
  const mod100 = n % 100;
  if (mod10 === 1 && mod100 !== 11) return `${n.toLocaleString()} срабатывание`;
  if (mod10 >= 2 && mod10 <= 4 && (mod100 < 12 || mod100 > 14)) return `${n.toLocaleString()} срабатывания`;
  return `${n.toLocaleString()} срабатываний`;
}

function renderRuleValue(raw, kind) {
  const preview = rulesUI.previewValues(raw, kind === 'ports' ? 1 : 2);
  const values = preview.values.length ? preview.values : ['Any'];
  const visible = preview.values.length ? preview.visible : ['Any'];
  const title = escapeHtml(values.join('\n'));
  return `<div class="value-stack" title="${title}">${visible.map((value) => `<span class="value-chip">${escapeHtml(value)}</span>`).join('')}${preview.hidden ? `<span class="value-more">+${preview.hidden}</span>` : ''}</div>`;
}

function ruleRouteMarkup(rule) {
  const action = normalizeAction(rule.action || 'direct');
  let label = actionLabel(action);
  if (action === 'proxy') label = proxyNameById(rule.proxy_id) || rule.proxy_id || 'Proxy';
  if (action === 'chain') label = chainNameById(rule.chain_id) || rule.chain_id || 'Chain';
  return `<span class="route-badge route-${escapeHtml(action)}" title="${escapeHtml(label)}">${escapeHtml(label)}</span>`;
}

function sparklineMarkup(stat) {
  const buckets = Array.isArray(stat?.buckets) ? stat.buckets : [];
  if (buckets.length < 2) return '<div class="sparkline-empty">—</div>';
  const values = buckets.map((bucket) => {
    const bytes = Number(bucket.up_bytes || 0) + Number(bucket.down_bytes || 0);
    return bytes > 0 ? Math.log1p(bytes) : Number(bucket.connections || 0);
  });
  const max = Math.max(1, ...values);
  const width = 62;
  const height = 28;
  const points = values.map((value, index) => {
    const x = values.length === 1 ? 0 : (index / (values.length - 1)) * width;
    const y = height - 2 - (value / max) * (height - 5);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  const area = `0,${height} ${points} ${width},${height}`;
  return `<svg class="sparkline" viewBox="0 0 ${width} ${height}" role="img" aria-label="Активность правила"><polygon class="spark-fill" points="${area}"></polygon><polyline class="spark-line" points="${points}"></polyline></svg>`;
}

function ruleActivityMarkup(rule, statsMaps) {
  const stat = getRuleStats(rule, statsMaps);
  const totalBytes = Number(stat.up_bytes || 0) + Number(stat.down_bytes || 0);
  const connections = Number(stat.connections || 0);
  const bytesText = totalBytes > 0 ? formatBytes(totalBytes) : (connections > 0 ? 'Нет данных о байтах' : 'Нет активности');
  const windowMinutes = Number(stat.window_minutes || Math.min(retentionMinutes(), 60));
  const rate = windowMinutes > 0 ? connections / windowMinutes : 0;
  const rateText = rate >= 10 ? Math.round(rate).toLocaleString() : rate.toFixed(rate > 0 && rate < 1 ? 1 : 0);
  return `<div class="activity-cell-wrap"><div class="activity-cell" title="За последние ${windowMinutes} мин: вход ${escapeHtml(formatBytes(stat.down_bytes || 0))}, исход ${escapeHtml(formatBytes(stat.up_bytes || 0))}"><div class="activity-values"><div class="activity-bytes">${escapeHtml(bytesText)}</div><div class="activity-connections">▲ ${escapeHtml(rateText)} соед./мин</div></div>${sparklineMarkup(stat)}</div><button type="button" class="condition-details-link" data-action="condition-activity">Детали условий</button></div>`;
}

function renderRulePager(page) {
  const first = $('ruleFirstPageBtn');
  const prev = $('rulePrevPageBtn');
  const next = $('ruleNextPageBtn');
  const last = $('ruleLastPageBtn');
  for (const button of [first, prev]) if (button) button.disabled = page.page <= 1;
  for (const button of [next, last]) if (button) button.disabled = page.page >= page.pageCount;
  const numbers = $('rulePageNumbers');
  if (!numbers) return;
  const pages = new Set([1, page.pageCount]);
  for (let n = page.page - 1; n <= page.page + 1; n += 1) if (n >= 1 && n <= page.pageCount) pages.add(n);
  const ordered = Array.from(pages).sort((a, b) => a - b);
  const chunks = [];
  let previous = 0;
  for (const n of ordered) {
    if (previous && n - previous > 1) chunks.push('<span class="page-gap">…</span>');
    chunks.push(`<button type="button" data-rule-page="${n}" class="${n === page.page ? 'active' : ''}" ${n === page.page ? 'aria-current="page"' : ''}>${n}</button>`);
    previous = n;
  }
  numbers.innerHTML = chunks.join('');
}

function renderRuleSelection(entries, page) {
  const pageIDs = page.items.map((entry) => entry.ruleId);
  const selectedOnPage = pageIDs.filter((id) => ui.rules.selected.has(id)).length;
  const selectPage = $('selectPageRules');
  if (selectPage) {
    selectPage.checked = pageIDs.length > 0 && selectedOnPage === pageIDs.length;
    selectPage.indeterminate = selectedOnPage > 0 && selectedOnPage < pageIDs.length;
    selectPage.disabled = pageIDs.length === 0 || ui.saving;
  }
  const selectedCount = ui.rules.selected.size;
  const bulkDisabled = selectedCount === 0 || ui.saving;
  for (const id of ['bulkEnableBtn', 'bulkDisableBtn', 'bulkDeleteBtn']) {
    const button = $(id);
    if (button) button.disabled = bulkDisabled;
  }
  const info = $('rulesSelectionInfo');
  if (!info) return;
  if (!selectedCount) {
    info.hidden = true;
    info.innerHTML = '';
    return;
  }
  info.hidden = false;
  const allFilteredSelected = entries.length > 0 && entries.every((entry) => ui.rules.selected.has(entry.ruleId));
  const canSelectAll = !allFilteredSelected && selectedOnPage === pageIDs.length && entries.length > pageIDs.length;
  info.innerHTML = `Выбрано: ${selectedCount}${canSelectAll ? `<button type="button" data-action="select-all-filtered">Выбрать все найденные (${entries.length})</button>` : ''}<button type="button" data-action="clear-selection">Снять выбор</button>`;
}

function refreshRuleSelectionDOM() {
  document.querySelectorAll('[data-rule-row]').forEach((row) => {
    const id = row.getAttribute('data-rule-row') || '';
    const selected = ui.rules.selected.has(id);
    row.classList.toggle('selected', selected);
    const checkbox = row.querySelector('[data-action="select"]');
    if (checkbox) checkbox.checked = selected;
  });
  if (ui.rules.lastPage) renderRuleSelection(ui.rules.lastEntries, ui.rules.lastPage);
}

function renderRuleColumnState() {
  const table = $('rulesTable');
  if (!table) return;
  const mediumLayout = window.matchMedia('(min-width: 761px) and (max-width: 1100px)').matches;
  for (const column of ['applications', 'hosts', 'ports', 'activity']) {
    table.classList.toggle(`hide-col-${column}`, !ui.rules.columns.has(column));
    const checkbox = document.querySelector(`[data-rule-column="${column}"]`);
    if (checkbox) {
      const autoHidden = mediumLayout && (column === 'applications' || column === 'activity');
      checkbox.checked = ui.rules.columns.has(column);
      checkbox.disabled = autoHidden;
      checkbox.closest('label').title = autoHidden ? 'Столбец временно скрыт на этой ширине окна' : '';
    }
  }
}

function ruleActivityShouldRun() {
  if (!ui.rules.columns.has('activity')) return false;
  return !window.matchMedia('(min-width: 761px) and (max-width: 1100px)').matches;
}

function syncRuleActivityVisibility() {
  const visible = ruleActivityShouldRun();
  if (ui.rules.activityVisible === visible) return;
  ui.rules.activityVisible = visible;
  if (visible && ui.route === 'rules') startRuleActivityPolling(true);
  else stopRuleActivityPolling();
}

function renderRules() {
  const box = $('rules');
  if (!box || !state) return;
  pruneRuleSelection();
  const items = state.rules || [];
  const { entries, page } = currentRulePage();
  const statsMaps = ruleStatsMap();
  const reorderLocked = !!String(ui.rules.query || '').trim() || ui.rules.filter !== 'all';

  const totalLabel = $('rulesTotalLabel');
  const searchCount = $('ruleSearchCount');
  const searchInput = $('ruleSearch');
  const clearSearch = $('clearRuleSearchBtn');
  const filter = $('ruleFilter');
  const pageSize = $('rulePageSize');
  const summary = $('rulePageSummary');
  const orderHint = $('ruleOrderHint');
  if (totalLabel) totalLabel.textContent = ruleCountText(items.length);
  if (searchCount) searchCount.textContent = `${entries.length} / ${items.length}`;
  if (searchInput && searchInput.value !== ui.rules.query) searchInput.value = ui.rules.query;
  if (clearSearch) clearSearch.classList.toggle('visible', !!String(ui.rules.query || '').trim());
  if (filter) filter.value = ui.rules.filter;
  if (pageSize) pageSize.value = String(page.pageSize);
  if (summary) summary.textContent = page.total ? `${page.start + 1}–${page.end} из ${page.total} правил` : '0 из 0 правил';
  if (orderHint) orderHint.hidden = !reorderLocked;
  renderRuleColumnState();
  renderRuleSelection(entries, page);
  renderRulePager(page);

  if (!items.length) {
    box.innerHTML = '<tr class="rules-empty-row"><td colspan="10" class="rules-table-empty">Правила ещё не добавлены. Создайте первое правило.</td></tr>';
    return;
  }
  if (!page.items.length) {
    box.innerHTML = '<tr class="rules-empty-row"><td colspan="10" class="rules-table-empty">По этому запросу правил не найдено.</td></tr>';
    return;
  }

  box.innerHTML = page.items.map(({ rule, ruleId, originalIndex }) => {
    const selected = ui.rules.selected.has(ruleId);
    const name = rule.name || rule.id || 'Rule';
    const route = ruleRouteMarkup(rule);
    const disableUp = reorderLocked || originalIndex <= 0 || ui.saving;
    const disableDown = reorderLocked || originalIndex >= items.length - 1 || ui.saving;
    return `
      <tr class="${selected ? 'selected ' : ''}${rule.enabled ? '' : 'rule-disabled'}" data-rule-row="${escapeHtml(ruleId)}">
        <td class="col-select"><label class="row-select"><input type="checkbox" data-action="select" ${selected ? 'checked' : ''} aria-label="Выбрать ${escapeHtml(name)}"></label></td>
        <td class="col-enabled"><label class="switch" title="${rule.enabled ? 'Отключить правило' : 'Включить правило'}"><input type="checkbox" data-action="toggle-enabled" aria-label="${rule.enabled ? 'Отключить' : 'Включить'} правило ${escapeHtml(name)}" ${rule.enabled ? 'checked' : ''} ${ui.saving ? 'disabled' : ''}><span class="switch-track"></span></label></td>
        <td class="col-order"><div class="order-cell"><span class="order-number">${originalIndex + 1}</span><span class="order-buttons"><button type="button" data-action="up" ${disableUp ? 'disabled' : ''} aria-label="Поднять правило">↑</button><button type="button" data-action="down" ${disableDown ? 'disabled' : ''} aria-label="Опустить правило">↓</button></span></div></td>
        <td class="col-name rule-name-cell" data-action="edit" tabindex="0" role="button" aria-label="Изменить правило ${escapeHtml(name)}"><div class="rule-table-name">${escapeHtml(name)}</div><div class="rule-table-note" title="${escapeHtml(rule.notes || 'Комментарий не указан')}">${escapeHtml(rule.notes || 'Комментарий не указан')}</div></td>
        <td class="col-applications">${renderRuleValue(rule.applications, 'applications')}</td>
        <td class="col-hosts">${renderRuleValue(rule.target_hosts, 'hosts')}</td>
        <td class="col-ports">${renderRuleValue(rule.target_ports, 'ports')}</td>
        <td class="col-route">${route}</td>
        <td class="col-activity" data-rule-activity="${escapeHtml(ruleId)}">${ruleActivityMarkup(rule, statsMaps)}</td>
        <td class="col-actions"><details class="row-menu"><summary aria-label="Действия с правилом">•••</summary><div class="row-menu-popover"><button type="button" data-action="edit">Изменить</button><button type="button" data-action="condition-activity">Активность условий</button><button type="button" data-action="duplicate">Дублировать</button><button type="button" data-action="delete">Удалить</button></div></details></td>
      </tr>`;
  }).join('');
}

function renderRuleActivityCells() {
  if (!state || ui.route !== 'rules') return;
  const statsMaps = ruleStatsMap();
  document.querySelectorAll('[data-rule-activity]').forEach((cell) => {
    const id = cell.getAttribute('data-rule-activity') || '';
    const index = findRuleIndexByID(id);
    if (index < 0) return;
    cell.innerHTML = ruleActivityMarkup(state.rules[index], statsMaps);
  });
}

function scheduleRuleActivityRefresh(delay = 350) {
  stopRuleActivityPolling();
  if (ui.route !== 'rules' || document.hidden || ui.servicePaused || ui.webUIPaused || !ruleActivityShouldRun()) return;
  const generation = ui.rules.activityGeneration;
  ui.rules.activityTimer = setTimeout(() => {
    ui.rules.activityTimer = null;
    void runRuleActivityPoll(generation);
  }, Math.max(0, delay));
}

async function loadRuleActivity() {
  if (!state || ui.route !== 'rules' || document.hidden || ui.servicePaused || ui.webUIPaused || !ruleActivityShouldRun() || ui.rules.activityLoading) return;
  const { page } = currentRulePage();
  const ids = page.items.map((entry) => entry.ruleId).filter(Boolean).slice(0, 50);
  if (!ids.length) {
    ui.rules.activity = new Map();
    renderRuleActivityCells();
    return;
  }
  const params = new URLSearchParams();
  ids.forEach((id) => params.append('id', id));
  params.set('points', '40');
  params.set('window_minutes', String(Math.min(15, retentionMinutes())));
  const controller = new AbortController();
  ui.rules.activityRequest = controller;
  ui.rules.activityLoading = true;
  try {
    const data = await api(`/api/rules/activity?${params.toString()}`, { signal: controller.signal });
    if (ui.rules.activityRequest !== controller || ui.route !== 'rules') return;
    const next = new Map();
    for (const series of (data?.series || [])) {
      if (!series?.rule_id) continue;
      next.set(String(series.rule_id), {
        ...series,
        window_minutes: Number(data.window_minutes || 15),
      });
    }
    ui.rules.activity = next;
    renderRuleActivityCells();
  } catch (e) {
    if (e.name !== 'AbortError') console.error(e);
  } finally {
    if (ui.rules.activityRequest === controller) {
      ui.rules.activityRequest = null;
      ui.rules.activityLoading = false;
    }
  }
}

async function runRuleActivityPoll(generation = ui.rules.activityGeneration) {
  await loadRuleActivity();
  if (generation === ui.rules.activityGeneration && ui.route === 'rules' && !document.hidden && !ui.servicePaused && !ui.webUIPaused && ruleActivityShouldRun()) {
    ui.rules.activityTimer = setTimeout(() => {
      ui.rules.activityTimer = null;
      void runRuleActivityPoll(generation);
    }, RULE_ACTIVITY_POLL_MS);
  }
}

function startRuleActivityPolling(immediate = true) {
  scheduleRuleActivityRefresh(immediate ? 0 : RULE_ACTIVITY_POLL_MS);
}

function stopRuleActivityPolling() {
  ui.rules.activityGeneration += 1;
  if (ui.rules.activityTimer) {
    clearTimeout(ui.rules.activityTimer);
    ui.rules.activityTimer = null;
  }
  if (ui.rules.activityRequest) {
    ui.rules.activityRequest.abort();
    ui.rules.activityRequest = null;
  }
  ui.rules.activityLoading = false;
}

async function changeRuleOrder(ruleID, delta) {
  if (String(ui.rules.query || '').trim() || ui.rules.filter !== 'all') {
    showToast('Сначала очистите поиск и фильтр — порядок правил влияет на маршрутизацию', 'warn');
    return;
  }
  await applyStateChange((next) => {
    next.rules = next.rules || [];
    const index = findRuleIndexByID(ruleID, next);
    if (index >= 0) moveItem(next.rules, index, index + delta);
  }, 'Порядок правил обновлён');
}

async function toggleRule(ruleID, enabled) {
  const ok = await applyStateChange((next) => {
    const index = findRuleIndexByID(ruleID, next);
    if (index >= 0) next.rules[index].enabled = !!enabled;
  }, enabled ? 'Правило включено' : 'Правило отключено');
  if (!ok) renderRules();
}

function duplicateRule(ruleID) {
  const index = findRuleIndexByID(ruleID);
  if (index < 0) return;
  const copy = clone(state.rules[index]);
  copy.id = uid('rule');
  copy.name = `${copy.name || 'Rule'} (copy)`;
  openRuleEditor(copy, { isDraft: true, insertAt: index + 1 });
}

async function deleteRule(ruleID) {
  const index = findRuleIndexByID(ruleID);
  if (index < 0) return;
  const rule = state.rules[index];
  if (!confirm(`Удалить правило «${rule.name || rule.id}»?`)) return;
  const ok = await applyStateChange((next) => {
    const currentIndex = findRuleIndexByID(ruleID, next);
    if (currentIndex >= 0) next.rules.splice(currentIndex, 1);
  }, 'Правило удалено');
  if (ok) ui.rules.selected.delete(ruleID);
}

async function applyBulkRuleEnabled(enabled) {
  const selected = new Set(ui.rules.selected);
  if (!selected.size) return;
  const ok = await applyStateChange((next) => {
    for (const rule of (next.rules || [])) {
      if (selected.has(ruleIDKey(rule.id))) rule.enabled = !!enabled;
    }
  }, `${enabled ? 'Включено' : 'Отключено'}: ${selected.size}`);
  if (ok) ui.rules.selected = new Set();
  renderRules();
}

async function deleteSelectedRules() {
  const selected = new Set(ui.rules.selected);
  if (!selected.size) return;
  const names = (state.rules || []).filter((rule) => selected.has(ruleIDKey(rule.id))).slice(0, 4).map((rule) => rule.name || rule.id);
  const suffix = selected.size > names.length ? ` и ещё ${selected.size - names.length}` : '';
  if (!confirm(`Удалить ${ruleCountText(selected.size)}?\n${names.join(', ')}${suffix}`)) return;
  const ok = await applyStateChange((next) => {
    next.rules = (next.rules || []).filter((rule) => !selected.has(ruleIDKey(rule.id)));
  }, `Удалено: ${selected.size}`);
  if (ok) ui.rules.selected = new Set();
  renderRules();
}

function exportRules() {
  const selected = ui.rules.selected;
  const rules = selected.size
    ? (state.rules || []).filter((rule) => selected.has(ruleIDKey(rule.id)))
    : (state.rules || []);
  if (!rules.length) {
    showToast('Нет правил для экспорта', 'warn');
    return;
  }
  const payload = rulesUI.makeExportPayload(rules);
  const blob = new Blob([`${JSON.stringify(payload, null, 2)}\n`], { type: 'application/json;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `pitchprox-rules-${new Date().toISOString().slice(0, 10)}.json`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  showToast(`Экспортировано: ${rules.length}`);
}

function unresolvedImportedRule(rule) {
  if (rule.action === 'proxy') {
    const profile = (state.proxies || []).find((item) => item.id === rule.proxy_id);
    return !profile || !profile.enabled;
  }
  if (rule.action === 'chain') {
    const chain = (state.chains || []).find((item) => item.id === rule.chain_id);
    return !chain || !chain.enabled;
  }
  return false;
}

function openRulesImportPreview(parsed) {
  const rules = parsed.rules || [];
  const errors = parsed.errors || [];
  if (!rules.length) {
    flashStatus(errors[0] || 'В файле нет подходящих правил', 'error', 6000);
    return;
  }
  const currentIDs = new Set((state.rules || []).map((rule) => ruleIDKey(rule.id)));
  const conflicts = rules.filter((rule) => currentIDs.has(ruleIDKey(rule.id))).length;
  const unresolved = rules.filter(unresolvedImportedRule);
  const unresolvedPreview = unresolved.slice(0, 100);
  const hiddenUnresolved = Math.max(0, unresolved.length - unresolvedPreview.length);
  const existingCriteria = new Set((state.rules || []).map((rule) => rulesUI.ruleCriteriaFingerprint(rule)));
  const possibleDuplicates = rules.filter((rule) => existingCriteria.has(rulesUI.ruleCriteriaFingerprint(rule))).length;
  openEditor({
    title: 'Импорт правил',
    hint: 'Предпросмотр rules-only файла. Прокси-пароли и остальные настройки не импортируются.',
    bodyHTML: `
      <div class="import-summary">
        <div class="import-stat"><strong>${rules.length}</strong><span>валидных правил</span></div>
        <div class="import-stat"><strong>${conflicts}</strong><span>конфликтов ID</span></div>
        <div class="import-stat"><strong>${possibleDuplicates}</strong><span>точных совпадений</span></div>
        <div class="import-stat"><strong>${unresolved.length}</strong><span>недоступных маршрутов</span></div>
      </div>
      <div class="editor-section">
        <label>При совпадении ID<select id="ed_import_strategy">
          <option value="skip">Пропустить существующие</option>
          <option value="replace">Заменить существующие</option>
          <option value="copy">Создать копии с новым ID</option>
        </select></label>
        <label class="editor-check"><input id="ed_import_disable_unresolved" type="checkbox" checked><span>Отключить правила с отсутствующим или выключенным маршрутом</span></label>
        <div class="hint">Новые правила сохраняют взаимный порядок и вставляются перед правилом Default, если оно существует.</div>
      </div>
      ${(errors.length || unresolved.length) ? `<div class="analysis-box import-issues"><strong>Предупреждения</strong><ul>${errors.map((error) => `<li>${escapeHtml(error)}</li>`).join('')}${unresolvedPreview.map((rule) => `<li>${escapeHtml(rule.name || rule.id)}: маршрут ${escapeHtml(rule.proxy_id || rule.chain_id || 'не указан')} недоступен</li>`).join('')}${hiddenUnresolved ? `<li>Ещё недоступных маршрутов скрыто: ${hiddenUnresolved}</li>` : ''}</ul></div>` : ''}
    `,
    onSave: async (editorSession) => {
      const strategy = $('ed_import_strategy')?.value || 'skip';
      const disableUnresolved = !!$('ed_import_disable_unresolved')?.checked;
      const imported = rules.map((rule) => {
        const copy = clone(rule);
        if (disableUnresolved && unresolvedImportedRule(copy)) copy.enabled = false;
        return copy;
      });
      const merged = rulesUI.mergeImportedRules(state.rules || [], imported, strategy);
      const changed = merged.summary.added + merged.summary.replaced + merged.summary.copied;
      if (!changed) {
        showToast('Новых изменений для импорта нет', 'warn');
        closeEditor(true, editorSession);
        return;
      }
      const ok = await applyStateChange((next) => {
        next.rules = merged.rules;
      }, `Импортировано: ${changed}`);
      if (ok) {
        ui.rules.selected = new Set();
        closeEditor(true, editorSession);
      }
    },
  });
}

async function handleRulesImportFile(file) {
  if (!file) return;
  if (file.size > 5 * 1024 * 1024) {
    flashStatus('Файл импорта превышает 5 МБ', 'error', 6000);
    return;
  }
  try {
    const parsed = rulesUI.parseImportPayload(await file.text());
    openRulesImportPreview(parsed);
  } catch (e) {
    flashStatus(`Не удалось прочитать импорт: ${e.message}`, 'error', 6000);
  }
}

function handleRulesTableClick(event) {
  const actionElement = event.target.closest('[data-action]');
  if (!actionElement) return;
  const row = actionElement.closest('[data-rule-row]');
  const ruleID = row?.getAttribute('data-rule-row') || '';
  const action = actionElement.getAttribute('data-action');
  if (action === 'edit') openRuleEditor(ruleID);
  else if (action === 'condition-activity') openRuleEditor(ruleID, { focusConditionActivity: true });
  else if (action === 'up') void changeRuleOrder(ruleID, -1);
  else if (action === 'down') void changeRuleOrder(ruleID, 1);
  else if (action === 'duplicate') duplicateRule(ruleID);
  else if (action === 'delete') void deleteRule(ruleID);
  else if (action === 'select-all-filtered') {
    for (const entry of ui.rules.lastEntries) ui.rules.selected.add(entry.ruleId);
    refreshRuleSelectionDOM();
  } else if (action === 'clear-selection') {
    ui.rules.selected = new Set();
    refreshRuleSelectionDOM();
  }
}

function handleRulesTableChange(event) {
  const actionElement = event.target.closest('[data-action]');
  const row = event.target.closest('[data-rule-row]');
  if (!actionElement || !row) return;
  const ruleID = row.getAttribute('data-rule-row') || '';
  const action = actionElement.getAttribute('data-action');
  if (action === 'select') {
    if (actionElement.checked) ui.rules.selected.add(ruleID);
    else ui.rules.selected.delete(ruleID);
    refreshRuleSelectionDOM();
  } else if (action === 'toggle-enabled') {
    void toggleRule(ruleID, !!actionElement.checked);
  }
}

function setupRulesUI() {
  const tableBody = $('rules');
  if (tableBody) {
    tableBody.addEventListener('click', handleRulesTableClick);
    tableBody.addEventListener('change', handleRulesTableChange);
    tableBody.addEventListener('keydown', (event) => {
      if ((event.key === 'Enter' || event.key === ' ') && event.target.matches('[data-action="edit"]')) {
        event.preventDefault();
        const row = event.target.closest('[data-rule-row]');
        if (row) openRuleEditor(row.getAttribute('data-rule-row') || '');
      }
    });
  }
  const selectionInfo = $('rulesSelectionInfo');
  if (selectionInfo) selectionInfo.addEventListener('click', handleRulesTableClick);
  const search = $('ruleSearch');
  if (search) {
    search.addEventListener('input', () => {
      ui.rules.query = search.value || '';
      ui.rules.page = 1;
      writeStorage(sessionStorage, 'pitchprox_rule_search', ui.rules.query);
      renderRules();
      scheduleRuleActivityRefresh();
    });
    search.addEventListener('keydown', (event) => {
      if (event.key === 'Escape' && ui.rules.query) {
        event.preventDefault();
        ui.rules.query = '';
        search.value = '';
        writeStorage(sessionStorage, 'pitchprox_rule_search', '');
        ui.rules.page = 1;
        renderRules();
        scheduleRuleActivityRefresh();
      }
    });
  }
  const clearSearch = $('clearRuleSearchBtn');
  if (clearSearch) clearSearch.onclick = () => {
    ui.rules.query = '';
    writeStorage(sessionStorage, 'pitchprox_rule_search', '');
    ui.rules.page = 1;
    renderRules();
    scheduleRuleActivityRefresh();
    $('ruleSearch')?.focus();
  };
  const filter = $('ruleFilter');
  if (filter) filter.onchange = () => {
    ui.rules.filter = filter.value || 'all';
    writeStorage(sessionStorage, 'pitchprox_rule_filter', ui.rules.filter);
    ui.rules.page = 1;
    renderRules();
    scheduleRuleActivityRefresh();
  };
  const pageSize = $('rulePageSize');
  if (pageSize) pageSize.onchange = () => {
    ui.rules.pageSize = Math.max(1, Math.min(50, Number(pageSize.value) || 25));
    writeStorage(localStorage, 'pitchprox_rule_page_size', ui.rules.pageSize);
    ui.rules.page = 1;
    renderRules();
    scheduleRuleActivityRefresh();
  };
  const selectPage = $('selectPageRules');
  if (selectPage) selectPage.onchange = () => {
    const page = ui.rules.lastPage;
    if (!page) return;
    for (const entry of page.items) {
      if (selectPage.checked) ui.rules.selected.add(entry.ruleId);
      else ui.rules.selected.delete(entry.ruleId);
    }
    refreshRuleSelectionDOM();
  };
  $('ruleFirstPageBtn').onclick = () => { ui.rules.page = 1; renderRules(); scheduleRuleActivityRefresh(); };
  $('rulePrevPageBtn').onclick = () => { ui.rules.page -= 1; renderRules(); scheduleRuleActivityRefresh(); };
  $('ruleNextPageBtn').onclick = () => { ui.rules.page += 1; renderRules(); scheduleRuleActivityRefresh(); };
  $('ruleLastPageBtn').onclick = () => {
    ui.rules.page = ui.rules.lastPage?.pageCount || 1;
    renderRules();
    scheduleRuleActivityRefresh();
  };
  $('rulePageNumbers').onclick = (event) => {
    const button = event.target.closest('[data-rule-page]');
    if (!button) return;
    ui.rules.page = Number(button.getAttribute('data-rule-page')) || 1;
    renderRules();
    scheduleRuleActivityRefresh();
  };
  $('bulkEnableBtn').onclick = () => void applyBulkRuleEnabled(true);
  $('bulkDisableBtn').onclick = () => void applyBulkRuleEnabled(false);
  $('bulkDeleteBtn').onclick = () => void deleteSelectedRules();
  $('exportRulesBtn').onclick = exportRules;
  $('importRulesBtn').onclick = () => $('rulesImportFile').click();
  $('rulesImportFile').onchange = async () => {
    const input = $('rulesImportFile');
    const file = input.files?.[0];
    input.value = '';
    await handleRulesImportFile(file);
  };
  document.querySelectorAll('[data-rule-column]').forEach((checkbox) => {
    checkbox.onchange = () => {
      const column = checkbox.getAttribute('data-rule-column');
      if (checkbox.checked) ui.rules.columns.add(column);
      else ui.rules.columns.delete(column);
      writeStorage(localStorage, 'pitchprox_rule_columns', Array.from(ui.rules.columns).join(','));
      renderRuleColumnState();
      syncRuleActivityVisibility();
    };
  });
}

function moveItem(arr, from, to) {
  if (to < 0 || to >= arr.length || from === to) return;
  const [item] = arr.splice(from, 1);
  arr.splice(to, 0, item);
}

function proxyNameById(id) {
  const item = (state.proxies || []).find((p) => p.id === id);
  return item ? (item.name || item.id) : id;
}

function chainNameById(id) {
  const item = (state.chains || []).find((c) => c.id === id);
  return item ? (item.name || item.id) : id;
}

function clearRuleEditorAnalysisTimer() {
  if (ui.editorAnalysisTimer != null) {
    clearTimeout(ui.editorAnalysisTimer);
    ui.editorAnalysisTimer = null;
  }
}

function cancelRuleConditionActivity() {
  ui.editorConditionGeneration += 1;
  if (ui.editorConditionRequest) {
    ui.editorConditionRequest.abort();
    ui.editorConditionRequest = null;
  }
}

function conditionLastSeenText(value) {
  const timestamp = Date.parse(value || '');
  return Number.isFinite(timestamp) ? new Date(timestamp).toLocaleString() : 'нет данных';
}

function conditionCoverageMarkup(label, raw, dimension, kind) {
  const coverage = rulesUI.buildConditionCoverage(raw, dimension, 100, kind);
  const rows = coverage.items.map((item) => {
    let status = 'не попало в наблюдаемую выборку';
    if (item.state === 'observed') {
      const percent = Math.max(0, Math.min(100, Number(item.share || 0) * 100));
      status = `${Number(item.hits || 0).toLocaleString()} · ${percent >= 10 ? Math.round(percent) : percent.toFixed(1)}%`;
    } else if (item.state === 'zero') {
      status = '0 · нет наблюдавшихся срабатываний';
    }
    return `<div class="condition-coverage-row coverage-${escapeHtml(item.state)}"><span title="${escapeHtml(item.token)}">${escapeHtml(truncate(item.token, 46))}</span><strong>${escapeHtml(status)}</strong></div>`;
  }).join('');
  const note = coverage.omitted > 0 ? `<div class="condition-coverage-omitted">Ещё ${coverage.omitted.toLocaleString()} значений не показано</div>` : '';
  return `<section class="condition-coverage-axis"><h4>${escapeHtml(label)}</h4>${rows || '<div class="condition-coverage-omitted">Значений нет</div>'}${note}</section>`;
}

function renderRuleConditionActivity(data, rule) {
  const box = $('ed_condition_activity');
  const meta = $('ed_condition_activity_meta');
  const coverage = $('ed_condition_coverage');
  if (!box || !meta || !coverage) return;
  const conditions = Array.isArray(data?.conditions) ? data.conditions : [];
  const totalHits = Number(data?.total_hits || 0);
  const otherHits = Number(data?.other_hits || 0);
  const unattributedHits = Number(data?.unattributed_hits || 0);
  meta.textContent = `${activationCountText(totalHits)} за ${Number(data?.window_minutes || 15)} мин`;
  coverage.innerHTML = [
    conditionCoverageMarkup('Applications', rule?.applications, data?.dimensions?.applications, 'applications'),
    conditionCoverageMarkup('Hosts', rule?.target_hosts, data?.dimensions?.hosts, 'hosts'),
    conditionCoverageMarkup('Ports', rule?.target_ports, data?.dimensions?.ports, 'ports'),
  ].join('');
  if (!conditions.length) {
    box.innerHTML = totalHits > 0
      ? `<div class="condition-activity-empty">${escapeHtml(activationCountText(totalHits))} были учтены, но фактические связки не удалось атрибутировать или они не попали в ограниченную выборку.</div>`
      : '<div class="condition-activity-empty">За выбранное окно наблюдаемых срабатываний не было.</div>';
  } else {
    box.innerHTML = conditions.map((condition) => {
      const share = Math.max(0, Math.min(1, Number(condition.share || 0)));
      const percent = share * 100;
      const percentText = percent >= 10 ? Math.round(percent).toLocaleString() : percent.toFixed(percent > 0 && percent < 1 ? 1 : 0);
      const sources = [];
      if (condition.sources?.intercepted) sources.push(`перехвачено: ${Number(condition.sources.intercepted).toLocaleString()}`);
      if (condition.sources?.direct_observer) sources.push(`наблюдатель Direct: ${Number(condition.sources.direct_observer).toLocaleString()}`);
      return `
        <div class="condition-activity-row">
          <div class="condition-tuple" title="${escapeHtml(`${condition.application} → ${condition.host}:${condition.port}`)}">
            <span>${escapeHtml(truncate(condition.application, 54))}</span><b aria-hidden="true">›</b>
            <span>${escapeHtml(truncate(condition.host, 54))}</span><b aria-hidden="true">:</b>
            <span>${escapeHtml(condition.port)}</span>
          </div>
          <div class="condition-count"><strong>${Number(condition.hits || 0).toLocaleString()}</strong><span>${escapeHtml(percentText)}%</span></div>
          <div class="condition-share" role="img" aria-label="Доля ${escapeHtml(percentText)}%"><i style="width:${percent.toFixed(2)}%"></i></div>
          <div class="condition-source">${escapeHtml(sources.join(' · ') || 'источник не указан')} · последнее ${escapeHtml(conditionLastSeenText(condition.last_seen))}</div>
        </div>`;
    }).join('');
  }
  const footnotes = [];
  if (otherHits > 0) footnotes.push(`Прочие связки: ${activationCountText(otherHits)}`);
  if (unattributedHits > 0) footnotes.push(`Не удалось атрибутировать к связке: ${activationCountText(unattributedHits)} (входит в прочие)`);
  if (data?.malformed_conditions > 0) footnotes.push(`Повреждённые записи пропущены: ${Number(data.malformed_conditions).toLocaleString()}`);
  if (data?.truncated) footnotes.push('Показаны наиболее частые сочетания');
  if (data?.accuracy?.notice) footnotes.push(String(data.accuracy.notice));
  else if (data?.accuracy?.direct_complete === false) footnotes.push('Учёт Direct-соединений может быть неполным');
  if (footnotes.length) box.insertAdjacentHTML('beforeend', `<div class="condition-activity-note">${footnotes.map(escapeHtml).join(' · ')}</div>`);
}

async function loadRuleConditionActivity(ruleID, editorSession) {
  if (!ruleID || ui.webUIPaused || editorSession !== ui.editorSession || !$('editorDialog')?.open) return false;
  cancelRuleConditionActivity();
  const generation = ui.editorConditionGeneration;
  const controller = new AbortController();
  ui.editorConditionRequest = controller;
  const box = $('ed_condition_activity');
  const meta = $('ed_condition_activity_meta');
  const coverage = $('ed_condition_coverage');
  const refresh = $('ed_condition_activity_refresh');
  const windowMinutes = Math.max(1, Math.min(60, Number($('ed_condition_activity_window')?.value || 15)));
  if (box) box.innerHTML = '<div class="condition-activity-empty">Загрузка…</div>';
  if (coverage) coverage.innerHTML = '<div class="condition-activity-empty">Загрузка покрытия…</div>';
  if (meta) meta.textContent = `Окно ${windowMinutes} мин`;
  if (refresh) {
    refresh.dataset.conditionLoading = '1';
    refresh.disabled = true;
  }
  try {
    const params = new URLSearchParams({ id: ruleID, window_minutes: String(windowMinutes), limit: '20' });
    const payload = await api(`/api/rules/condition-activity?${params.toString()}`, { signal: controller.signal });
    if (generation !== ui.editorConditionGeneration || ui.editorConditionRequest !== controller || editorSession !== ui.editorSession) return false;
    const ruleIndex = findRuleIndexByID(ruleID);
    const appliedRule = ruleIndex >= 0 ? state?.rules?.[ruleIndex] : null;
    if (!appliedRule) throw new Error('Сохранённое правило больше не найдено');
    renderRuleConditionActivity(rulesUI.normalizeConditionActivity(payload, ruleID, 20), appliedRule);
    return true;
  } catch (error) {
    if (isAbortError(error) || generation !== ui.editorConditionGeneration || editorSession !== ui.editorSession) return false;
    console.error(error);
    if (box) box.innerHTML = `<div class="condition-activity-empty status-error">Не удалось загрузить детали: ${escapeHtml(error.message || String(error))}</div>`;
    if (coverage) coverage.innerHTML = '<div class="condition-activity-empty status-error">Покрытие условий недоступно.</div>';
    if (meta) meta.textContent = 'Данные недоступны';
    return false;
  } finally {
    if (ui.editorConditionRequest === controller) {
      ui.editorConditionRequest = null;
      if (refresh && editorSession === ui.editorSession) {
        delete refresh.dataset.conditionLoading;
        if (ui.editorSavingSession !== editorSession) refresh.disabled = false;
      }
    }
  }
}

function scheduleRuleEditorAnalysis(originalRuleID) {
  clearRuleEditorAnalysisTimer();
  ui.editorAnalysisTimer = setTimeout(() => {
    ui.editorAnalysisTimer = null;
    updateRuleEditorAnalysis(originalRuleID);
  }, 150);
}

function setEditorBusy(session, busy) {
  if (session !== ui.editorSession) return false;
  const dialog = $('editorDialog');
  const controls = dialog?.querySelectorAll('button, input, textarea, select') || [];
  if (busy) {
    if (ui.editorSavingSession) return false;
    ui.editorSavingSession = session;
    dialog.setAttribute('aria-busy', 'true');
    controls.forEach((control) => {
      control.dataset.editorBusyWasDisabled = control.disabled ? '1' : '0';
      control.disabled = true;
    });
    return true;
  }
  if (ui.editorSavingSession !== session) return false;
  controls.forEach((control) => {
    if (!Object.hasOwn(control.dataset, 'editorBusyWasDisabled')) return;
    control.disabled = control.dataset.editorBusyWasDisabled === '1';
    delete control.dataset.editorBusyWasDisabled;
  });
  const conditionRefresh = $('ed_condition_activity_refresh');
  if (conditionRefresh && !conditionRefresh.dataset.conditionLoading) conditionRefresh.disabled = false;
  dialog.removeAttribute('aria-busy');
  ui.editorSavingSession = 0;
  return true;
}

async function runEditorTask(session, task) {
  if (session !== ui.editorSession || !$('editorDialog')?.open) return false;
  if (ui.saving || ui.editorSavingSession || !setEditorBusy(session, true)) {
    showToast('Дождитесь завершения текущего сохранения', 'warn');
    return false;
  }
  try {
    return await task();
  } finally {
    setEditorBusy(session, false);
  }
}

function openEditor({ title, hint, bodyHTML, onSave, extraActionsHTML = '', onOpen = null }) {
  const dialog = $('editorDialog');
  if (ui.saving || ui.editorSavingSession) {
    showToast('Дождитесь завершения текущего сохранения', 'warn');
    return 0;
  }
  if (dialog.open && !closeEditor()) return 0;
  clearRuleEditorAnalysisTimer();
  const session = ui.editorSession + 1;
  ui.editorSession = session;
  $('editorTitle').textContent = title;
  $('editorHint').textContent = hint || '';
  $('editorBody').innerHTML = bodyHTML;
  $('editorExtraActions').innerHTML = extraActionsHTML || '';
  ui.editorSave = onSave;
  ui.editorDirty = false;
  dialog.showModal();
  const body = $('editorBody');
  body.oninput = (event) => { if (!event.target.closest('[data-editor-transient]')) ui.editorDirty = true; };
  body.onchange = (event) => { if (!event.target.closest('[data-editor-transient]')) ui.editorDirty = true; };
  if (typeof onOpen === 'function') onOpen(session);
  return session;
}

function closeEditor(force = false, expectedSession = null) {
  const dialog = $('editorDialog');
  if (expectedSession != null && expectedSession !== ui.editorSession) return false;
  if (!force && dialog.open && ui.editorSavingSession === ui.editorSession) {
    showToast('Сохранение ещё выполняется', 'warn');
    return false;
  }
  if (!force && dialog.open && ui.editorDirty && !confirm('Закрыть редактор и потерять несохранённые изменения?')) return false;
  if (ui.editorSavingSession === ui.editorSession) setEditorBusy(ui.editorSession, false);
  clearRuleEditorAnalysisTimer();
  cancelRuleConditionActivity();
  if (dialog.open) dialog.close();
  const body = $('editorBody');
  const extra = $('editorExtraActions');
  body.oninput = null;
  body.onchange = null;
  body.replaceChildren();
  extra.replaceChildren();
  $('editorTitle').textContent = 'Редактор';
  $('editorHint').textContent = '';
  ui.editorSave = null;
  ui.editorDirty = false;
  ui.editorSession += 1;
  ui.editorSavingSession = 0;
  return true;
}

function openSettingsEditor() {
  const src = clone({ retention_minutes: state.retention_minutes || 7, dropped_log_max_bytes: droppedLogMaxBytesFor(state), http: state.http || {}, transparent: state.transparent || {} });
  openEditor({
    title: 'Параметры',
    hint: 'Конфиг автоматически сохраняется рядом с pitchProx.exe в файл pitchProx.config.json.',
    bodyHTML: `
      <div class="editor-grid two">
        <label>Web UI listen<input id="ed_http_listen" type="text" value="${escapeHtml(src.http.listen || '127.0.0.1:18080')}"></label>
        <label>Transparent listener port<input id="ed_listener_port" type="number" min="1" max="65535" value="${escapeHtml(src.transparent.listener_port || 26001)}"></label>
      </div>
      <div class="editor-grid two">
        <label>IPv4 listener<input id="ed_ipv4_listener" type="text" value="${escapeHtml(src.transparent.ipv4_listener || '0.0.0.0')}"></label>
        <label>IPv6 listener<input id="ed_ipv6_listener" type="text" value="${escapeHtml(src.transparent.ipv6_listener || '::')}"></label>
      </div>
      <div class="editor-grid two">
        <label>Sniff bytes<input id="ed_sniff_bytes" type="number" value="${escapeHtml(src.transparent.sniff_bytes || 4096)}"></label>
        <label>Sniff timeout (ms)<input id="ed_sniff_timeout" type="number" value="${escapeHtml(src.transparent.sniff_timeout_ms || 1500)}"></label>
      </div>
      <div class="editor-grid two">
        <label>Лимит журнала «Отброшены» (МБ)
          <input id="ed_dropped_log_mb" type="number" min="1" max="1024" value="${escapeHtml(droppedLogMaxMBFor(src))}">
          <span class="hint">По умолчанию 10 МБ. При достижении лимита старые заблокированные соединения вытесняются новыми.</span>
        </label>
      </div>
      <div class="editor-grid two">
        <label>Интервал накопления (мин)
          <input id="ed_retention_minutes" type="number" min="1" max="1440" value="${escapeHtml(src.retention_minutes || 7)}">
          <span class="hint">Один и тот же интервал используется для истории соединений, графика трафика и статистики правил. Вкладка «Новые» сравнивает последнюю минуту с этим окном; окно должно быть больше минуты.</span>
        </label>
      </div>
    `,
    onSave: async (editorSession) => {
      const ok = await applyStateChange((next) => {
        next.http = next.http || {};
        next.transparent = next.transparent || {};
        next.retention_minutes = Math.max(1, Number($('ed_retention_minutes').value || 7));
        next.dropped_log_max_bytes = Math.max(1, Number($('ed_dropped_log_mb').value || 10)) * 1024 * 1024;
        next.http.listen = $('ed_http_listen').value.trim();
        next.transparent.listener_port = Number($('ed_listener_port').value || 0);
        next.transparent.ipv4_listener = $('ed_ipv4_listener').value.trim();
        next.transparent.ipv6_listener = $('ed_ipv6_listener').value.trim();
        next.transparent.sniff_bytes = Number($('ed_sniff_bytes').value || 0);
        next.transparent.sniff_timeout_ms = Number($('ed_sniff_timeout').value || 0);
      }, 'Параметры сохранены');
      if (ok) closeEditor(true, editorSession);
    },
  });
}

function openProxyEditor(target, options = {}) {
  const isDraft = !Number.isInteger(target) || !!options.isDraft;
  const idx = Number.isInteger(target) ? target : -1;
  const base = isDraft ? target : state.proxies[idx];
  const src = clone(base || makeProxyDraft());
  const originalProxyID = isDraft ? '' : String(src.id || '');
  openEditor({
    title: isDraft ? 'Новый proxy' : 'Редактирование proxy',
    hint: 'Поддерживаются HTTP CONNECT и SOCKS5.',
    bodyHTML: `
      <div class="editor-grid two">
        <label>Name<input id="ed_name" type="text" value="${escapeHtml(src.name || '')}"></label>
        <label>ID<input id="ed_id" type="text" value="${escapeHtml(src.id || '')}"></label>
      </div>
      <div class="editor-grid three align-end">
        <label>Type<select id="ed_type"><option value="http" ${src.type === 'http' ? 'selected' : ''}>HTTP CONNECT</option><option value="socks5" ${src.type === 'socks5' ? 'selected' : ''}>SOCKS5</option></select></label>
        <label>Address<input id="ed_address" type="text" value="${escapeHtml(src.address || '')}" placeholder="host:port"></label>
        <label class="editor-check"><input id="ed_enabled" type="checkbox" ${src.enabled ? 'checked' : ''}><span>Включено</span></label>
      </div>
      <div class="editor-grid two">
        <label>Username<input id="ed_username" type="text" value="${escapeHtml(src.username || '')}"></label>
        <label>Password<input id="ed_password" type="password" value="${escapeHtml(src.password || '')}"></label>
      </div>
    `,
    onSave: async (editorSession) => {
      const baseProxy = clone(src || makeProxyDraft());
      const payload = {
        ...baseProxy,
        id: $('ed_id').value.trim() || src.id || uid('proxy'),
        name: $('ed_name').value.trim(),
        type: $('ed_type').value,
        address: $('ed_address').value.trim(),
        username: $('ed_username').value,
        password: $('ed_password').value,
        enabled: $('ed_enabled').checked,
      };
      const ok = await applyStateChange((next) => {
        next.proxies = next.proxies || [];
        if (isDraft) next.proxies.push(payload);
        else {
          const currentIndex = next.proxies.findIndex((item) => ruleIDKey(item.id) === ruleIDKey(originalProxyID));
          if (currentIndex < 0) throw new Error('Прокси уже удалён или изменён в другой вкладке');
          next.proxies[currentIndex] = { ...next.proxies[currentIndex], ...payload };
        }
      }, 'Прокси сохранён');
      if (ok) closeEditor(true, editorSession);
    },
  });
}

function openChainEditor(target, options = {}) {
  const isDraft = !Number.isInteger(target) || !!options.isDraft;
  const idx = Number.isInteger(target) ? target : -1;
  const base = isDraft ? target : state.chains[idx];
  const src = clone(base || makeChainDraft());
  const originalChainID = isDraft ? '' : String(src.id || '');
  const proxyIDs = (src.proxy_ids || []).join('; ');
  openEditor({
    title: isDraft ? 'Новая chain' : 'Редактирование chain',
    hint: 'Proxy IDs перечисляются через ; в том порядке, в котором должны использоваться.',
    bodyHTML: `
      <div class="editor-grid two">
        <label>Name<input id="ed_name" type="text" value="${escapeHtml(src.name || '')}"></label>
        <label>ID<input id="ed_id" type="text" value="${escapeHtml(src.id || '')}"></label>
      </div>
      <div class="editor-grid two align-end">
        <label>Proxy IDs<input id="ed_proxy_ids" type="text" value="${escapeHtml(proxyIDs)}" placeholder="proxy_main; proxy_backup"><span class="hint">Пример: sto; backup-socks5. Допускаются ;, запятая и новая строка; порядок сохраняется.</span></label>
        <label class="editor-check"><input id="ed_enabled" type="checkbox" ${src.enabled ? 'checked' : ''}><span>Включено</span></label>
      </div>
    `,
    onSave: async (editorSession) => {
      const baseChain = clone(src || makeChainDraft());
      const payload = {
        ...baseChain,
        id: $('ed_id').value.trim() || src.id || uid('chain'),
        name: $('ed_name').value.trim(),
        proxy_ids: splitTokens($('ed_proxy_ids').value),
        enabled: $('ed_enabled').checked,
      };
      const ok = await applyStateChange((next) => {
        next.chains = next.chains || [];
        if (isDraft) next.chains.push(payload);
        else {
          const currentIndex = next.chains.findIndex((item) => ruleIDKey(item.id) === ruleIDKey(originalChainID));
          if (currentIndex < 0) throw new Error('Цепочка уже удалена или изменена в другой вкладке');
          next.chains[currentIndex] = { ...next.chains[currentIndex], ...payload };
        }
      }, 'Цепочка сохранена');
      if (ok) closeEditor(true, editorSession);
    },
  });
}

function openRuleEditor(target, options = {}) {
  const targetIsID = typeof target === 'string';
  const isDraft = !!options.isDraft || (!Number.isInteger(target) && !targetIsID);
  const idx = Number.isInteger(target) ? target : (targetIsID ? findRuleIndexByID(target) : -1);
  const base = isDraft ? target : state.rules[idx];
  const src = clone(base || makeRuleDraft());
  const originalRuleID = isDraft ? '' : String(src.id || '');
  const extraActionsHTML = isDraft ? '' : `
      <button id="editorDuplicateRuleBtn" type="button" class="rule-duplicate-btn">Дублировать</button>
      <button id="editorDeleteRuleBtn" type="button" class="rule-delete-btn">Удалить</button>
    `;
  const conditionActivityHTML = isDraft ? '' : `
      <details id="ed_condition_activity_details" class="editor-details condition-activity-details" data-editor-transient ${options.focusConditionActivity ? 'open' : ''}>
        <summary>Фактические срабатывания условий</summary>
        <div class="condition-activity-panel">
          <div class="condition-activity-head">
            <div>
              <strong>Наблюдаемая активность применённой версии правила</strong>
              <span id="ed_condition_activity_meta" class="hint">Данные загрузятся при открытии раздела</span>
              <span class="condition-saved-note">Несохранённые правки не учитываются; окно может включать предыдущую сохранённую редакцию этого ID.</span>
            </div>
            <div class="condition-activity-controls">
              <label>Окно
                <select id="ed_condition_activity_window" data-editor-transient>
                  <option value="5">5 мин</option>
                  <option value="15" selected>15 мин</option>
                  <option value="60">60 мин</option>
                </select>
              </label>
              <button id="ed_condition_activity_refresh" type="button" data-editor-transient>Обновить</button>
            </div>
          </div>
          <section class="condition-coverage-section">
            <div class="condition-subhead"><strong>Покрытие условий</strong><span>Каждое исходное значение оценивается отдельно, без построения всех комбинаций.</span></div>
            <div id="ed_condition_coverage" class="condition-coverage-grid"></div>
          </section>
          <section class="condition-combinations-section">
            <div class="condition-subhead"><strong>Частые фактические связки</strong><span>Application › host : port — одно наблюдавшееся TCP-соединение считается одним срабатыванием.</span></div>
          <div id="ed_condition_activity" class="condition-activity-list" aria-live="polite">
            <div class="condition-activity-empty">Откройте раздел, чтобы загрузить детали.</div>
          </div>
          </section>
        </div>
      </details>`;
  openEditor({
    title: isDraft ? 'Новое правило' : 'Редактирование правила',
    hint: isDraft
      ? 'Составные значения сохраняются в одном правиле и могут разделяться точкой с запятой, запятой или новой строкой.'
      : 'Изменения применяются атомарно ко всей конфигурации после нажатия «Применить».',
    bodyHTML: `
      <div class="editor-section">
        <div class="editor-section-title">Назначение правила</div>
        <div class="editor-grid rule-toggle-row">
          <label>Название<input id="ed_name" type="text" value="${escapeHtml(src.name || '')}" placeholder="Например: GitHub для рабочего проекта"></label>
          <label class="editor-check"><input id="ed_enabled" type="checkbox" ${src.enabled ? 'checked' : ''}><span>Правило включено</span></label>
        </div>
        <label class="notes-field">Комментарий / назначение<textarea id="ed_notes" placeholder="Зачем создано правило, для какой задачи или приложения">${escapeHtml(src.notes || '')}</textarea><span class="hint">Комментарий виден в таблице и участвует в поиске, но не влияет на сопоставление трафика.</span></label>
      </div>

      <div class="editor-section">
        <div class="editor-section-title">Условия совпадения</div>
        <label>Applications<textarea id="ed_apps" placeholder="Any или chrome.exe; telegram.exe">${escapeHtml(src.applications || '')}</textarea><span class="hint">Несколько приложений: iexplore.exe; "C:\\some app.exe"; fire*.exe; 12345 (PID). Кавычки сохраняют запятую или ; внутри пути.</span></label>
        <label>Target hosts<textarea id="ed_hosts" placeholder="Any или *.example.com; 10.0.0.0/8">${escapeHtml(src.target_hosts || '')}</textarea><span class="hint">Поддерживаются hostname, wildcard, IPv4/IPv6, CIDR и диапазоны IP. Элементы внутри поля объединяются как ИЛИ.</span></label>
        <label>Target ports<textarea id="ed_ports" placeholder="Any или 80; 443; 8000-9000">${escapeHtml(src.target_ports || '')}</textarea><span class="hint">Несколько портов и диапазонов сохраняются в одном правиле.</span></label>
      </div>

      <div class="editor-section">
        <div class="editor-section-title">Действие и маршрут</div>
        <div class="editor-grid three align-end">
          <label>Действие<select id="ed_action">
            <option value="direct" ${src.action === 'direct' ? 'selected' : ''}>Direct</option>
            <option value="proxy" ${src.action === 'proxy' ? 'selected' : ''}>Proxy</option>
            <option value="chain" ${src.action === 'chain' ? 'selected' : ''}>Chain</option>
            <option value="block" ${src.action === 'block' ? 'selected' : ''}>Block</option>
          </select></label>
          <label id="ed_proxy_wrap">Прокси<select id="ed_proxy_id">${selectOptions(state.proxies || [], src.proxy_id)}</select></label>
          <label id="ed_chain_wrap">Цепочка<select id="ed_chain_id">${selectOptions(state.chains || [], src.chain_id)}</select></label>
        </div>
        <div id="ed_route_hint" class="hint"></div>
      </div>

      <div class="rule-analysis">
        <div id="ed_syntax_analysis" class="analysis-box"></div>
        <div id="ed_similar_rules" class="analysis-box"></div>
      </div>

      ${conditionActivityHTML}

      <details class="editor-details">
        <summary>Дополнительно: стабильный ID правила</summary>
        <div><label>ID<input id="ed_id" type="text" value="${escapeHtml(src.id || '')}" placeholder="rule_unique_id"><span class="hint">ID используется статистикой и импортом. Меняйте его только при необходимости.</span></label></div>
      </details>
    `,
    extraActionsHTML,
    onOpen: (editorSession) => {
      syncRuleActionEditor();
      const refreshAnalysis = () => scheduleRuleEditorAnalysis(originalRuleID);
      const actionSel = $('ed_action');
      if (actionSel) actionSel.addEventListener('change', () => {
        syncRuleActionEditor();
        refreshAnalysis();
      });
      for (const id of ['ed_id', 'ed_apps', 'ed_hosts', 'ed_ports', 'ed_proxy_id', 'ed_chain_id']) {
        const field = $(id);
        if (field) field.addEventListener('input', refreshAnalysis);
        if (field) field.addEventListener('change', refreshAnalysis);
      }
      updateRuleEditorAnalysis(originalRuleID);
      if (isDraft) return;
      const activityDetails = $('ed_condition_activity_details');
      const refreshConditionActivity = () => void loadRuleConditionActivity(originalRuleID, editorSession);
      if (activityDetails) {
        activityDetails.addEventListener('toggle', () => {
          if (activityDetails.open && !activityDetails.dataset.loaded) {
            activityDetails.dataset.loaded = '1';
            refreshConditionActivity();
          }
        });
      }
      const conditionWindow = $('ed_condition_activity_window');
      if (conditionWindow) conditionWindow.addEventListener('change', refreshConditionActivity);
      const conditionRefresh = $('ed_condition_activity_refresh');
      if (conditionRefresh) conditionRefresh.onclick = refreshConditionActivity;
      if (activityDetails?.open) {
        activityDetails.dataset.loaded = '1';
        refreshConditionActivity();
        activityDetails.scrollIntoView({ block: 'nearest' });
      }
      const dupBtn = $('editorDuplicateRuleBtn');
      if (dupBtn) dupBtn.onclick = () => {
        const currentIndex = findRuleIndexByID(originalRuleID);
        const cp = collectRuleEditorPayload(currentIndex >= 0 ? state.rules[currentIndex] : src);
        cp.id = uid('rule');
        cp.name = `${cp.name || 'Rule'} (copy)`;
        if (closeEditor(true, editorSession)) {
          openRuleEditor(cp, { isDraft: true, insertAt: currentIndex >= 0 ? currentIndex + 1 : defaultRuleInsertIndex() });
        }
      };
      const delBtn = $('editorDeleteRuleBtn');
      if (delBtn) delBtn.onclick = async () => {
        if (!confirm(`Удалить правило «${src.name || src.id}»?`)) return;
        await runEditorTask(editorSession, async () => {
          const ok = await applyStateChange((next) => {
            next.rules = next.rules || [];
            const currentIndex = findRuleIndexByID(originalRuleID, next);
            if (currentIndex < 0) throw new Error('Правило уже удалено или изменено в другой вкладке');
            next.rules.splice(currentIndex, 1);
          }, 'Правило удалено');
          if (ok) closeEditor(true, editorSession);
          return ok;
        });
      };
    },
    onSave: async (editorSession) => {
      const payload = collectRuleEditorPayload(src);
      const error = validateRuleEditorPayload(payload, originalRuleID);
      if (error) {
        flashStatus(error, 'error', 6000);
        return;
      }
      const ok = await applyStateChange((next) => {
        next.rules = next.rules || [];
        if (isDraft) {
          const at = Number.isInteger(options.insertAt)
            ? Math.max(0, Math.min(options.insertAt, next.rules.length))
            : defaultRuleInsertIndex(next.rules);
          next.rules.splice(at, 0, payload);
        } else {
          const currentIndex = findRuleIndexByID(originalRuleID, next);
          if (currentIndex < 0) throw new Error('Правило уже удалено или изменено в другой вкладке');
          next.rules[currentIndex] = payload;
        }
      }, 'Правило сохранено');
      if (ok) closeEditor(true, editorSession);
    },
  });
}

function collectRuleEditorPayload(base) {
  const action = $('ed_action')?.value || 'direct';
  return {
    ...clone(base || makeRuleDraft()),
    id: $('ed_id')?.value.trim() || base?.id || uid('rule'),
    name: $('ed_name')?.value.trim() || '',
    enabled: !!$('ed_enabled')?.checked,
    applications: $('ed_apps')?.value || '',
    target_hosts: $('ed_hosts')?.value || '',
    target_ports: $('ed_ports')?.value || '',
    action,
    proxy_id: action === 'proxy' ? ($('ed_proxy_id')?.value || '') : '',
    chain_id: action === 'chain' ? ($('ed_chain_id')?.value || '') : '',
    notes: $('ed_notes')?.value || '',
  };
}

function validateRuleEditorPayload(payload, originalRuleID) {
  if (!String(payload.id || '').trim()) return 'Укажите ID правила';
  const payloadID = ruleIDKey(payload.id);
  const originalID = ruleIDKey(originalRuleID);
  const duplicate = (state?.rules || []).some((rule) => ruleIDKey(rule.id) === payloadID && ruleIDKey(rule.id) !== originalID);
  if (duplicate) return `Правило с ID «${payload.id}» уже существует`;
  if (rulesUI.hasUnclosedQuote(payload.applications) || rulesUI.hasUnclosedQuote(payload.target_hosts) || rulesUI.hasUnclosedQuote(payload.target_ports)) {
    return 'Закройте двойные кавычки в составных значениях';
  }
  if (payload.action === 'proxy' && !payload.proxy_id) return 'Выберите прокси для действия Proxy';
  if (payload.action === 'chain' && !payload.chain_id) return 'Выберите цепочку для действия Chain';
  return '';
}

function updateRuleEditorAnalysis(originalRuleID) {
  if (!$('ed_action')) return;
  const payload = collectRuleEditorPayload({});
  const warnings = rulesUI.syntaxWarnings(payload);
  const payloadID = ruleIDKey(payload.id);
  const originalID = ruleIDKey(originalRuleID);
  const duplicate = (state?.rules || []).some((rule) => ruleIDKey(rule.id) === payloadID && ruleIDKey(rule.id) !== originalID);
  if (duplicate) warnings.unshift(`ID «${payload.id}» уже используется`);
  const syntax = $('ed_syntax_analysis');
  if (syntax) {
    syntax.innerHTML = `<strong>Проверка синтаксиса</strong>${warnings.length ? `<ul>${warnings.map((warning) => `<li>${escapeHtml(warning)}</li>`).join('')}</ul>` : '<div class="analysis-ok">Ошибок не найдено. Исходный синтаксис будет сохранён.</div>'}`;
  }
  const similar = rulesUI.findSimilarRules(payload, state?.rules || [], originalRuleID, 55);
  const similarBox = $('ed_similar_rules');
  if (similarBox) {
    similarBox.innerHTML = `<strong>Возможные пересечения</strong>${similar.length ? similar.map((entry) => `<div class="similar-rule"><span>${escapeHtml(entry.rule.name || entry.rule.id)}</span><span class="similar-score">${entry.score}%</span></div>`).join('') : '<div class="analysis-ok">Похожих правил не найдено.</div>'}`;
  }
}

function syncRuleActionEditor() {
  const action = $('ed_action')?.value || 'direct';
  const proxyWrap = $('ed_proxy_wrap');
  const chainWrap = $('ed_chain_wrap');
  const proxySel = $('ed_proxy_id');
  const chainSel = $('ed_chain_id');
  const hint = $('ed_route_hint');
  const proxyActive = action === 'proxy';
  const chainActive = action === 'chain';
  if (proxySel) proxySel.disabled = !proxyActive;
  if (chainSel) chainSel.disabled = !chainActive;
  if (proxyWrap) proxyWrap.classList.toggle('field-disabled', !proxyActive);
  if (chainWrap) chainWrap.classList.toggle('field-disabled', !chainActive);
  if (hint) {
    if (proxyActive) hint.textContent = 'Action=Proxy использует только поле Proxy. Поле Chain игнорируется.';
    else if (chainActive) hint.textContent = 'Action=Chain использует только поле Chain. Сама chain — это последовательность Proxy IDs.';
    else if (action === 'block') hint.textContent = 'Action=Block блокирует соединение. Proxy и Chain не используются.';
    else hint.textContent = 'Action=Direct пропускает соединение напрямую. Proxy и Chain не используются.';
  }
}

function selectOptions(items, selected) {
  const options = ['<option value="">—</option>'];
  for (const item of items) {
    const id = item.id || '';
    const name = `${item.name || id}${item.enabled ? '' : ' (отключён)'}`;
    options.push(`<option value="${escapeHtml(id)}" ${id === selected ? 'selected' : ''} ${item.enabled || id === selected ? '' : 'disabled'}>${escapeHtml(name)}</option>`);
  }
  return options.join('');
}

function renderObservability() {
  if (ui.route === 'monitor') {
    renderFocusBar();
    renderConnectionSearch();
    renderConnectionTabs();
    renderConnections();
    renderActivity();
  } else if (ui.route === 'logs') {
    renderLogs();
  }
}

function collapseConnections(rows) {
  const groups = new Map();
  for (const c of rows) {
    const host = (c.hostname || c.original_ip || '').trim().toLowerCase();
    const ruleKey = c.rule_id || c.rule_name || '';
    const key = [c.pid || 0, c.exe_path || '', host, c.original_port || 0, ruleKey, normalizeAction(c.action)].join('');
    const seedCount = Math.max(1, Number(c.count || 0) || 1);
    const existing = groups.get(key);
    if (!existing) {
      groups.set(key, { ...c, __count: seedCount });
      continue;
    }
    existing.__count += seedCount;
    const existingTime = Date.parse(existing.last_updated_at || existing.created_at || 0) || 0;
    const currentTime = Date.parse(c.last_updated_at || c.created_at || 0) || 0;
    const merged = currentTime >= existingTime ? { ...c } : { ...existing };
    merged.__count = existing.__count;
    merged.bytes_up = Number(existing.bytes_up || 0) + Number(c.bytes_up || 0);
    merged.bytes_down = Number(existing.bytes_down || 0) + Number(c.bytes_down || 0);
    groups.set(key, merged);
  }
  return Array.from(groups.values()).sort((a, b) => {
    const ta = Date.parse(a.last_updated_at || a.created_at || 0) || 0;
    const tb = Date.parse(b.last_updated_at || b.created_at || 0) || 0;
    return tb - ta;
  });
}

function connectionsForFilter(filter = ui.connFilter) {
  if (filter === 'new') return snapshot.new_connections || [];
  return snapshot.connections || [];
}

function connectionNoveltyKey(item) {
  const app = String(item?.exe_path || '').trim().toLowerCase() || (item?.pid ? `pid:${item.pid}` : '');
  const host = String(item?.original_ip || item?.hostname || item?.host || '').trim().toLowerCase();
  const port = Number(item?.original_port || item?.port || 0);
  if (!app || !host || !port) return '';
  return `${app}\u001f${host}\u001f${port}`;
}

function newConnectionKeySet() {
  const keys = new Set();
  for (const item of snapshot.new_connections || []) {
    const app = String(item?.exe_path || '').trim().toLowerCase() || (item?.pid ? `pid:${item.pid}` : '');
    const port = Number(item?.original_port || item?.port || 0);
    if (!app || !port) continue;
    for (const rawHost of [item?.original_ip, item?.hostname, item?.host]) {
      const host = String(rawHost || '').trim().toLowerCase();
      if (host) keys.add(`${app}\u001f${host}\u001f${port}`);
    }
  }
  return keys;
}

function baseFocusedConnections(filter = ui.connFilter) {
  return connectionsForFilter(filter).filter(connectionMatchesFocus);
}

function searchedFocusedConnections(filter = ui.connFilter) {
  return baseFocusedConnections(filter).filter(connectionMatchesSearch);
}

function filteredConnections() {
  if (ui.connFilter === 'new') return searchedFocusedConnections('new');
  return searchedFocusedConnections().filter((c) => scopeMatchesFilter(c, ui.connFilter)).filter((c) => {
    if (ui.connFilter === 'proxy' || ui.connFilter === 'direct' || ui.connFilter === 'block') {
      return actionMatchesFilter(c.action, ui.connFilter);
    }
    return true;
  });
}

function filteredLogs() {
  const newKeys = ui.connFilter === 'new' ? newConnectionKeySet() : null;
  return (logEntries || []).filter((entry) => {
    if (!logMatchesFocus(entry)) return false;
    if (newKeys && !newKeys.has(connectionNoveltyKey(entry))) return false;
    if (!scopeMatchesFilter(entry, ui.connFilter)) return false;
    if (ui.connFilter === 'proxy' || ui.connFilter === 'direct' || ui.connFilter === 'block') {
      return actionMatchesFilter(entry.action, ui.connFilter);
    }
    return true;
  });
}

function renderFocusBar() {
  const bar = $('focusBar');
  if (!bar) return;
  const chips = [];
  if (ui.focus?.pid) {
    chips.push(`<span class="focus-chip"><strong>Процесс</strong><span>${escapeHtml(shortExe(ui.focus.exePath || '') || String(ui.focus.pid))} · PID ${escapeHtml(String(ui.focus.pid))}</span><button type="button" class="chip-close" data-clear="process" aria-label="Убрать фильтр по процессу">×</button></span>`);
  }
  if (ui.focus?.ruleId || ui.focus?.ruleName) {
    chips.push(`<span class="focus-chip"><strong>Правило</strong><span>${escapeHtml(ui.focus.ruleName || ui.focus.ruleId)}</span><button type="button" class="chip-close" data-clear="rule" aria-label="Убрать фильтр по правилу">×</button></span>`);
  }
  if (ui.connFilter !== 'all') {
    chips.push(`<span class="focus-chip"><strong>Режим</strong><span>${escapeHtml(actionLabel(ui.connFilter))}</span><button type="button" class="chip-close" data-clear="action" aria-label="Убрать фильтр по режиму">×</button></span>`);
  }
  if (!chips.length) {
    bar.className = 'focus-bar';
    bar.innerHTML = '';
    return;
  }
  const pidRuleBtn = ui.focus?.pid ? '<button type="button" id="createPidRuleBtn">Правило по PID</button>' : '';
  bar.className = 'focus-bar active';
  bar.innerHTML = `
    <div class="focus-chips">${chips.join('')}</div>
    <div class="focus-tools">${pidRuleBtn}<button type="button" id="clearFocusBtn">Сбросить всё</button></div>
  `;
  bar.querySelectorAll('[data-clear]').forEach((btn) => {
    btn.onclick = () => {
      const kind = btn.getAttribute('data-clear');
      if (kind === 'process') clearProcessFocus();
      else if (kind === 'rule') clearRuleFocus();
      else if (kind === 'action') clearActionFilter();
    };
  });
  const clearBtn = $('clearFocusBtn');
  if (clearBtn) clearBtn.onclick = clearFocus;
  const pidBtn = $('createPidRuleBtn');
  if (pidBtn) pidBtn.onclick = createRuleFromFocus;
}


function findRuleByID(ruleID) {
  const key = ruleIDKey(ruleID);
  return (state?.rules || []).find((r) => ruleIDKey(r.id) === key) || null;
}

function renderConnectionSearch() {
  const input = $('connectionSearch');
  const clearBtn = $('clearConnectionSearchBtn');
  if (!input || !clearBtn) return;
  if (input.value !== ui.connSearch) input.value = ui.connSearch;
  const syncClear = () => {
    const hasValue = !!String(ui.connSearch || '').trim();
    clearBtn.disabled = !hasValue;
    clearBtn.classList.toggle('visible', hasValue);
  };
  input.oninput = () => {
    ui.connSearch = input.value || '';
    sessionStorage.setItem('pitchprox_conn_search', ui.connSearch);
    syncClear();
    renderConnectionTabs();
    renderConnections();
  };
  input.onkeydown = (e) => {
    if (e.key === 'Escape') {
      if (ui.connSearch) {
        e.preventDefault();
        ui.connSearch = '';
        input.value = '';
        sessionStorage.setItem('pitchprox_conn_search', ui.connSearch);
        syncClear();
        renderConnectionTabs();
        renderConnections();
      }
    }
  };
  clearBtn.onclick = () => {
    if (!ui.connSearch) return;
    ui.connSearch = '';
    input.value = '';
    sessionStorage.setItem('pitchprox_conn_search', ui.connSearch);
    syncClear();
    renderConnectionTabs();
    renderConnections();
    input.focus();
  };
  syncClear();
}

function buildDroppedURL() {
  const params = new URLSearchParams();
  params.set('offset', String(ui.dropped.offset || 0));
  params.set('limit', String(ui.dropped.limit || 100));
  const q = String(ui.dropped.search || '').trim();
  if (q) params.set('q', q);
  return `/api/dropped?${params.toString()}`;
}

function cancelDroppedRequest() {
  ui.dropped.generation += 1;
  if (ui.dropped.request) {
    ui.dropped.request.abort();
    ui.dropped.request = null;
  }
  ui.dropped.loading = false;
}

function suspendDroppedLoading() {
  if (ui.dropped.searchTimer) {
    clearTimeout(ui.dropped.searchTimer);
    ui.dropped.searchTimer = null;
  }
  cancelDroppedRequest();
}

async function loadDropped(options = {}) {
  if (ui.route !== 'dropped' || document.hidden || ui.servicePaused || ui.webUIPaused) return false;
  if (options.resetOffset) ui.dropped.offset = 0;
  cancelDroppedRequest();
  const generation = ui.dropped.generation;
  const controller = new AbortController();
  ui.dropped.request = controller;
  ui.dropped.loading = true;
  ui.dropped.error = '';
  renderDroppedDialog();
  try {
    const data = await api(buildDroppedURL(), { signal: controller.signal });
    if (ui.dropped.request !== controller || generation !== ui.dropped.generation || ui.route !== 'dropped') return false;
    ui.dropped.items = Array.isArray(data.items) ? data.items : [];
    ui.dropped.total = Number(data.total || 0);
    ui.dropped.offset = Number(data.offset || 0);
    ui.dropped.limit = Number(data.limit || ui.dropped.limit || 100);
    ui.dropped.fileBytes = Number(data.file_bytes || 0);
    ui.dropped.maxBytes = Number(data.max_bytes || droppedLogMaxBytesFor(state));
    const visible = new Set(ui.dropped.items.map((item) => item.drop_id));
    ui.dropped.selected = new Set(Array.from(ui.dropped.selected).filter((id) => visible.has(id)));
    return true;
  } catch (e) {
    if (isAbortError(e) || generation !== ui.dropped.generation || ui.route !== 'dropped') return false;
    console.error(e);
    ui.dropped.error = e.message || String(e);
    return false;
  } finally {
    if (ui.dropped.request === controller) {
      ui.dropped.request = null;
      ui.dropped.loading = false;
      renderDroppedDialog();
    }
  }
}

function releaseRulesView() {
  ui.rules.activity = new Map();
  ui.rules.lastEntries = [];
  ui.rules.lastPage = null;
  $('rules')?.replaceChildren();
}

function releaseMonitorView() {
  snapshot.connections = [];
  snapshot.new_connections = [];
  snapshot.traffic = [];
  snapshot.traffic_totals = { up_bytes: 0, down_bytes: 0 };
  snapshot.rule_stats = [];
  $('connectionsTable')?.querySelector('tbody')?.replaceChildren();
  if ($('connectionSummary')) $('connectionSummary').textContent = '';
  $('activityStats')?.replaceChildren();
  const canvas = $('activityChart');
  if (canvas) {
    canvas.width = 0;
    canvas.height = 0;
  }
}

function releaseEditorConditionView() {
  cancelRuleConditionActivity();
  const details = $('ed_condition_activity_details');
  if (!details) return;
  details.open = false;
  delete details.dataset.loaded;
  const coverage = $('ed_condition_coverage');
  const activity = $('ed_condition_activity');
  if (coverage) coverage.replaceChildren();
  if (activity) activity.innerHTML = '<div class="condition-activity-empty">Откройте раздел, чтобы загрузить детали.</div>';
  const meta = $('ed_condition_activity_meta');
  if (meta) meta.textContent = 'Данные освобождены, пока вкладка неактивна';
}

function releaseCurrentViewForSuspension() {
  if (ui.route === 'rules') releaseRulesView();
  else if (ui.route === 'monitor') releaseMonitorView();
  else if (ui.route === 'logs') releaseLogView();
  else if (ui.route === 'dropped') closeDroppedDialog();
  releaseEditorConditionView();
  if (ui.resizeFrame != null) {
    cancelAnimationFrame(ui.resizeFrame);
    ui.resizeFrame = null;
  }
}

function scheduleDroppedLoad() {
  if (ui.dropped.searchTimer) clearTimeout(ui.dropped.searchTimer);
  cancelDroppedRequest();
  renderDroppedDialog();
  ui.dropped.searchTimer = setTimeout(() => {
    ui.dropped.searchTimer = null;
    void loadDropped({ resetOffset: true });
  }, 250);
}

function openDroppedDialog() {
  if (ui.route !== 'dropped') {
    setRoute('dropped');
    return;
  }
  ui.dropped.open = true;
  ui.dropped.offset = 0;
  ui.dropped.selected = new Set();
  renderDroppedDialog();
  void loadDropped({ resetOffset: true });
  setTimeout(() => {
    if (ui.route === 'dropped' && ui.dropped.open) $('droppedSearch')?.focus();
  }, 0);
}

function closeDroppedDialog() {
  ui.dropped.open = false;
  suspendDroppedLoading();
  ui.dropped.items = [];
  ui.dropped.total = null;
  ui.dropped.selected = new Set();
  ui.dropped.error = '';
  $('droppedTable')?.querySelector('tbody')?.replaceChildren();
}

function formatDroppedDate(ts) {
  try {
    return new Date(ts).toLocaleString();
  } catch {
    return String(ts || '');
  }
}

function droppedPageText() {
  const total = Number(ui.dropped.total || 0);
  if (!total) return '0 / 0';
  const from = Math.min(total, Number(ui.dropped.offset || 0) + 1);
  const to = Math.min(total, Number(ui.dropped.offset || 0) + Number(ui.dropped.limit || 100));
  return `${from}-${to} / ${total}`;
}

function renderDroppedDialog() {
  const panel = $('droppedPanel');
  if (!panel) return;
  const input = $('droppedSearch');
  const clearBtn = $('clearDroppedSearchBtn');
  if (input && input.value !== ui.dropped.search) input.value = ui.dropped.search;
  if (clearBtn) {
    const hasValue = !!String(ui.dropped.search || '').trim();
    clearBtn.disabled = !hasValue;
    clearBtn.classList.toggle('visible', hasValue);
  }
  renderDroppedRows();
  const meta = $('droppedMeta');
  if (meta) {
    const parts = [];
    if (ui.dropped.loading) parts.push('Загрузка...');
    else if (ui.dropped.error) parts.push(`Ошибка: ${ui.dropped.error}`);
    else parts.push(`Показано ${ui.dropped.items.length} из ${ui.dropped.total ?? 0}`);
    parts.push(`файл ${formatBytes(ui.dropped.fileBytes)} / ${formatBytes(ui.dropped.maxBytes)}`);
    if (String(ui.dropped.search || '').trim()) parts.push(`поиск: ${ui.dropped.search.trim()}`);
    meta.textContent = parts.join(' · ');
    meta.className = ui.dropped.error ? 'hint status-error' : 'hint';
  }
  const prevBtn = $('droppedPrevBtn');
  const nextBtn = $('droppedNextBtn');
  const page = $('droppedPage');
  const deleteBtn = $('droppedDeleteBtn');
  if (prevBtn) prevBtn.disabled = ui.dropped.loading || (ui.dropped.offset || 0) <= 0;
  if (nextBtn) nextBtn.disabled = ui.dropped.loading || ((ui.dropped.offset || 0) + (ui.dropped.limit || 100) >= (ui.dropped.total || 0));
  if (page) page.textContent = droppedPageText();
  if (deleteBtn) {
    const n = ui.dropped.selected.size;
    deleteBtn.disabled = ui.dropped.loading || n === 0;
    deleteBtn.textContent = n > 0 ? `Удалить выбранные (${n})` : 'Удалить выбранные';
  }
}

function renderDroppedRows() {
  const tbody = $('droppedTable')?.querySelector('tbody');
  if (!tbody) return;
  if (ui.dropped.loading && !ui.dropped.items.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">Загрузка...</td></tr>';
    return;
  }
  if (ui.dropped.error) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-state status-error">${escapeHtml(ui.dropped.error)}</td></tr>`;
    return;
  }
  if (!ui.dropped.items.length) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-state">Отброшенных соединений нет.</td></tr>';
    return;
  }
  tbody.innerHTML = ui.dropped.items.map((c) => {
    const host = c.hostname || c.original_ip || '—';
    const proc = shortExe(c.exe_path) || c.exe_path || '—';
    const fullProc = c.exe_path || proc;
    const checked = ui.dropped.selected.has(c.drop_id) ? 'checked' : '';
    return `
      <tr>
        <td title="${escapeHtml(formatDroppedDate(c.dropped_at))}">${escapeHtml(formatDroppedDate(c.dropped_at))}</td>
        <td>${escapeHtml(String(c.pid || ''))}</td>
        <td title="${escapeHtml(fullProc)}">${escapeHtml(proc)}</td>
        <td title="${escapeHtml(host)}">${escapeHtml(truncate(host, 44))}</td>
        <td>${escapeHtml(String(c.original_port || ''))}</td>
        <td title="${escapeHtml(c.rule_name || c.rule_id || '')}">${escapeHtml(truncate(c.rule_name || c.rule_id || '—', 28))}</td>
        <td><span class="action-badge ${actionBadgeClass(c.action || 'block')}">${escapeHtml(actionLabel(c.action || 'block'))}</span></td>
        <td class="dropped-check-cell"><input type="checkbox" data-drop-id="${escapeHtml(c.drop_id)}" ${checked} aria-label="Выбрать запись"></td>
      </tr>
    `;
  }).join('');
  tbody.querySelectorAll('[data-drop-id]').forEach((box) => {
    box.onchange = () => {
      const id = box.getAttribute('data-drop-id') || '';
      if (!id) return;
      if (box.checked) ui.dropped.selected.add(id);
      else ui.dropped.selected.delete(id);
      renderDroppedDialog();
    };
  });
}

async function deleteSelectedDropped() {
  const ids = Array.from(ui.dropped.selected);
  if (!ids.length || ui.route !== 'dropped') return;
  cancelDroppedRequest();
  const generation = ui.dropped.generation;
  const controller = new AbortController();
  ui.dropped.request = controller;
  ui.dropped.loading = true;
  ui.dropped.error = '';
  renderDroppedDialog();
  try {
    await api('/api/dropped', { method: 'DELETE', body: JSON.stringify({ ids }), signal: controller.signal });
    if (ui.dropped.request !== controller || generation !== ui.dropped.generation || ui.route !== 'dropped') return;
    ui.dropped.selected = new Set();
    ui.dropped.request = null;
    ui.dropped.loading = false;
    if (await loadDropped()) flashStatus('Выбранные отброшенные соединения удалены');
  } catch (e) {
    if (isAbortError(e) || generation !== ui.dropped.generation || ui.route !== 'dropped') return;
    console.error(e);
    ui.dropped.error = e.message || String(e);
  } finally {
    if (ui.dropped.request === controller) {
      ui.dropped.request = null;
      ui.dropped.loading = false;
      renderDroppedDialog();
    }
  }
}

function renderConnectionTabs() {
  const distinct = collapseConnections(searchedFocusedConnections('all'));
  const newDistinct = collapseConnections(searchedFocusedConnections('new'));
  const ruleFocused = !!(ui.focus?.ruleId || ui.focus?.ruleName);
  const inScope = ruleFocused ? distinct : distinct.filter((c) => isMatchedRuleItem(c));
  const more = ruleFocused ? [] : distinct.filter((c) => isMoreItem(c));
  const counts = { all: inScope.length, proxy: 0, direct: 0, block: 0, more: more.length, new: newDistinct.length };
  for (const c of inScope) {
    const a = normalizeAction(c.action);
    if (a === 'block') counts.block++;
    else if (a === 'direct') counts.direct++;
    else counts.proxy++;
  }
  const tabs = [
    ['new', `Новые (${counts.new})`],
    ['all', `Все (${counts.all})`],
    ['proxy', `Proxy / Chain (${counts.proxy})`],
    ['direct', `Direct (${counts.direct})`],
    ['block', `Block (${counts.block})`],
    ['more', `Ещё (${counts.more})`],
  ];
  const droppedCount = Number.isFinite(Number(ui.dropped.total)) && ui.dropped.total !== null ? ` (${ui.dropped.total})` : '';
  $('connectionTabs').innerHTML = tabs.map(([key, label]) => `<button type="button" class="tab ${ui.connFilter === key ? 'active' : ''}" data-filter="${key}">${label}</button>`).join('') +
    `<button type="button" class="tab dropped-tab" data-dropped="1">Отброшены${droppedCount}</button>`;
  $('connectionTabs').querySelectorAll('[data-filter]').forEach((btn) => {
    btn.onclick = () => {
      const next = btn.dataset.filter;
      clearRuleFocus({ render: false });
      ui.connFilter = (ui.connFilter === next) ? 'all' : next;
      sessionStorage.setItem('pitchprox_conn_filter', ui.connFilter);
      renderFocusBar();
      renderConnectionSearch();
      renderConnectionTabs();
      renderConnections();
      renderLogs();
    };
  });
  const droppedBtn = $('connectionTabs').querySelector('[data-dropped]');
  if (droppedBtn) droppedBtn.onclick = openDroppedDialog;
}

function connectionRowClass(c) {
  const classes = [];
  if (ui.connFilter === 'new') classes.push('conn-new');
  const a = normalizeAction(c.action);
  if (a === 'block') classes.push('conn-block');
  if (a === 'proxy' || a === 'chain') classes.push('conn-proxy');
  return classes.join(' ');
}

async function copyText(text) {
  const value = String(text ?? '');
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(value);
      return true;
    }
  } catch {}
  const ta = document.createElement('textarea');
  ta.value = value;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try {
    document.execCommand('copy');
    document.body.removeChild(ta);
    return true;
  } catch {
    document.body.removeChild(ta);
    return false;
  }
}

function renderConnections() {
  const rawRows = filteredConnections();
  const rows = collapseConnections(rawRows);
  const tbody = $('connectionsTable').querySelector('tbody');
  if (!rows.length) {
    if (ui.connFilter === 'new') {
      tbody.innerHTML = '<tr><td colspan="7" class="empty-state">Новых соединений в текущем окне нет.</td></tr>';
      const searchInfo = ui.connSearch.trim() ? ` · поиск: ${ui.connSearch.trim()}` : '';
      const windowWarning = newConnectionBaselineMinutes() <= newConnectionRecentMinutes() ? ' Окно истории должно быть больше минуты.' : '';
      $('connectionSummary').textContent = `Вкладка «Новые» показывает адреса, впервые появившиеся у приложения: ${newConnectionWindowText()}${searchInfo}.${windowWarning}`;
      return;
    }
    tbody.innerHTML = '<tr><td colspan="7" class="empty-state">Нет соединений в текущем фильтре.</td></tr>';
    const searchInfo = ui.connSearch.trim() ? ` · поиск: ${ui.connSearch.trim()}` : '';
    $('connectionSummary').textContent = `История соединений хранится ${formatMinutesRu()}. По умолчанию показаны соединения, попавшие под явные правила; вкладка «Ещё» показывает остальное${searchInfo}.`;
    return;
  }
  tbody.innerHTML = rows.map((c) => {
    const host = c.hostname || c.original_ip || '—';
    const proc = shortExe(c.exe_path) || c.exe_path || '—';
    const fullProc = c.exe_path || proc;
    const countBadge = c.__count > 1 ? `<span class="badge badge-muted">×${c.__count}</span>` : '';
    const rowClass = connectionRowClass(c);
    return `
      <tr class="${rowClass}">
        <td class="copy-cell" data-copy="${escapeHtml(String(c.pid || ''))}" title="PID ${escapeHtml(String(c.pid || ''))}"><span class="copy-main"><span class="copy-text">${c.pid || ''}</span><button type="button" class="copy-btn" data-copy="${escapeHtml(String(c.pid || ''))}" aria-label="Копировать PID">⧉</button></span></td>
        <td class="copy-cell" data-copy="${escapeHtml(fullProc)}" title="${escapeHtml(fullProc)}"><span class="copy-main"><span class="copy-text">${escapeHtml(proc)}</span>${countBadge}<button type="button" class="copy-btn" data-copy="${escapeHtml(fullProc)}" aria-label="Копировать путь">⧉</button></span></td>
        <td class="copy-cell" data-copy="${escapeHtml(host)}" title="${escapeHtml(host)}"><span class="copy-main"><span class="copy-text">${escapeHtml(truncate(host, 48))}</span><button type="button" class="copy-btn" data-copy="${escapeHtml(host)}" aria-label="Копировать host">⧉</button></span></td>
        <td class="copy-cell" data-copy="${escapeHtml(String(c.original_port || ''))}" title="Port ${escapeHtml(String(c.original_port || ''))}"><span class="copy-main"><span class="copy-text">${c.original_port || ''}</span><button type="button" class="copy-btn" data-copy="${escapeHtml(String(c.original_port || ''))}" aria-label="Копировать port">⧉</button></span></td>
        <td>${isMatchedRuleItem(c) ? `<button type="button" class="rule-filter-btn" data-rule-id="${escapeHtml(String(c.rule_id || ''))}" data-rule-name="${escapeHtml(String(c.rule_name || ''))}" title="Показать соединения и лог по правилу ${escapeHtml(c.rule_name || c.rule_id || '')}">${escapeHtml(truncate(c.rule_name || c.rule_id || '—', 28))}</button>` : '—'}</td>
        <td><button type="button" class="action-filter-btn" data-focus-pid="${escapeHtml(String(c.pid || ''))}" data-focus-exe="${escapeHtml(fullProc)}" data-focus-action="${escapeHtml(String(c.action || ''))}" title="Показать этот процесс и этот режим в соединениях и логе"><span class="action-badge ${actionBadgeClass(c.action)}">${escapeHtml(actionLabel(c.action))}</span></button></td>
        <td>${escapeHtml(c.state || '')}</td>
      </tr>
    `;
  }).join('');
  tbody.onclick = async (e) => {
    const focusBtn = e.target.closest('[data-focus-pid]');
    if (focusBtn) {
      setProcessFocus({
        pid: focusBtn.getAttribute('data-focus-pid'),
        exe_path: focusBtn.getAttribute('data-focus-exe') || '',
        action: focusBtn.getAttribute('data-focus-action') || '',
      }, { syncAction: true });
      return;
    }
    const ruleBtn = e.target.closest('[data-rule-id]');
    if (ruleBtn) {
      const ruleID = ruleBtn.getAttribute('data-rule-id') || '';
      if (ui.focus?.ruleId && ui.focus.ruleId === ruleID) {
        clearRuleFocus();
        return;
      }
      const rule = findRuleByID(ruleID) || {
        id: ruleID,
        name: ruleBtn.getAttribute('data-rule-name') || ruleID,
      };
      setRuleFocus(rule, { clearAction: true, scroll: false });
      return;
    }
    const target = e.target.closest('[data-copy]');
    if (!target) return;
    const value = target.getAttribute('data-copy') || '';
    if (!value) return;
    await copyText(value);
    flashStatus(`Скопировано: ${truncate(value, 64)}`);
  };
  const proxyCount = rows.filter((c) => isProxyAction(c.action)).length;
  const blockCount = rows.filter((c) => normalizeAction(c.action) === 'block').length;
  const groupedAway = Math.max(0, rawRows.length - rows.length);
  const focusText = describeFocus().join(' · ');
  const scopeLabel = ui.connFilter === 'new'
    ? newConnectionWindowText()
    : (ui.focus?.ruleId ? `правило ${ui.focus.ruleName || ui.focus.ruleId}` : (ui.connFilter === 'more' ? 'вкладка Ещё' : (ui.connFilter === 'all' ? 'явные правила' : actionLabel(ui.connFilter))));
  const searchText = ui.connSearch.trim();
  $('connectionSummary').textContent = `Показано ${rows.length}${groupedAway > 0 ? ` (сгруппировано ${groupedAway} дубл.)` : ''} · ${scopeLabel} · proxy ${proxyCount} · block ${blockCount} · история ${formatMinutesRu()}${searchText ? ` · поиск: ${searchText}` : ''}${focusText ? ` · ${focusText}` : ''}`;
}

function renderLogs(options = {}) {
  if (ui.route !== 'logs') return;
  const box = $('logs');
  const hint = $('logsHint');
  const oldTop = box.scrollTop;
  const oldHeight = box.scrollHeight;
  const nearTop = oldTop < 16;
  const items = logEntries || [];
  const lines = items.slice().reverse().map((entry) => `[${formatDateTime(entry.time)}] [${String(entry.level || '').toUpperCase()}]${logMetaText(entry)} ${entry.message}`);
  box.textContent = lines.join('\n');
  const parts = ['Лог в реальном времени', `в памяти не более ${MAX_UI_LOG_ENTRIES} записей`];
  hint.textContent = parts.join(' · ');
  if (options.toTop || nearTop) {
    box.scrollTop = 0;
    return;
  }
  const newHeight = box.scrollHeight;
  if (newHeight > oldHeight) box.scrollTop = oldTop + (newHeight - oldHeight);
}

function scheduleLogRender(options = {}) {
  if (ui.route !== 'logs' || ui.logRenderFrame != null) return;
  ui.logRenderFrame = requestAnimationFrame(() => {
    ui.logRenderFrame = null;
    renderLogs(options);
  });
}

function releaseLogView() {
  if (ui.logRenderFrame != null) {
    cancelAnimationFrame(ui.logRenderFrame);
    ui.logRenderFrame = null;
  }
  logEntries = [];
  if (snapshot && Array.isArray(snapshot.logs)) snapshot.logs = [];
  const box = $('logs');
  if (box) box.textContent = '';
  ui.logsInitialized = false;
}

function applyLogEntry(entry) {
  if (!entry) return;
  logEntries.push(entry);
  if (logEntries.length > MAX_UI_LOG_BUFFER) logEntries.splice(0, logEntries.length - MAX_UI_LOG_ENTRIES);
  scheduleLogRender();
}

function handleLiveEvent(event) {
  if (!event || !event.type) return;
  switch (event.type) {
    case 'snapshot':
      if (event.data && Array.isArray(event.data.logs)) {
        logEntries = rulesUI.mergeLogEntries(
          event.data.logs.slice(-MAX_UI_LOG_ENTRIES),
          logEntries,
          MAX_UI_LOG_ENTRIES,
        );
        ui.logsInitialized = true;
        scheduleLogRender({ toTop: true });
      }
      break;
    case 'log':
      applyLogEntry(event.data);
      break;
    case 'webui_status':
      applyWebUIStatus(event.data);
      break;
    default:
      break;
  }
}

async function backfillLiveLogs(generation, eventSource) {
  if (generation !== ui.liveGeneration || ui.route !== 'logs' || ui.events !== eventSource || document.hidden || ui.servicePaused || ui.webUIPaused) return false;
  try {
    return await loadTrackedSnapshot({
      includeLogs: true,
      forceLogs: true,
      mergeLogs: true,
      generation,
      route: 'logs',
    });
  } catch (error) {
    if (!isAbortError(error) && generation === ui.liveGeneration && ui.route === 'logs') console.error(error);
    return false;
  }
}

function startLiveEvents(generation = ui.liveGeneration) {
  if (generation !== ui.liveGeneration || !routeNeedsEvents()) return;
  ui.eventsWanted = true;
  if (document.hidden || ui.servicePaused || ui.webUIPaused) return;
  if (ui.events) {
    ui.events.close();
    ui.events = null;
  }
  if (ui.eventsRetryTimer) {
    clearTimeout(ui.eventsRetryTimer);
    ui.eventsRetryTimer = null;
  }
  const es = new EventSource('/api/events?_ui=1');
  ui.events = es;
  es.onopen = () => {
    if (ui.events !== es || generation !== ui.liveGeneration || !routeNeedsEvents()) return;
    ui.eventsRetryAttempt = 0;
    void backfillLiveLogs(generation, es);
  };
  es.onmessage = (evt) => {
    if (ui.events !== es || generation !== ui.liveGeneration || !routeNeedsEvents()) return;
    try {
      handleLiveEvent(JSON.parse(evt.data));
    } catch (e) {
      console.error(e);
    }
  };
  es.onerror = () => {
    if (ui.events === es) {
      es.close();
      ui.events = null;
      if (ui.eventsWanted && generation === ui.liveGeneration && routeNeedsEvents() && !document.hidden && !ui.servicePaused && !ui.webUIPaused) {
        const retryDelay = Math.min(30000, 1500 * (2 ** Math.min(5, ui.eventsRetryAttempt)));
        ui.eventsRetryAttempt = Math.min(5, ui.eventsRetryAttempt + 1);
        ui.eventsRetryTimer = setTimeout(() => startLiveEvents(generation), retryDelay);
      }
    }
  };
}

function stopLiveEvents() {
  ui.eventsWanted = false;
  ui.eventsRetryAttempt = 0;
  if (ui.events) {
    ui.events.close();
    ui.events = null;
  }
  if (ui.eventsRetryTimer) {
    clearTimeout(ui.eventsRetryTimer);
    ui.eventsRetryTimer = null;
  }
}

function clearSnapshotTimer() {
  if (ui.snapshotTimer) {
    clearTimeout(ui.snapshotTimer);
    ui.snapshotTimer = null;
  }
}

function stopSnapshotPolling() {
  clearSnapshotTimer();
  cancelSnapshotRequest();
}

async function postUIVisibility(active, keepalive = false) {
  if (ui.visibilityRequest) {
    ui.visibilityRequest.abort();
    ui.visibilityRequest = null;
  }
  const controller = keepalive ? null : new AbortController();
  if (controller) ui.visibilityRequest = controller;
  try {
    await fetch('/api/ui/visibility', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-PitchProx-WebUI': '1' },
      body: JSON.stringify({ active }),
      keepalive,
      ...(controller ? { signal: controller.signal } : {}),
    });
  } catch (_) {
  } finally {
    if (controller && ui.visibilityRequest === controller) ui.visibilityRequest = null;
  }
}

function leaveLiveMode(keepalive = false, notifyInactive = true) {
  ui.liveGeneration += 1;
  stopLiveEvents();
  stopSnapshotPolling();
  if (notifyInactive) void postUIVisibility(false, keepalive);
}

async function enterLiveMode(forceFullSnapshot = false) {
  const route = ui.route;
  if (!routeNeedsLive(route) || document.hidden || ui.servicePaused || ui.webUIPaused) return false;
  const generation = ui.liveGeneration + 1;
  ui.liveGeneration = generation;
  stopLiveEvents();
  stopSnapshotPolling();
  void postUIVisibility(true);
  // Subscribe before the history request so events arriving during the
  // backfill are retained by mergeLogEntries instead of falling into a gap.
  if (routeNeedsEvents(route)) startLiveEvents(generation);
  if (forceFullSnapshot && routeNeedsSnapshot(route)) {
    try {
      await loadTrackedSnapshot({
        includeLogs: false,
        generation,
        route,
      });
    } catch (error) {
      console.error(error);
    }
  }
  if (generation !== ui.liveGeneration || route !== ui.route || document.hidden || ui.servicePaused || ui.webUIPaused) return false;
  if (routeNeedsSnapshot(route)) startSnapshotPolling(generation);
  return true;
}

function buildTrafficSeries() {
  const bucketSeconds = Math.max(1, Number(snapshot?.traffic_bucket_seconds || 1));
  return (snapshot.traffic || []).map((item) => ({
    t: new Date(item.time).getTime(),
    up: Number(item.up_bytes || 0) / bucketSeconds,
    down: Number(item.down_bytes || 0) / bucketSeconds,
  })).filter((item) => Number.isFinite(item.t));
}

function renderActivityStats() {
  const series = buildTrafficSeries();
  const current = series[series.length - 1] || { up: 0, down: 0 };
  const peakRx = Math.max(0, ...series.map((x) => x.down || 0));
  const peakTx = Math.max(0, ...series.map((x) => x.up || 0));
  const windowRx = Number(snapshot?.traffic_totals?.down_bytes || 0);
  const windowTx = Number(snapshot?.traffic_totals?.up_bytes || 0);
  $('activityStats').innerHTML = `
    <div class="stat-pill stat-rx"><span>Входящий</span><strong>${escapeHtml(formatRate(current.down || 0))}</strong></div>
    <div class="stat-pill stat-tx"><span>Исходящий</span><strong>${escapeHtml(formatRate(current.up || 0))}</strong></div>
    <div class="stat-pill stat-rx"><span>Peak входящий</span><strong>${escapeHtml(formatRate(peakRx))}</strong></div>
    <div class="stat-pill stat-tx"><span>Peak исходящий</span><strong>${escapeHtml(formatRate(peakTx))}</strong></div>
    <div class="stat-pill stat-total"><span>↓ за окно</span><strong>${escapeHtml(formatBytes(windowRx))}</strong></div>
    <div class="stat-pill stat-total"><span>↑ за окно</span><strong>${escapeHtml(formatBytes(windowTx))}</strong></div>
  `;
}

function drawLine(ctx, points, color, width) {
  if (!points.length) return;
  ctx.strokeStyle = color;
  ctx.lineWidth = width;
  ctx.beginPath();
  ctx.moveTo(points[0].x, points[0].y);
  for (let i = 1; i < points.length; i++) ctx.lineTo(points[i].x, points[i].y);
  ctx.stroke();
}

function drawLegend(ctx, x, y, items) {
  ctx.font = '12px system-ui, -apple-system, Segoe UI, Roboto, sans-serif';
  items.forEach((item, idx) => {
    const yy = y + idx * 18;
    ctx.fillStyle = item.color;
    ctx.fillRect(x, yy - 8, 12, 12);
    ctx.fillStyle = '#374151';
    ctx.fillText(item.label, x + 18, yy + 2);
  });
}

function renderActivityChart() {
  const canvas = $('activityChart');
  const width = canvas.clientWidth || 720;
  const height = canvas.height || 220;
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, width, height);
  const series = buildTrafficSeries();
  if (!series.length) return;
  const padding = { top: 16, right: 18, bottom: 28, left: 64 };
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;
  const minScaleBytes = 5 * 1024;
  const maxY = Math.max(minScaleBytes, 1, ...series.flatMap((p) => [p.up || 0, p.down || 0]));
  const maxT = Date.now();
  const minT = maxT - retentionWindowMs();
  const toX = (t) => padding.left + ((t - minT) / (maxT - minT)) * chartW;
  const toY = (v) => padding.top + chartH - (v / maxY) * chartH;

  ctx.strokeStyle = '#e5e7eb';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = padding.top + (chartH / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padding.left, y);
    ctx.lineTo(width - padding.right, y);
    ctx.stroke();
  }
  ctx.strokeStyle = '#d1d5db';
  ctx.beginPath();
  ctx.moveTo(padding.left, padding.top + chartH);
  ctx.lineTo(width - padding.right, padding.top + chartH);
  ctx.stroke();

  ctx.fillStyle = '#6b7280';
  ctx.font = '12px system-ui, -apple-system, Segoe UI, Roboto, sans-serif';
  for (let i = 0; i <= 4; i++) {
    const value = (maxY / 4) * (4 - i);
    const y = padding.top + (chartH / 4) * i;
    ctx.fillText(formatBytes(value), 10, y + 4);
  }

  const rxPoints = series.map((p) => ({ x: toX(p.t), y: toY(p.down || 0) }));
  const txPoints = series.map((p) => ({ x: toX(p.t), y: toY(p.up || 0) }));
  drawLine(ctx, txPoints, '#3b82f6', 2);
  drawLine(ctx, rxPoints, '#10b981', 2.5);
  drawLegend(ctx, width - 128, 22, [
    { label: 'Входящий', color: '#10b981' },
    { label: 'Исходящий', color: '#3b82f6' },
  ]);
}

function renderActivity() {
  const hint = $('activityHint');
  if (hint) hint.textContent = `Проксируемый входящий и исходящий трафик за последние ${formatMinutesRu()}.`;
  renderActivityStats();
  renderActivityChart();
}

async function refreshSnapshot(options = { includeLogs: false }, generation = ui.liveGeneration, route = ui.route) {
  if (ui.snapshotLoading || generation !== ui.liveGeneration || route !== ui.route || !routeNeedsSnapshot(route) || document.hidden || ui.servicePaused || ui.webUIPaused) return false;
  try {
    return await loadTrackedSnapshot({ ...options, generation, route });
  } catch (e) {
    console.error(e);
    return false;
  }
}

function startSnapshotPolling(generation = ui.liveGeneration) {
  const route = ui.route;
  if (generation !== ui.liveGeneration || ui.servicePaused || ui.webUIPaused || !routeNeedsSnapshot(route) || document.hidden) return;
  clearSnapshotTimer();
  const poll = async () => {
    await refreshSnapshot({ includeLogs: false }, generation, route);
    if (generation === ui.liveGeneration && route === ui.route && !ui.servicePaused && !ui.webUIPaused && routeNeedsSnapshot(route) && !document.hidden) {
      ui.snapshotTimer = setTimeout(poll, SNAPSHOT_POLL_MS);
    }
  };
  ui.snapshotTimer = setTimeout(poll, SNAPSHOT_POLL_MS);
}

async function refreshCurrentPage() {
  if (ui.refreshing) return;
  if (ui.webUIPaused) {
    await recheckWebUIStatus();
    return;
  }
  ui.refreshing = true;
  const button = $('refreshBtn');
  if (button) button.disabled = true;
  try {
    if (ui.route === 'rules') {
      await loadConfig();
      await loadRuleActivity();
      void postUIVisibility(false);
    } else if (ui.route === 'monitor') {
      await loadTrackedSnapshot({ includeLogs: false, generation: ui.liveGeneration, route: 'monitor' });
    } else if (ui.route === 'logs') {
      await loadTrackedSnapshot({ includeLogs: true, forceLogs: true, mergeLogs: true, generation: ui.liveGeneration, route: 'logs' });
    } else if (ui.route === 'dropped') {
      await loadDropped();
    } else {
      await loadConfig();
      void postUIVisibility(false);
    }
    flashStatus('Данные обновлены');
  } catch (e) {
    console.error(e);
    flashStatus(`Ошибка обновления: ${e.message}`, 'error', 6000);
  } finally {
    ui.refreshing = false;
    if (button) button.disabled = false;
  }
}

$('settingsBtn').onclick = () => openSettingsEditor();
$('sidebarSettingsBtn').onclick = () => {
  setMobileSidebarOpen(false);
  openSettingsEditor();
};
$('refreshBtn').onclick = () => void refreshCurrentPage();
$('webUIStatusCheckBtn').onclick = () => void recheckWebUIStatus();
$('addProxyBtn').onclick = () => {
  openProxyEditor(makeProxyDraft(), { isDraft: true });
};
$('addChainBtn').onclick = () => {
  openChainEditor(makeChainDraft(), { isDraft: true });
};
$('addRuleBtn').onclick = () => {
  openRuleEditor(makeRuleDraft(), { isDraft: true, insertAt: defaultRuleInsertIndex() });
};
$('scrollLogsTopBtn').onclick = () => { $('logs').scrollTop = 0; };
setupRulesUI();
document.querySelectorAll('[data-page]').forEach((button) => {
  button.onclick = () => setRoute(button.getAttribute('data-page') || 'rules');
});
$('collapseSidebarBtn').onclick = () => {
  const collapsed = !document.body.classList.contains('sidebar-collapsed');
  document.body.classList.toggle('sidebar-collapsed', collapsed);
  writeStorage(localStorage, 'pitchprox_sidebar_collapsed', collapsed ? '1' : '0');
};
$('mobileMenuBtn').onclick = () => setMobileSidebarOpen(true);
$('mobileScrim').onclick = () => setMobileSidebarOpen(false, { restoreFocus: true });
const servicePauseToggle = $('servicePauseToggle');
if (servicePauseToggle) {
  servicePauseToggle.onchange = () => {
    void setServicePaused(servicePauseToggle.checked);
  };
}
$('droppedRefreshBtn').onclick = () => void loadDropped();
$('droppedSearch').oninput = () => {
  ui.dropped.search = $('droppedSearch').value || '';
  sessionStorage.setItem('pitchprox_dropped_search', ui.dropped.search);
  ui.dropped.selected = new Set();
  renderDroppedDialog();
  scheduleDroppedLoad();
};
$('droppedSearch').onkeydown = (e) => {
  if (e.key === 'Escape' && ui.dropped.search) {
    e.preventDefault();
    ui.dropped.search = '';
    $('droppedSearch').value = '';
    sessionStorage.setItem('pitchprox_dropped_search', ui.dropped.search);
    ui.dropped.selected = new Set();
    void loadDropped({ resetOffset: true });
  }
};
$('clearDroppedSearchBtn').onclick = () => {
  if (!ui.dropped.search) return;
  ui.dropped.search = '';
  $('droppedSearch').value = '';
  sessionStorage.setItem('pitchprox_dropped_search', ui.dropped.search);
  ui.dropped.selected = new Set();
  void loadDropped({ resetOffset: true });
  $('droppedSearch').focus();
};
$('droppedPrevBtn').onclick = () => {
  ui.dropped.offset = Math.max(0, (ui.dropped.offset || 0) - (ui.dropped.limit || 100));
  ui.dropped.selected = new Set();
  void loadDropped();
};
$('droppedNextBtn').onclick = () => {
  ui.dropped.offset = (ui.dropped.offset || 0) + (ui.dropped.limit || 100);
  ui.dropped.selected = new Set();
  void loadDropped();
};
$('droppedDeleteBtn').onclick = () => { void deleteSelectedDropped(); };
$('editorCloseBtn').onclick = () => closeEditor();
$('editorCancelBtn').onclick = () => closeEditor();
$('editorSaveBtn').onclick = async () => {
  const editorSave = ui.editorSave;
  const editorSession = ui.editorSession;
  if (typeof editorSave !== 'function') return;
  await runEditorTask(editorSession, () => editorSave(editorSession));
};
$('editorDialog').addEventListener('cancel', (e) => { e.preventDefault(); closeEditor(); });
window.addEventListener('resize', () => {
  if (ui.resizeFrame != null) return;
  ui.resizeFrame = requestAnimationFrame(() => {
    ui.resizeFrame = null;
    if (window.innerWidth > 760 && document.body.classList.contains('sidebar-open')) setMobileSidebarOpen(false);
    renderRuleColumnState();
    syncRuleActivityVisibility();
    if (ui.route === 'monitor') renderActivityChart();
  });
});
window.addEventListener('hashchange', () => setRoute(routeFromHash(), { updateHash: false }));
document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && document.body.classList.contains('sidebar-open')) {
    event.preventDefault();
    setMobileSidebarOpen(false, { restoreFocus: true });
    return;
  }
  if ($('editorDialog')?.open) return;
  if (ui.webUIPaused) return;
  if (event.repeat) return;
  const target = event.target;
  const typing = target && (target.matches('input, textarea, select') || target.isContentEditable);
  if (!typing && event.key === '/') {
    event.preventDefault();
    runAfterRoute('rules', () => $('ruleSearch')?.focus());
  }
  if (!typing && (event.ctrlKey || event.metaKey) && event.key.toLocaleLowerCase('ru') === 'n') {
    event.preventDefault();
    runAfterRoute('rules', () => openRuleEditor(makeRuleDraft(), { isDraft: true, insertAt: defaultRuleInsertIndex() }));
  }
});
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    clearWebUIIdleTimer();
    cancelWebUIStatusRequest();
    if (cancelConfigLoadRequest()) ui.configReloadOnResume = true;
    leaveLiveMode(true);
    stopRuleActivityPolling();
    suspendDroppedLoading();
    cancelPendingRouteTask();
    releaseCurrentViewForSuspension();
    return;
  }
  void (async () => {
    await loadWebUIStatus();
    if (!ui.webUIPaused) await resumeCurrentRouteLifecycle(true);
  })();
});
window.addEventListener('pagehide', () => {
  clearWebUIIdleTimer();
  cancelWebUIStatusRequest();
  if (cancelConfigLoadRequest()) ui.configReloadOnResume = true;
  cancelPendingRouteTask();
  clearToasts();
  leaveLiveMode(true);
  stopRuleActivityPolling();
  suspendDroppedLoading();
  releaseCurrentViewForSuspension();
});
window.addEventListener('pageshow', (event) => {
  if (event.persisted) {
    void (async () => {
      await loadWebUIStatus();
      if (!ui.webUIPaused) await resumeCurrentRouteLifecycle(true);
    })();
  }
});
window.addEventListener('beforeunload', (event) => {
  if (ui.editorDirty) {
    event.preventDefault();
    event.returnValue = '';
  }
});

(async function init() {
  document.body.classList.toggle('sidebar-collapsed', readStorage(localStorage, 'pitchprox_sidebar_collapsed', '0') === '1');
  ui.route = routeFromHash();
  setRoute(ui.route, { updateHash: false });
  await Promise.all([
    loadHealth().catch(() => {}),
    loadServiceStatus().catch(() => {}),
    loadWebUIStatus().catch(() => {}),
  ]);
  if (ui.webUIPaused) {
    ui.initialized = true;
    renderServicePauseToggle();
    renderWebUIStatus();
    updateStatusLine();
    return;
  }
  try {
    await loadConfig();
  } catch (e) {
    if (e.status === 503) {
      await loadWebUIStatus();
      if (ui.webUIPaused) {
        ui.initialized = true;
        renderWebUIStatus();
        updateStatusLine();
        return;
      }
    }
    console.error(e);
    const card = document.querySelector('.system-card');
    if (card) card.classList.add('error');
    if ($('systemStateText')) $('systemStateText').textContent = 'Сервис недоступен';
    flashStatus(`Не удалось загрузить конфигурацию: ${e.message}`, 'error', 7000);
    return;
  }
  ui.initialized = true;
  setRoute(ui.route, { updateHash: false });
  if (ui.servicePaused) {
    void postUIVisibility(false);
    return;
  }
  if (!routeNeedsLive()) void postUIVisibility(false);
  scheduleWebUIIdleCheck();
})();
