let state = null;
let snapshot = { connections: [], logs: [], traffic: [], traffic_totals: { up_bytes: 0, down_bytes: 0 }, rule_stats: [] };
let logEntries = [];
let ui = {
  connFilter: sessionStorage.getItem('pitchprox_conn_filter') || 'all',
  connSearch: sessionStorage.getItem('pitchprox_conn_search') || '',
  focus: { pid: null, exePath: '', ruleId: '', ruleName: '' },
  snapshotTimer: null,
  events: null,
  eventsRetryTimer: null,
  logsInitialized: false,
  editorSave: null,
  saving: false,
  statusMessage: '',
  statusTone: 'muted',
  statusTimer: null,
};

const SNAPSHOT_POLL_MS = 7000;

function retentionMinutes() {
  const n = Number(state?.retention_minutes || snapshot?.retention_minutes || 7);
  return Number.isFinite(n) && n >= 1 ? Math.round(n) : 7;
}

function retentionWindowMs() {
  return retentionMinutes() * 60 * 1000;
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

async function api(path, opts = {}) {
  const res = await fetch(path, { headers: { 'Content-Type': 'application/json' }, ...opts });
  if (!res.ok) throw new Error(await res.text());
  if (res.status === 204) return null;
  return res.json();
}

function clone(v) { return JSON.parse(JSON.stringify(v)); }
function escapeHtml(s) { return String(s ?? '').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;'); }
function shortExe(path) { const parts = String(path || '').split('\\'); return parts[parts.length - 1] || ''; }
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
  const id = String(ruleID || '').trim().toLowerCase();
  const name = String(ruleName || '').trim().toLowerCase();
  return id === 'default' || name === 'default';
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
    if (ruleID !== ui.focus.ruleId && ruleName !== String(ui.focus.ruleName || '').toLowerCase()) return false;
  }
  return true;
}
function logMatchesFocus(entry) {
  if (ui.focus?.pid && Number(entry.pid || 0) !== Number(ui.focus.pid || 0)) return false;
  if (ui.focus?.ruleId) {
    const ruleID = String(entry.rule_id || '');
    const ruleName = String(entry.rule_name || '').toLowerCase();
    if (ruleID !== ui.focus.ruleId && ruleName !== String(ui.focus.ruleName || '').toLowerCase()) return false;
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

function defaultRuleInsertIndex() {
  const rules = state.rules || [];
  const defaultIdx = rules.findIndex((r) => String(r.id || '').toLowerCase() === 'default');
  return defaultIdx >= 0 ? defaultIdx : rules.length;
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

function collectConfig() {
  return {
    version: state.version || 1,
    updated_at: state.updated_at,
    retention_minutes: retentionMinutes(),
    http: stripUIFields(state.http || {}),
    transparent: stripUIFields(state.transparent || {}),
    proxies: (state.proxies || []).map(stripUIFields),
    chains: (state.chains || []).map(stripUIFields),
    rules: (state.rules || []).map(stripUIFields),
  };
}

function captureTransientState(src) {
  const out = { proxies: new Map() };
  for (const p of (src?.proxies || [])) {
    out.proxies.set(p.id, {
      __test_target: p.__test_target,
      __test_status: p.__test_status,
      __testing: p.__testing,
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
  }
  return out;
}

async function persistConfig(successMessage = 'Сохранено') {
  const transient = captureTransientState(state);
  ui.saving = true;
  updateStatusLine();
  try {
    const saved = await api('/api/config', { method: 'PUT', body: JSON.stringify(collectConfig()) });
    state = restoreTransientState(saved, transient);
    ui.saving = false;
    renderAll();
    flashStatus(successMessage);
    return true;
  } catch (e) {
    ui.saving = false;
    updateStatusLine();
    flashStatus(`Ошибка сохранения: ${e.message}`, 'error', 6000);
    alert(`Ошибка сохранения: ${e.message}`);
    throw e;
  }
}

async function loadConfig() {
  state = await api('/api/config');
  renderAll();
}

async function loadSnapshot() {
  const data = await api('/api/snapshot');
  snapshot = data;
  if (data && data.retention_minutes && (!state || !state.retention_minutes)) {
    state = state || {};
    state.retention_minutes = Number(data.retention_minutes) || 7;
  }
  if (!ui.logsInitialized || !ui.events) {
    logEntries = Array.isArray(data.logs) ? data.logs.slice() : [];
    ui.logsInitialized = true;
  }
  renderObservability();
  renderRules();
}

function renderAll() {
  updateStatusLine();
  renderRules();
  renderProxies();
  renderChains();
  renderObservability();
  renderRules();
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
            <button type="button" data-action="test">Проверить</button>
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
      state.proxies.splice(idx, 1);
      renderProxies();
      renderRules();
      renderChains();
      await persistConfig('Прокси удалён');
    };
    row.querySelector('[data-action="test"]').onclick = async () => {
      const btn = row.querySelector('[data-action="test"]');
      const target = (proxy.__test_target || '').trim() || 'www.google.com:443';
      btn.disabled = true;
      proxy.__testing = true;
      renderProxies();
      try {
        const result = await api('/api/proxy-test', { method: 'POST', body: JSON.stringify({ proxy: stripUIFields(proxy), target }) });
        proxy.__test_status = result;
      } catch (e) {
        proxy.__test_status = { ok: false, message: e.message || String(e) };
      } finally {
        proxy.__testing = false;
        btn.disabled = false;
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
      state.chains.splice(idx, 1);
      renderChains();
      renderRules();
      await persistConfig('Цепочка удалена');
    };
    box.appendChild(row);
  });
}

function ruleStatsMap() {
  const byID = new Map();
  const byName = new Map();
  for (const item of (snapshot.rule_stats || [])) {
    if (item.rule_id) byID.set(item.rule_id, item);
    if (item.rule_name) byName.set(String(item.rule_name).toLowerCase(), item);
  }
  return { byID, byName };
}

function getRuleStats(rule, statsMaps) {
  return statsMaps.byID.get(rule.id) || statsMaps.byName.get(String(rule.name || '').toLowerCase()) || { connections: 0, up_bytes: 0, down_bytes: 0 };
}

function renderRules() {
  const box = $('rules');
  const items = state.rules || [];
  if (!items.length) {
    box.innerHTML = '<div class="empty-state">Правила ещё не добавлены.</div>';
    return;
  }
  box.innerHTML = '';
  const statsMaps = ruleStatsMap();
  items.forEach((rule, idx) => {
    const row = document.createElement('div');
    row.className = `list-row rule-card${rule.enabled ? '': ' rule-disabled'}`;
    const chips = summarizeRule(rule);
    const stat = getRuleStats(rule, statsMaps);
    row.innerHTML = `
      <div class="rule-card-shell">
        <div class="rule-side">
          <label class="rule-enable-mini ${rule.enabled ? 'rule-enable-on' : 'rule-enable-off'}" title="${rule.enabled ? 'Правило включено' : 'Правило отключено'}" aria-label="${rule.enabled ? 'Правило включено' : 'Правило отключено'}" data-stop-edit>
            <input type="checkbox" data-action="toggle-enabled" ${rule.enabled ? 'checked' : ''}>
          </label>
          <div class="move-buttons move-buttons-small move-buttons-vertical" data-stop-edit>
            <button type="button" data-action="up" aria-label="Поднять правило">↑</button>
            <button type="button" data-action="down" aria-label="Опустить правило">↓</button>
          </div>
        </div>
        <div class="rule-card-main" data-action="edit" tabindex="0" aria-label="Открыть правило ${escapeHtml(rule.name || rule.id || 'Rule')}">
          <div class="rule-card-header">
            <div class="rule-title-cluster">
              <span class="rule-name">${escapeHtml(rule.name || rule.id || 'Rule')}</span>
              <span class="badge ${actionBadgeClass(rule.action)}">${escapeHtml(actionLabel(rule.action))}</span>
              ${rule.enabled ? '' : '<span class="badge badge-disabled-alert">Отключено</span>'}
            </div>
            <div class="rule-stats">
              <button type="button" class="stat-link" data-focus-rule="${escapeHtml(rule.id || '')}" data-focus-rule-name="${escapeHtml(rule.name || '')}" data-stop-edit title="Показать соединения и лог по правилу">Соединения ${Number(stat.connections || 0)}</button>
              <button type="button" class="stat-link" data-focus-rule="${escapeHtml(rule.id || '')}" data-focus-rule-name="${escapeHtml(rule.name || '')}" data-stop-edit title="Показать соединения и лог по правилу">Вх ${escapeHtml(formatBytes(stat.down_bytes || 0))}</button>
              <button type="button" class="stat-link" data-focus-rule="${escapeHtml(rule.id || '')}" data-focus-rule-name="${escapeHtml(rule.name || '')}" data-stop-edit title="Показать соединения и лог по правилу">Исх ${escapeHtml(formatBytes(stat.up_bytes || 0))}</button>
            </div>
          </div>
          <div class="preview-lines">${chips.map((chip) => `<span class="preview-chip">${escapeHtml(chip)}</span>`).join('')}</div>
          ${rule.notes ? `<div class="rule-note">${escapeHtml(truncate(rule.notes, 140))}</div>` : ''}
        </div>
      </div>
    `;

    row.querySelectorAll('[data-focus-rule]').forEach((btn) => {
      btn.onclick = (e) => {
        e.preventDefault();
        e.stopPropagation();
        setRuleFocus(rule);
      };
    });

    const openEditorHandler = (e) => {
      if (e.target.closest('[data-stop-edit]')) return;
      openRuleEditor(idx);
    };
    const main = row.querySelector('[data-action="edit"]');
    if (main) {
      main.onclick = openEditorHandler;
      main.onkeydown = (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          openRuleEditor(idx);
        }
      };
    }

    const toggle = row.querySelector('[data-action="toggle-enabled"]');
    if (toggle) {
      toggle.onchange = async (e) => {
        e.stopPropagation();
        state.rules[idx].enabled = !!toggle.checked;
        renderRules();
        await persistConfig(state.rules[idx].enabled ? 'Правило включено' : 'Правило отключено');
      };
      toggle.onclick = (e) => e.stopPropagation();
    }

    const upBtn = row.querySelector('[data-action="up"]');
    if (upBtn) upBtn.onclick = async (e) => {
      e.preventDefault();
      e.stopPropagation();
      moveItem(state.rules, idx, idx - 1);
      renderRules();
      await persistConfig('Порядок правил обновлён');
    };

    const downBtn = row.querySelector('[data-action="down"]');
    if (downBtn) downBtn.onclick = async (e) => {
      e.preventDefault();
      e.stopPropagation();
      moveItem(state.rules, idx, idx + 1);
      renderRules();
      await persistConfig('Порядок правил обновлён');
    };

    box.appendChild(row);
  });
}

function summarizeRule(rule) {
  const parts = [];
  parts.push(truncate(`Apps: ${splitTokens(rule.applications).slice(0, 3).join('; ') || 'Any'}`, 72));
  parts.push(truncate(`Hosts: ${splitTokens(rule.target_hosts).slice(0, 3).join('; ') || 'Any'}`, 72));
  parts.push(`Ports: ${truncate(rule.target_ports || 'Any', 32)}`);
  if (rule.action === 'proxy' && rule.proxy_id) parts.push(`Proxy: ${proxyNameById(rule.proxy_id)}`);
  if (rule.action === 'chain' && rule.chain_id) parts.push(`Chain: ${chainNameById(rule.chain_id)}`);
  return parts;
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

function openEditor({ title, hint, bodyHTML, onSave, extraActionsHTML = '', onOpen = null }) {
  const dialog = $('editorDialog');
  $('editorTitle').textContent = title;
  $('editorHint').textContent = hint || '';
  $('editorBody').innerHTML = bodyHTML;
  $('editorExtraActions').innerHTML = extraActionsHTML || '';
  ui.editorSave = onSave;
  if (dialog.open) dialog.close();
  dialog.showModal();
  if (typeof onOpen === 'function') onOpen();
}

function closeEditor() {
  const dialog = $('editorDialog');
  if (dialog.open) dialog.close();
  $('editorExtraActions').innerHTML = '';
  ui.editorSave = null;
}

function openSettingsEditor() {
  const src = clone({ retention_minutes: state.retention_minutes || 7, http: state.http || {}, transparent: state.transparent || {} });
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
        <label>Интервал накопления (мин)
          <input id="ed_retention_minutes" type="number" min="1" max="1440" value="${escapeHtml(src.retention_minutes || 7)}">
          <span class="hint">Один и тот же интервал используется для истории соединений, графика трафика и статистики правил.</span>
        </label>
      </div>
    `,
    onSave: async () => {
      state.http = state.http || {};
      state.transparent = state.transparent || {};
      state.retention_minutes = Math.max(1, Number($('ed_retention_minutes').value || 7));
      state.http.listen = $('ed_http_listen').value.trim();
      state.transparent.listener_port = Number($('ed_listener_port').value || 0);
      state.transparent.ipv4_listener = $('ed_ipv4_listener').value.trim();
      state.transparent.ipv6_listener = $('ed_ipv6_listener').value.trim();
      state.transparent.sniff_bytes = Number($('ed_sniff_bytes').value || 0);
      state.transparent.sniff_timeout_ms = Number($('ed_sniff_timeout').value || 0);
      await persistConfig('Параметры сохранены');
      closeEditor();
    },
  });
}

function openProxyEditor(idx) {
  const src = clone(state.proxies[idx]);
  openEditor({
    title: 'Редактирование proxy',
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
    onSave: async () => {
      state.proxies[idx] = {
        ...state.proxies[idx],
        id: $('ed_id').value.trim() || uid('proxy'),
        name: $('ed_name').value.trim(),
        type: $('ed_type').value,
        address: $('ed_address').value.trim(),
        username: $('ed_username').value,
        password: $('ed_password').value,
        enabled: $('ed_enabled').checked,
      };
      await persistConfig('Прокси сохранён');
      closeEditor();
    },
  });
}

function openChainEditor(idx) {
  const src = clone(state.chains[idx]);
  const proxyIDs = (src.proxy_ids || []).join('; ');
  openEditor({
    title: 'Редактирование chain',
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
    onSave: async () => {
      state.chains[idx] = {
        ...state.chains[idx],
        id: $('ed_id').value.trim() || uid('chain'),
        name: $('ed_name').value.trim(),
        proxy_ids: splitTokens($('ed_proxy_ids').value),
        enabled: $('ed_enabled').checked,
      };
      await persistConfig('Цепочка сохранена');
      closeEditor();
    },
  });
}

function openRuleEditor(target, options = {}) {
  const isDraft = !Number.isInteger(target) || !!options.isDraft;
  const idx = Number.isInteger(target) ? target : -1;
  const base = isDraft ? target : state.rules[idx];
  const src = clone(base || makeRuleDraft());
  const extraActionsHTML = isDraft ? '' : `
      <button id="editorDuplicateRuleBtn" type="button" class="rule-duplicate-btn">Дублировать</button>
      <button id="editorDeleteRuleBtn" type="button" class="rule-delete-btn">Удалить</button>
    `;
  openEditor({
    title: 'Редактирование правила',
    hint: isDraft
      ? 'Новое правило ещё не сохранено. Оно появится в списке только после нажатия «Применить».'
      : 'Формат как в Proxifier: значения через ;, запятую или с новой строки; поддерживаются *, ?, диапазоны портов и IP.',
    bodyHTML: `
      <div class="editor-grid two">
        <label>Name<input id="ed_name" type="text" value="${escapeHtml(src.name || '')}"></label>
        <label>ID<input id="ed_id" type="text" value="${escapeHtml(src.id || '')}"></label>
      </div>
      <div class="editor-grid three align-end">
        <label>Action<select id="ed_action">
          <option value="direct" ${src.action === 'direct' ? 'selected' : ''}>Direct</option>
          <option value="proxy" ${src.action === 'proxy' ? 'selected' : ''}>Proxy</option>
          <option value="chain" ${src.action === 'chain' ? 'selected' : ''}>Chain</option>
          <option value="block" ${src.action === 'block' ? 'selected' : ''}>Block</option>
        </select></label>
        <label id="ed_proxy_wrap">Proxy<select id="ed_proxy_id">${selectOptions(state.proxies || [], src.proxy_id)}</select></label>
        <label id="ed_chain_wrap">Chain<select id="ed_chain_id">${selectOptions(state.chains || [], src.chain_id)}</select></label>
      </div>
      <div id="ed_route_hint" class="hint"></div>
      <div class="editor-grid rule-toggle-row">
        <label class="editor-check"><input id="ed_enabled" type="checkbox" ${src.enabled ? 'checked' : ''}><span>Включено</span></label>
        <label class="notes-field">Notes<input id="ed_notes" type="text" value="${escapeHtml(src.notes || '')}"></label>
      </div>
      <label>Applications<textarea id="ed_apps">${escapeHtml(src.applications || '')}</textarea><span class="hint">iexplore.exe; "C:\\some app.exe"; fire*.exe; "*.bin"; 12345 (PID). Можно также с новой строки.</span></label>
      <label>Target hosts<textarea id="ed_hosts">${escapeHtml(src.target_hosts || '')}</textarea><span class="hint">localhost; 127.0.0.1; *.example.com; 192.168.1.*; 10.1.0.0-10.5.255.255. Можно также с новой строки.</span></label>
      <label>Target ports<input id="ed_ports" type="text" value="${escapeHtml(src.target_ports || '')}"><span class="hint">Any; 80; 8000-9000; 3128</span></label>
    `,
    extraActionsHTML,
    onOpen: () => {
      syncRuleActionEditor();
      const actionSel = $('ed_action');
      if (actionSel) actionSel.addEventListener('change', syncRuleActionEditor);
      if (isDraft) return;
      const dupBtn = $('editorDuplicateRuleBtn');
      if (dupBtn) dupBtn.onclick = () => {
        const cp = clone(state.rules[idx] || src);
        cp.id = uid('rule');
        cp.name = `${cp.name || 'Rule'} (copy)`;
        closeEditor();
        openRuleEditor(cp, { isDraft: true, insertAt: idx + 1 });
      };
      const delBtn = $('editorDeleteRuleBtn');
      if (delBtn) delBtn.onclick = async () => {
        state.rules.splice(idx, 1);
        await persistConfig('Правило удалено');
        closeEditor();
      };
    },
    onSave: async () => {
      const action = $('ed_action').value;
      const payload = {
        ...(isDraft ? {} : state.rules[idx]),
        id: $('ed_id').value.trim() || uid('rule'),
        name: $('ed_name').value.trim(),
        enabled: $('ed_enabled').checked,
        applications: $('ed_apps').value,
        target_hosts: $('ed_hosts').value,
        target_ports: $('ed_ports').value,
        action,
        proxy_id: action === 'proxy' ? $('ed_proxy_id').value : '',
        chain_id: action === 'chain' ? $('ed_chain_id').value : '',
        notes: $('ed_notes').value,
      };
      state.rules = state.rules || [];
      if (isDraft) {
        const at = Number.isInteger(options.insertAt) ? Math.max(0, Math.min(options.insertAt, state.rules.length)) : defaultRuleInsertIndex();
        state.rules.splice(at, 0, payload);
      } else {
        state.rules[idx] = payload;
      }
      await persistConfig('Правило сохранено');
      closeEditor();
    },
  });
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
    const name = item.name || id;
    options.push(`<option value="${escapeHtml(id)}" ${id === selected ? 'selected' : ''}>${escapeHtml(name)}</option>`);
  }
  return options.join('');
}

function renderObservability() {
  renderFocusBar();
  renderConnectionSearch();
  renderConnectionTabs();
  renderConnections();
  renderLogs();
  renderActivity();
}

function collapseConnections(rows) {
  const groups = new Map();
  for (const c of rows) {
    const host = (c.hostname || c.original_ip || '').trim().toLowerCase();
    const key = [c.pid || 0, c.exe_path || '', host, c.original_port || 0, c.rule_name || '', normalizeAction(c.action)].join('');
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

function baseFocusedConnections() {
  return (snapshot.connections || []).filter(connectionMatchesFocus);
}

function searchedFocusedConnections() {
  return baseFocusedConnections().filter(connectionMatchesSearch);
}

function filteredConnections() {
  return searchedFocusedConnections().filter((c) => scopeMatchesFilter(c, ui.connFilter)).filter((c) => {
    if (ui.connFilter === 'proxy' || ui.connFilter === 'direct' || ui.connFilter === 'block') {
      return actionMatchesFilter(c.action, ui.connFilter);
    }
    return true;
  });
}

function filteredLogs() {
  return (logEntries || []).filter((entry) => {
    if (!logMatchesFocus(entry)) return false;
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
  return (state?.rules || []).find((r) => String(r.id || '') === String(ruleID || '')) || null;
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

function renderConnectionTabs() {
  const distinct = collapseConnections(searchedFocusedConnections());
  const ruleFocused = !!(ui.focus?.ruleId || ui.focus?.ruleName);
  const inScope = ruleFocused ? distinct : distinct.filter((c) => isMatchedRuleItem(c));
  const more = ruleFocused ? [] : distinct.filter((c) => isMoreItem(c));
  const counts = { all: inScope.length, proxy: 0, direct: 0, block: 0, more: more.length };
  for (const c of inScope) {
    const a = normalizeAction(c.action);
    if (a === 'block') counts.block++;
    else if (a === 'direct') counts.direct++;
    else counts.proxy++;
  }
  const tabs = [
    ['all', `Все (${counts.all})`],
    ['proxy', `Proxy / Chain (${counts.proxy})`],
    ['direct', `Direct (${counts.direct})`],
    ['block', `Block (${counts.block})`],
    ['more', `Ещё (${counts.more})`],
  ];
  $('connectionTabs').innerHTML = tabs.map(([key, label]) => `<button type="button" class="tab ${ui.connFilter === key ? 'active' : ''}" data-filter="${key}">${label}</button>`).join('');
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
}

function connectionRowClass(c) {
  const a = normalizeAction(c.action);
  if (a === 'block') return 'conn-block';
  if (a === 'proxy' || a === 'chain') return 'conn-proxy';
  return '';
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
  const scopeLabel = ui.focus?.ruleId ? `правило ${ui.focus.ruleName || ui.focus.ruleId}` : (ui.connFilter === 'more' ? 'вкладка Ещё' : (ui.connFilter === 'all' ? 'явные правила' : actionLabel(ui.connFilter))); 
  const searchText = ui.connSearch.trim();
  $('connectionSummary').textContent = `Показано ${rows.length}${groupedAway > 0 ? ` (сгруппировано ${groupedAway} дубл.)` : ''} · ${scopeLabel} · proxy ${proxyCount} · block ${blockCount} · история ${formatMinutesRu()}${searchText ? ` · поиск: ${searchText}` : ''}${focusText ? ` · ${focusText}` : ''}`;
}

function renderLogs(options = {}) {
  const box = $('logs');
  const hint = $('logsHint');
  const oldTop = box.scrollTop;
  const oldHeight = box.scrollHeight;
  const nearTop = oldTop < 16;
  const items = filteredLogs();
  const lines = items.slice().reverse().map((entry) => `[${formatDateTime(entry.time)}] [${String(entry.level || '').toUpperCase()}]${logMetaText(entry)} ${entry.message}`);
  box.textContent = lines.join('\n');
  const parts = ['Лог в реальном времени', 'до 100 последних записей на процесс'];
  if (ui.connFilter === 'more') parts.push('вкладка: Ещё');
  else if (ui.connFilter !== 'all') parts.push(`вкладка: ${actionLabel(ui.connFilter)}`);
  else parts.push('вкладка: Все по правилам');
  const focusText = describeFocus().join(' · ');
  if (focusText) parts.push(focusText);
  if (items.length !== logEntries.length) parts.push(`показано ${items.length} из ${logEntries.length}`);
  hint.textContent = parts.join(' · ');
  if (options.toTop || nearTop) {
    box.scrollTop = 0;
    return;
  }
  const newHeight = box.scrollHeight;
  if (newHeight > oldHeight) box.scrollTop = oldTop + (newHeight - oldHeight);
}

function applyLogEntry(entry) {
  if (!entry) return;
  logEntries.push(entry);
  if (logEntries.length > 10000) logEntries = logEntries.slice(logEntries.length - 10000);
  renderLogs();
}

function handleLiveEvent(event) {
  if (!event || !event.type) return;
  switch (event.type) {
    case 'snapshot':
      if (!ui.logsInitialized && event.data && Array.isArray(event.data.logs)) {
        logEntries = event.data.logs.slice();
        ui.logsInitialized = true;
        renderLogs({ toTop: true });
      }
      break;
    case 'log':
      applyLogEntry(event.data);
      break;
    default:
      break;
  }
}

function startLiveEvents() {
  if (ui.events) {
    ui.events.close();
    ui.events = null;
  }
  if (ui.eventsRetryTimer) {
    clearTimeout(ui.eventsRetryTimer);
    ui.eventsRetryTimer = null;
  }
  const es = new EventSource('/api/events');
  ui.events = es;
  es.onmessage = (evt) => {
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
      ui.eventsRetryTimer = setTimeout(() => startLiveEvents(), 1500);
    }
  };
}

function buildTrafficSeries() {
  const now = Date.now();
  const buckets = new Map((snapshot.traffic || []).map((item) => [new Date(item.time).getTime(), item]));
  const out = [];
  for (let ts = now - retentionWindowMs(); ts <= now; ts += 1000) {
    const key = Math.floor(ts / 1000) * 1000;
    const item = buckets.get(key) || { up_bytes: 0, down_bytes: 0, time: new Date(key).toISOString() };
    out.push({ t: key, up: Number(item.up_bytes || 0), down: Number(item.down_bytes || 0) });
  }
  return compressSeries(out, 120);
}

function compressSeries(series, maxPoints) {
  if (series.length <= maxPoints) return series;
  const bucketSize = Math.ceil(series.length / maxPoints);
  const out = [];
  for (let i = 0; i < series.length; i += bucketSize) {
    const chunk = series.slice(i, i + bucketSize);
    out.push({
      t: chunk[chunk.length - 1].t,
      up: chunk.reduce((sum, x) => sum + x.up, 0) / chunk.length,
      down: chunk.reduce((sum, x) => sum + x.down, 0) / chunk.length,
    });
  }
  return out;
}

function renderActivityStats() {
  const series = buildTrafficSeries();
  const current = series[series.length - 1] || { up: 0, down: 0 };
  const peakRx = Math.max(0, ...series.map((x) => x.down || 0));
  const peakTx = Math.max(0, ...series.map((x) => x.up || 0));
  const windowRx = series.reduce((sum, x) => sum + Number(x.down || 0), 0);
  const windowTx = series.reduce((sum, x) => sum + Number(x.up || 0), 0);
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
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, width, height);
  const series = buildTrafficSeries();
  if (!series.length) return;
  const padding = { top: 16, right: 18, bottom: 28, left: 64 };
  const chartW = width - padding.left - padding.right;
  const chartH = height - padding.top - padding.bottom;
  const minScaleBytes = 5 * 1024;
  const maxY = Math.max(minScaleBytes, 1, ...series.flatMap((p) => [p.up || 0, p.down || 0]));
  const minT = series[0].t;
  const maxT = Math.max(series[series.length - 1].t, minT + 1000);
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

async function refreshSnapshot() {
  try {
    await loadSnapshot();
  } catch (e) {
    console.error(e);
  }
}

function startSnapshotPolling() {
  if (ui.snapshotTimer) clearInterval(ui.snapshotTimer);
  ui.snapshotTimer = setInterval(refreshSnapshot, SNAPSHOT_POLL_MS);
}

$('settingsBtn').onclick = openSettingsEditor;
$('addProxyBtn').onclick = () => {
  state.proxies = state.proxies || [];
  state.proxies.push({ id: uid('proxy'), name: '', type: 'http', address: '', username: '', password: '', enabled: true, __test_target: 'www.google.com:443' });
  openProxyEditor(state.proxies.length - 1);
};
$('addChainBtn').onclick = () => {
  state.chains = state.chains || [];
  state.chains.push({ id: uid('chain'), name: '', proxy_ids: [], enabled: true });
  openChainEditor(state.chains.length - 1);
};
$('addRuleBtn').onclick = () => {
  openRuleEditor(makeRuleDraft(), { isDraft: true, insertAt: defaultRuleInsertIndex() });
};
$('scrollLogsTopBtn').onclick = () => { $('logs').scrollTop = 0; };
$('editorCloseBtn').onclick = closeEditor;
$('editorCancelBtn').onclick = closeEditor;
$('editorSaveBtn').onclick = async () => { if (typeof ui.editorSave === 'function') await ui.editorSave(); };
$('editorDialog').addEventListener('cancel', (e) => { e.preventDefault(); closeEditor(); });
window.addEventListener('resize', () => renderActivityChart());
window.addEventListener('beforeunload', () => {
  if (ui.events) ui.events.close();
  if (ui.eventsRetryTimer) clearTimeout(ui.eventsRetryTimer);
  if (ui.snapshotTimer) clearInterval(ui.snapshotTimer);
});

(async function init() {
  await loadConfig();
  await loadSnapshot();
  startSnapshotPolling();
  startLiveEvents();
})();
