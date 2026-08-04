'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const rulesUI = require('./dist/rules-ui.js');

function rule(overrides = {}) {
  return {
    id: 'rule-1',
    name: 'Рабочее правило',
    enabled: true,
    applications: 'chrome.exe; "C:\\Program Files\\Some, App\\app.exe"',
    target_hosts: '*.github.com; api.example.test',
    target_ports: '443; 8000-8010',
    action: 'proxy',
    proxy_id: 'office',
    chain_id: '',
    notes: 'Доступ к рабочим репозиториям',
    ...overrides,
  };
}

test('rules search uses one explicit clear control', () => {
  const markup = fs.readFileSync(path.join(__dirname, 'dist', 'index.html'), 'utf8');
  assert.match(markup, /<input id="ruleSearch" type="text"/);
  assert.doesNotMatch(markup, /<input id="ruleSearch" type="search"/);
  assert.equal((markup.match(/id="clearRuleSearchBtn"/g) || []).length, 1);
});

test('paused WebUI guidance names the exact tray action', () => {
  const markup = fs.readFileSync(path.join(__dirname, 'dist', 'index.html'), 'utf8');
  const source = fs.readFileSync(path.join(__dirname, 'dist', 'app.js'), 'utf8');

  assert.match(markup, /Выберите «Включить WebUI» в меню pitchProx/);
  assert.match(source, /Выберите «Включить WebUI» в меню pitchProx/);
  assert.doesNotMatch(markup, /Возобновите WebUI через меню pitchProx/);
  assert.doesNotMatch(source, /Возобновите WebUI через меню pitchProx/);
});

test('rules import and export open clipboard dialogs while retaining file operations', () => {
  const markup = fs.readFileSync(path.join(__dirname, 'dist', 'index.html'), 'utf8');
  const source = fs.readFileSync(path.join(__dirname, 'dist', 'app.js'), 'utf8');
  const exportStart = source.indexOf('function openRulesExportDialog()');
  const exportEnd = source.indexOf('\nfunction unresolvedImportedRule(', exportStart);
  const importStart = source.indexOf('function openRulesImportDialog()');
  const importEnd = source.indexOf('\nfunction handleRulesTableClick(', importStart);
  const exportSource = source.slice(exportStart, exportEnd);
  const importSource = source.slice(importStart, importEnd);

  assert.match(markup, /id="importRulesBtn"/);
  assert.match(markup, /id="exportRulesBtn"/);
  assert.match(source, /\$\('exportRulesBtn'\)\.onclick = openRulesExportDialog/);
  assert.match(source, /\$\('importRulesBtn'\)\.onclick = openRulesImportDialog/);
  assert.match(exportSource, /id="ed_rules_export_text"[^>]*readonly/);
  assert.match(exportSource, /saveLabel: 'Копировать всё'/);
  assert.match(exportSource, /id="ed_rules_export_file"/);
  assert.match(source, /URL\.revokeObjectURL/);
  assert.match(exportSource, /\$\('editorSaveBtn'\)\?\.focus/);
  assert.match(source, /\(openDialog \|\| document\.body\)\.appendChild\(ta\)/);
  assert.match(source, /control\.matches\('textarea\[readonly\]'\)/);
  assert.match(importSource, /id="ed_rules_import_text"/);
  assert.match(importSource, /saveLabel: 'Проверить правила'/);
  assert.match(importSource, /id="ed_rules_import_file"[^>]*type="file"/);
  assert.match(importSource, /fileInput\.value = ''/);
  assert.match(importSource, /fileReadGeneration/);
  assert.match(importSource, /textarea\.oninput = \(\) => \{\s*fileReadGeneration \+= 1;/);
  assert.match(importSource, /rulesUI\.parseImportPayload\(text\)/);
  assert.match(source, /Math\.max\(rulesUI\.MAX_IMPORT_RULES, existingRuleCount\)/);
  assert.match(source, /rulesUI\.utf8ByteLength\(body, MAX_CONFIG_BODY_BYTES\)/);
  assert.ok(exportStart >= 0 && exportEnd > exportStart && importStart >= 0 && importEnd > importStart);
});

test('existing rule editor opens condition activity before editable fields', () => {
  const source = fs.readFileSync(path.join(__dirname, 'dist', 'app.js'), 'utf8');
  const editorStart = source.indexOf('function openRuleEditor(');
  const editorEnd = source.indexOf('\nfunction collectRuleEditorPayload(', editorStart);
  const editorSource = source.slice(editorStart, editorEnd);
  const bodyStart = editorSource.indexOf('bodyHTML: `');

  assert.ok(editorStart >= 0 && editorEnd > editorStart && bodyStart >= 0);
  assert.match(editorSource, /const conditionActivityHTML = isDraft \? '' : `/);
  assert.match(editorSource, /<details id="ed_condition_activity_details"[^>]* data-editor-transient open>/);
  assert.equal((editorSource.match(/\$\{conditionActivityHTML\}/g) || []).length, 1);
  assert.ok(
    editorSource.indexOf('${conditionActivityHTML}', bodyStart) < editorSource.indexOf('Назначение правила', bodyStart),
    'condition activity must be the first rule-editor body section',
  );
});

test('rule enabled control is a single-line row after the name field', () => {
  const styles = fs.readFileSync(path.join(__dirname, 'dist', 'styles.css'), 'utf8');
  assert.match(styles, /\.editor-grid\.rule-toggle-row\{[^}]*grid-template-columns:minmax\(0,1fr\) max-content/);
  assert.match(styles, /\.rule-toggle-row \.editor-check\{[^}]*flex-direction:row;[^}]*white-space:nowrap/);
});

test('release version comparison detects upgrades, current builds, and downgrades', () => {
  assert.equal(rulesUI.compareReleaseVersions('v0.43', '0.43.0'), 0);
  assert.equal(rulesUI.compareReleaseVersions('v0.44.0', 'v0.43.9'), 1);
  assert.equal(rulesUI.compareReleaseVersions('v0.42.9', 'v0.43.0'), -1);
  assert.equal(rulesUI.compareReleaseVersions('v0.43.0', 'v0.43.0-rc.4'), 1);
  assert.equal(rulesUI.compareReleaseVersions('v0.43.0-rc.10', 'v0.43.0-rc.2'), 1);
});

test('settings updater is explicit, bounded, and releases request resources on close', () => {
  const source = fs.readFileSync(path.join(__dirname, 'dist', 'app.js'), 'utf8');
  const settingsStart = source.indexOf('function openSettingsEditor()');
  const settingsEnd = source.indexOf('\nfunction openProxyEditor(', settingsStart);
  const settingsSource = source.slice(settingsStart, settingsEnd);

  assert.ok(settingsStart >= 0 && settingsEnd > settingsStart);
  assert.match(settingsSource, /id="ed_update_check"[^>]*>Проверить обновления</);
  assert.match(settingsSource, /data-editor-transient aria-labelledby="ed_update_title"/);
  assert.match(settingsSource, /role="status" aria-live="polite"/);
  assert.match(settingsSource, /checkButton\.onclick = \(\) => void checkUpdates\(\)/);
  assert.match(settingsSource, /api\('\/api\/update\/releases'/);
  assert.match(settingsSource, /\.slice\(0, 5\)/);
  assert.match(settingsSource, /api\('\/api\/update\/install'/);
  assert.match(settingsSource, /body: JSON\.stringify\(\{ version \}\)/);
  assert.match(settingsSource, /api\('\/api\/update\/status'/);
  assert.match(settingsSource, /status\?\.downloaded_bytes/);
  assert.match(settingsSource, /status\?\.total_bytes/);
  assert.match(settingsSource, /status\?\.updated_at/);
  assert.match(settingsSource, /старше установленной[^]*confirm|confirm\(`Версия[^]*старше установленной/);
  assert.match(settingsSource, /const installable = !!release\.installable && !!version && !isCurrent/);
  assert.match(settingsSource, /isCurrent \? 'Установлена'/);
  assert.match(settingsSource, /if \(ui\.editorDirty\)/);
  assert.match(settingsSource, /встроенный модуль обновления будет недоступен/);
  assert.match(settingsSource, /lifecycle\.legacyInstall \|\| \(lifecycle\.statusWasAvailable && lifecycle\.reloadAfterInstall\)/);
  assert.match(settingsSource, /api\('\/api\/health'/);
  assert.match(settingsSource, /lifecycle\.statusFailures < 120/);
  assert.doesNotMatch(settingsSource, /setInterval\(/);
  assert.match(settingsSource, /clearTimeout\(lifecycle\.statusTimer\)/);
  assert.match(settingsSource, /lifecycle\.releasesRequest\?\.abort\(\)/);
  assert.match(settingsSource, /lifecycle\.installRequest\?\.abort\(\)/);
  assert.match(settingsSource, /lifecycle\.statusRequest\?\.abort\(\)/);
});

test('settings updater resumes an active install and confirms the running version before success', () => {
  const source = fs.readFileSync(path.join(__dirname, 'dist', 'app.js'), 'utf8');
  const settingsStart = source.indexOf('function openSettingsEditor()');
  const settingsEnd = source.indexOf('\nfunction openProxyEditor(', settingsStart);
  const settingsSource = source.slice(settingsStart, settingsEnd);
  const initialSync = settingsSource.indexOf('const syncInitialUpdateStatus = async () =>');
  const initialStatusRequest = settingsSource.indexOf("api('/api/update/status'", initialSync);
  const resume = settingsSource.indexOf('lifecycle.installing = true;', initialStatusRequest);
  const resumePoll = settingsSource.indexOf('scheduleStatusPoll(0);', resume);
  const polling = settingsSource.indexOf('const pollInstallStatus = async () =>');
  const completionHealth = settingsSource.indexOf("const health = await api('/api/health'", polling);
  const confirmedCompletion = settingsSource.indexOf('completeConfirmedInstall(status, health', completionHealth);

  assert.ok(initialSync >= 0 && initialStatusRequest > initialSync);
  assert.ok(resume > initialStatusRequest && resumePoll > resume, 'busy persisted status must resume polling');
  assert.match(settingsSource, /void syncInitialUpdateStatus\(\)/);
  assert.match(settingsSource, /targetVersion: String\(ui\.updatePendingVersion \|\| ''\)/);
  assert.match(settingsSource, /reloadAfterInstall: !!ui\.updatePendingVersion/);
  assert.ok(completionHealth > polling && confirmedCompletion > completionHealth, 'completion must follow a health check');
  assert.match(settingsSource, /if \(expectedVersion && runningVersion && !versionsEqual\(expectedVersion, runningVersion\)\)/);
  assert.match(settingsSource, /if \(expectedVersion && !runningVersion && !allowVersionless\)/);
  assert.match(settingsSource, /ui\.version = runningVersion/);
  assert.match(settingsSource, /if \(lifecycle\.reloadAfterInstall && isActive\(\)\) window\.location\.reload\(\)/);
});

test('settings updater recovers a legacy install after its status endpoint disappears', () => {
  const source = fs.readFileSync(path.join(__dirname, 'dist', 'app.js'), 'utf8');
  const settingsStart = source.indexOf('function openSettingsEditor()');
  const settingsEnd = source.indexOf('\nfunction openProxyEditor(', settingsStart);
  const settingsSource = source.slice(settingsStart, settingsEnd);
  const initialSync = settingsSource.indexOf('const syncInitialUpdateStatus = async () =>');
  const initialCatch = settingsSource.indexOf('} catch (error) {', initialSync);
  const legacyFallback = settingsSource.indexOf('if (lifecycle.legacyInstall && lifecycle.targetVersion)', initialCatch);
  const healthRequest = settingsSource.indexOf("api('/api/health'", legacyFallback);
  const versionlessConfirmation = settingsSource.indexOf('allowVersionless: true, notify: false', healthRequest);
  const resumeAfterFailure = settingsSource.indexOf('if (lifecycle.reloadAfterInstall)', versionlessConfirmation);

  assert.ok(initialSync >= 0 && initialCatch > initialSync);
  assert.ok(legacyFallback > initialCatch && healthRequest > legacyFallback);
  assert.ok(versionlessConfirmation > healthRequest, 'known legacy releases may confirm via versionless health');
  assert.ok(resumeAfterFailure > versionlessConfirmation, 'temporarily unavailable legacy service must keep polling');
  assert.match(settingsSource.slice(resumeAfterFailure), /lifecycle\.installing = true;[^]*scheduleStatusPoll\(1500\);/);
});

test('settings updater reloads a stale page after a completed external update', () => {
  const source = fs.readFileSync(path.join(__dirname, 'dist', 'app.js'), 'utf8');
  const settingsStart = source.indexOf('function openSettingsEditor()');
  const settingsEnd = source.indexOf('\nfunction openProxyEditor(', settingsStart);
  const settingsSource = source.slice(settingsStart, settingsEnd);
  const completion = settingsSource.indexOf('const completeConfirmedInstall =');
  const comparePageVersion = settingsSource.indexOf('!versionsEqual(confirmedVersion, pageVersion)', completion);
  const enableReload = settingsSource.indexOf('lifecycle.reloadAfterInstall = true;', comparePageVersion);
  const adoptVersion = settingsSource.indexOf('adoptRunningVersion(runningVersion)', enableReload);
  const reload = settingsSource.indexOf('window.location.reload()', adoptVersion);

  assert.ok(completion >= 0 && comparePageVersion > completion);
  assert.ok(enableReload > comparePageVersion && adoptVersion > enableReload);
  assert.ok(reload > adoptVersion, 'a stale bundle must reload only after the running version is confirmed');
});

test('splitValues preserves delimiters inside quoted values', () => {
  assert.deepEqual(
    rulesUI.splitValues('firefox.exe; "C:\\Some, App\\app.exe"\ntelegram.exe'),
    ['firefox.exe', 'C:\\Some, App\\app.exe', 'telegram.exe'],
  );
  assert.equal(rulesUI.hasUnclosedQuote('"broken.exe'), true);
});

test('search uses AND tokens across all rule fields and route label', () => {
  const rules = [rule(), rule({ id: 'rule-2', name: 'Видео', applications: 'vlc.exe', notes: '' })];
  const found = rulesUI.filterRules(rules, {
    query: 'chrome github репозиториям office',
    filter: 'all',
    routeLabel: (item) => item.proxy_id === 'office' ? 'Офисный proxy' : '',
  });
  assert.deepEqual(found.map((entry) => entry.ruleId), ['rule-1']);
  assert.equal(rulesUI.filterRules(rules, { query: 'some, app', filter: 'proxy' }).length, 1);
});

test('filter and pagination preserve global indexes', () => {
  const rules = Array.from({ length: 74 }, (_, index) => rule({
    id: `rule-${index + 1}`,
    enabled: index % 2 === 0,
    action: index % 3 === 0 ? 'direct' : 'proxy',
  }));
  const filtered = rulesUI.filterRules(rules, { filter: 'disabled' });
  const page = rulesUI.paginate(filtered, 2, 25);
  assert.equal(filtered.length, 37);
  assert.equal(page.page, 2);
  assert.equal(page.items[0].originalIndex, 51);
  assert.equal(page.items.length, 12);
});

test('filtering skips search-index construction when the query is empty', () => {
  let routeLabelCalls = 0;
  const rules = [rule(), rule({ id: 'direct', action: 'direct', proxy_id: '' })];
  const filtered = rulesUI.filterRules(rules, {
    query: '',
    filter: 'all',
    routeLabel: () => {
      routeLabelCalls += 1;
      return 'route';
    },
  });
  assert.equal(routeLabelCalls, 0);
  assert.equal(Object.hasOwn(filtered[0], 'searchText'), false);
});

test('similarity detects exact routing criteria and excludes current rule', () => {
  const source = rule();
  const similar = rulesUI.findSimilarRules(source, [source, rule({ id: 'copy', name: 'Копия' })], source.id);
  assert.equal(similar.length, 1);
  assert.equal(similar[0].score, 100);
  assert.equal(similar[0].rule.id, 'copy');
});

test('criteria fingerprints match exact similarity semantics in linear-time import checks', () => {
  const source = rule({
    applications: 'chrome.exe; FIREFOX.EXE',
    target_hosts: '*.example.test; API.EXAMPLE.TEST',
    target_ports: '443; 80',
  });
  const reordered = rule({
    id: 'other',
    applications: 'firefox.exe, CHROME.EXE',
    target_hosts: 'api.example.test, *.EXAMPLE.TEST',
    target_ports: '80,443',
    proxy_id: 'office',
  });
  assert.equal(rulesUI.ruleSimilarity(source, reordered), 100);
  assert.equal(rulesUI.ruleCriteriaFingerprint(source), rulesUI.ruleCriteriaFingerprint(reordered));
  assert.notEqual(
    rulesUI.ruleCriteriaFingerprint(source),
    rulesUI.ruleCriteriaFingerprint({ ...reordered, target_ports: '80' }),
  );
  const differentlyCasedRoute = { ...reordered, proxy_id: 'Office' };
  assert.equal(rulesUI.ruleSimilarity(source, differentlyCasedRoute), 95);
  assert.notEqual(rulesUI.ruleCriteriaFingerprint(source), rulesUI.ruleCriteriaFingerprint(differentlyCasedRoute));
});

test('host wildcard remains distinct from unconditional Any', () => {
  const anyHost = rule({ target_hosts: 'Any' });
  const wildcardHost = rule({ id: 'wildcard', target_hosts: '*' });
  assert.equal(rulesUI.ruleSimilarity(anyHost, wildcardHost), 65);
  assert.notEqual(
    rulesUI.ruleCriteriaFingerprint(anyHost),
    rulesUI.ruleCriteriaFingerprint(wildcardHost),
  );
  assert.deepEqual(
    rulesUI.syntaxWarnings(rule({ target_hosts: '*; 10.0.0.1' })),
    [],
  );
});

test('syntax warnings report unclosed quotes and redundant Any', () => {
  const warnings = rulesUI.syntaxWarnings(rule({
    applications: 'Any; chrome.exe',
    target_hosts: '"broken.example',
  }));
  assert.equal(warnings.length, 2);
  assert.match(warnings[0], /Any/);
  assert.match(warnings[1], /кавычка/);
});

test('condition activity adapter bounds and normalizes backend data', () => {
  const normalized = rulesUI.normalizeConditionActivity({
    generated_at: '2026-08-04T12:00:00Z',
    rule_id: 'rule-1',
    window_minutes: 90,
    total_hits: 8,
    other_hits: 2,
    unattributed_hits: 1,
    truncated: false,
    accuracy: { scope: 'intercepted+direct', direct_complete: false, notice: 'Direct данные неполные' },
    dimensions: {
      applications: { total_hits: 8, other_hits: 0, truncated: false, values: [{ value: 'chrome.exe', hits: 6, share: 0.75 }] },
      hosts: { total_hits: 8, other_hits: 3, truncated: true, values: [{ value: '*.example.test', hits: 5, share: 0.625 }] },
      ports: { total_hits: 8, other_hits: 0, truncated: false, values: [{ value: '443', hits: 6, share: 0.75 }] },
    },
    conditions: [
      { application: 'chrome.exe', host: '*.example.test', port: 443, hits: 6, share: 1.5, last_seen: '2026-08-04T11:59:00Z', sources: { intercepted: 4, direct_observer: 2 } },
      null,
    ],
  }, 'rule-1', 20);
  assert.equal(normalized.window_minutes, 60);
  assert.equal(normalized.conditions.length, 1);
  assert.deepEqual(normalized.conditions[0], {
    application: 'chrome.exe',
    host: '*.example.test',
    port: '443',
    hits: 6,
    share: 1,
    last_seen: '2026-08-04T11:59:00Z',
    sources: { intercepted: 4, direct_observer: 2 },
  });
  assert.equal(normalized.accuracy.direct_complete, false);
  assert.equal(normalized.unattributed_hits, 1);
  assert.equal(normalized.malformed_conditions, 1);
  assert.equal(normalized.truncated, true);
  assert.equal(normalized.dimensions.applications.values[0].value, 'chrome.exe');
  assert.equal(normalized.dimensions.hosts.truncated, true);
  assert.throws(
    () => rulesUI.normalizeConditionActivity({ rule_id: 'another-rule' }, 'rule-1'),
    /другого правила/,
  );

  const malformed = rulesUI.normalizeConditionActivity({
    rule_id: 'rule-1',
    conditions: [
      { host: 'example.test', port: '443', hits: 2 },
      { application: 'app.exe', port: '443', hits: 2 },
      { application: 'app.exe', host: 'example.test', hits: 2 },
    ],
  }, 'rule-1');
  assert.deepEqual(malformed.conditions, []);
  assert.equal(malformed.malformed_conditions, 3);
  assert.equal(malformed.truncated, true);
});

test('condition coverage only reports exact zero for a complete marginal dimension', () => {
  const complete = rulesUI.buildConditionCoverage('chrome.exe; firefox.exe', {
    available: true,
    truncated: false,
    values: [{ value: 'chrome.exe', hits: 4, share: 1, last_seen: '', sources: {} }],
  });
  assert.deepEqual(complete.items.map((item) => [item.token, item.state, item.hits]), [
    ['chrome.exe', 'observed', 4],
    ['firefox.exe', 'zero', 0],
  ]);

  const truncated = rulesUI.buildConditionCoverage('chrome.exe; firefox.exe', {
    available: true,
    truncated: true,
    values: [{ value: 'chrome.exe', hits: 4, share: 1, last_seen: '', sources: {} }],
  });
  assert.equal(truncated.items[1].state, 'unknown');
  assert.equal(truncated.items[1].hits, null);

  const unavailable = rulesUI.buildConditionCoverage('Any', { available: false, truncated: false, values: [] });
  assert.equal(unavailable.items[0].state, 'unknown');

  for (const [raw, observed] of [['*', 'Any'], ['Any', '*']]) {
    const unconditionalApp = rulesUI.buildConditionCoverage(raw, {
      available: true,
      truncated: false,
      values: [{ value: observed, hits: 3, share: 1, last_seen: '', sources: {} }],
    }, 20, 'applications');
    assert.equal(unconditionalApp.items[0].state, 'observed');
    assert.equal(unconditionalApp.items[0].hits, 3);
  }
  const hostWildcard = rulesUI.buildConditionCoverage('*', {
    available: true,
    truncated: false,
    values: [{ value: 'Any', hits: 3, share: 1, last_seen: '', sources: {} }],
  }, 20, 'hosts');
  assert.equal(hostWildcard.items[0].state, 'zero');

  const canonicalApp = rulesUI.buildConditionCoverage('C:/Program Files/App.EXE', {
    available: true,
    truncated: false,
    values: [{ value: 'c:\\program files\\app.exe', hits: 2, share: 1, last_seen: '', sources: {} }],
  }, 20, 'applications');
  assert.equal(canonicalApp.items[0].state, 'observed');
});

test('WebUI status keeps full service pause separate from WebUI idle pause', () => {
  assert.deepEqual(rulesUI.normalizeWebUIStatus({ enabled: false, paused: true, auto_paused: true }), {
    servicePaused: true,
    webUIEnabled: false,
    webUIPaused: false,
    webUIAutoPaused: false,
    disabledReason: '',
    idleDeadlineAt: '',
    idleTimeoutSeconds: 3600,
  });
  const idle = rulesUI.normalizeWebUIStatus({ enabled: false, paused: false, auto_paused: true, disabled_reason: 'idle' });
  assert.equal(idle.servicePaused, false);
  assert.equal(idle.webUIPaused, true);
  assert.equal(idle.webUIAutoPaused, true);
});

test('expired WebUI deadline uses bounded backoff after repeated status checks', (t) => {
  t.mock.timers.enable({ apis: ['Date'], now: new Date('2026-08-04T12:00:00Z') });
  const expired = '2026-08-04T11:59:00Z';
  assert.equal(rulesUI.nextWebUIIdleDelay(expired, Date.now(), 0, false), 0);
  assert.equal(rulesUI.nextWebUIIdleDelay(expired, Date.now(), 1, true), 30000);
  assert.equal(rulesUI.nextWebUIIdleDelay(expired, Date.now(), 2, true), 60000);
  assert.equal(rulesUI.nextWebUIIdleDelay(expired, Date.now(), 20, true), 300000);
  t.mock.timers.tick(60000);
  assert.equal(rulesUI.nextWebUIIdleDelay('2026-08-04T12:03:00Z', Date.now(), 0, false), 120250);
});

test('versioned import preserves raw multi-value strings', () => {
  const source = rule();
  const parsed = rulesUI.parseImportPayload(JSON.stringify({
    format: 'pitchprox.rules',
    version: 1,
    rules: [source],
  }));
  assert.deepEqual(parsed.errors, []);
  assert.equal(parsed.rules[0].applications, source.applications);
  assert.equal(parsed.rules[0].target_ports, '443; 8000-8010');
});

test('clipboard export text round-trips Unicode and raw multi-value syntax', () => {
  const source = rule({
    name: 'Рабочее правило',
    notes: 'Перенос между машинами через буфер обмена',
    applications: 'chrome.exe; "C:\\Some App\\app.exe"',
    target_hosts: '*.пример.рф; api.example.com',
    target_ports: '443; 8000-8010',
  });
  const text = rulesUI.stringifyExportPayload([source], '2026-08-04T12:00:00.000Z');
  assert.equal(text.endsWith('\n'), true);
  const parsed = rulesUI.parseImportPayload(text);
  assert.deepEqual(parsed.errors, []);
  assert.deepEqual(parsed.rules, [source]);
  assert.deepEqual(rulesUI.parseImportPayload(`\uFEFF${text}`).rules, [source]);
});

test('text import enforces the same five-megabyte bound as file import', () => {
  assert.equal(rulesUI.MAX_IMPORT_BYTES, 5 * 1024 * 1024);
  assert.equal(rulesUI.utf8ByteLength('a😀я'), 7);
  assert.equal(rulesUI.utf8ByteLength('😀😀', 3), 4);
  assert.throws(
    () => rulesUI.parseImportPayload(' '.repeat(rulesUI.MAX_IMPORT_BYTES + 1)),
    /превышает 5 МБ/,
  );
});

test('import canonicalizes route references like the backend', () => {
  const proxyRule = rulesUI.parseImportPayload([rule({ proxy_id: ' office ', chain_id: 'stale-chain' })]).rules[0];
  assert.equal(proxyRule.proxy_id, 'office');
  assert.equal(proxyRule.chain_id, '');

  const chainRule = rulesUI.parseImportPayload([rule({ id: 'chain-rule', action: 'chain', proxy_id: 'stale-proxy', chain_id: ' Work ' })]).rules[0];
  assert.equal(chainRule.proxy_id, '');
  assert.equal(chainRule.chain_id, 'Work');

  const directRule = rulesUI.parseImportPayload([rule({ id: 'direct-rule', action: 'direct', proxy_id: 'stale-proxy', chain_id: 'stale-chain' })]).rules[0];
  assert.equal(directRule.proxy_id, '');
  assert.equal(directRule.chain_id, '');
});

test('import rejects non-boolean enabled instead of coercing strings', () => {
  const parsed = rulesUI.parseImportPayload([
    rule({ id: 'unsafe-block', action: 'block', proxy_id: '', enabled: 'false' }),
  ]);
  assert.deepEqual(parsed.rules, []);
  assert.equal(parsed.errors.length, 1);
  assert.match(parsed.errors[0], /enabled.*boolean/);
});

test('import bounds the number of rules and reported errors', () => {
  assert.throws(
    () => rulesUI.parseImportPayload(Array.from({ length: rulesUI.MAX_IMPORT_RULES + 1 }, () => null)),
    /максимум/,
  );
  const parsed = rulesUI.parseImportPayload(Array.from({ length: rulesUI.MAX_IMPORT_ERRORS + 5 }, () => null));
  assert.equal(parsed.rules.length, 0);
  assert.equal(parsed.errors.length, rulesUI.MAX_IMPORT_ERRORS + 1);
  assert.equal(parsed.invalidCount, rulesUI.MAX_IMPORT_ERRORS + 5);
  assert.match(parsed.errors.at(-1), /Ещё ошибок скрыто: 5/);
});

test('rule IDs remain case-sensitive during import and merge', () => {
  const parsed = rulesUI.parseImportPayload([
    rule({ id: 'Foo' }),
    rule({ id: 'foo' }),
  ]);
  assert.deepEqual(parsed.errors, []);
  assert.deepEqual(parsed.rules.map((item) => item.id), ['Foo', 'foo']);

  const merged = rulesUI.mergeImportedRules([rule({ id: 'Foo' })], [rule({ id: 'foo' })], 'skip');
  assert.deepEqual(merged.rules.map((item) => item.id), ['Foo', 'foo']);
  assert.equal(merged.summary.added, 1);
  assert.equal(merged.summary.skipped, 0);

  const trimmed = rulesUI.parseImportPayload([rule({ id: ' Foo ' }), rule({ id: 'Foo' })]);
  assert.deepEqual(trimmed.rules.map((item) => item.id), ['Foo']);
  assert.equal(trimmed.errors.length, 1);
  assert.match(trimmed.errors[0], /повторяющийся id Foo/);
});

test('import strategies skip, replace, or copy conflicts and insert before default', () => {
  const existing = [rule({ id: 'same', name: 'Старое' }), rule({ id: 'default', action: 'direct', proxy_id: '' })];
  const incoming = [rule({ id: 'same', name: 'Новое' }), rule({ id: 'fresh', name: 'Новое 2' })];

  const skipped = rulesUI.mergeImportedRules(existing, incoming, 'skip');
  assert.deepEqual(skipped.rules.map((item) => item.id), ['same', 'fresh', 'default']);
  assert.equal(skipped.summary.skipped, 1);

  const replaced = rulesUI.mergeImportedRules(existing, incoming, 'replace');
  assert.equal(replaced.rules[0].name, 'Новое');
  assert.equal(replaced.summary.replaced, 1);

  const copied = rulesUI.mergeImportedRules(existing, incoming, 'copy');
  assert.deepEqual(copied.rules.map((item) => item.id), ['same', 'same-import', 'fresh', 'default']);
  assert.equal(copied.summary.copied, 1);
});

test('copy import reserves explicit IDs of later incoming rules', () => {
  const existing = [rule({ id: 'foo' })];
  const incoming = [rule({ id: 'foo' }), rule({ id: 'foo-import' })];
  const copied = rulesUI.mergeImportedRules(existing, incoming, 'copy');
  assert.deepEqual(copied.rules.map((item) => item.id), ['foo', 'foo-import-2', 'foo-import']);
  assert.equal(new Set(copied.rules.map((item) => item.id)).size, copied.rules.length);
});

test('log backfill merge keeps live events, removes overlap, sorts, and bounds memory', () => {
  const entry = (time, message, overrides = {}) => ({ time, level: 'info', message, ...overrides });
  const overlap = entry('2026-08-03T12:00:01.000Z', 'overlap', { pid: 42, rule_id: 'Foo' });
  const merged = rulesUI.mergeLogEntries([
    entry('2026-08-03T12:00:00.000Z', 'history'),
    overlap,
  ], [
    overlap,
    entry('2026-08-03T12:00:02.000Z', 'live'),
  ], 10);
  assert.deepEqual(merged.map((item) => item.message), ['history', 'overlap', 'live']);

  const bounded = rulesUI.mergeLogEntries([], [
    entry('2026-08-03T12:00:00.000Z', 'one'),
    entry('2026-08-03T12:00:01.000Z', 'two'),
    entry('2026-08-03T12:00:02.000Z', 'three'),
  ], 2);
  assert.deepEqual(bounded.map((item) => item.message), ['two', 'three']);
});

test('export does not include proxy credentials or unrelated config', () => {
  const payload = rulesUI.makeExportPayload([rule()], '2026-08-03T12:00:00.000Z');
  assert.equal(payload.format, 'pitchprox.rules');
  assert.equal(payload.rules.length, 1);
  assert.equal(Object.hasOwn(payload, 'proxies'), false);
});
