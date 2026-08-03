'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
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

test('syntax warnings report unclosed quotes and redundant Any', () => {
  const warnings = rulesUI.syntaxWarnings(rule({
    applications: 'Any; chrome.exe',
    target_hosts: '"broken.example',
  }));
  assert.equal(warnings.length, 2);
  assert.match(warnings[0], /Any/);
  assert.match(warnings[1], /кавычка/);
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
