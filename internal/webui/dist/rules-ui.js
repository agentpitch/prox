(function initRulesUI(root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.PitchProxRulesUI = api;
}(typeof globalThis !== 'undefined' ? globalThis : this, function rulesUIFactory() {
  'use strict';

  const DEFAULT_PAGE_SIZE = 25;
  const MAX_PAGE_SIZE = 50;
  const EXPORT_FORMAT = 'pitchprox.rules';
  const EXPORT_VERSION = 1;
  const MAX_IMPORT_RULES = 2000;
  const MAX_IMPORT_ERRORS = 100;

  function splitValues(raw) {
    const out = [];
    let current = '';
    let quoted = false;
    for (const char of String(raw || '')) {
      if (char === '"') {
        quoted = !quoted;
        current += char;
        continue;
      }
      if (!quoted && (char === ';' || char === ',' || char === '\n' || char === '\r')) {
        pushValue(out, current);
        current = '';
        continue;
      }
      current += char;
    }
    pushValue(out, current);
    return out;
  }

  function pushValue(out, raw) {
    let value = String(raw || '').trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
      value = value.slice(1, -1).trim();
    }
    if (value) out.push(value);
  }

  function hasUnclosedQuote(raw) {
    let quoted = false;
    for (const char of String(raw || '')) {
      if (char === '"') quoted = !quoted;
    }
    return quoted;
  }

  function queryTokens(raw) {
    const tokens = [];
    let current = '';
    let quoted = false;
    const flush = () => {
      const token = current.trim().toLocaleLowerCase('ru');
      if (token) tokens.push(token);
      current = '';
    };
    for (const char of String(raw || '')) {
      if (char === '"') {
        quoted = !quoted;
        continue;
      }
      if (!quoted && /\s/.test(char)) {
        flush();
        continue;
      }
      current += char;
    }
    flush();
    return tokens;
  }

  function actionMatches(rule, filter) {
    const normalized = String(filter || 'all').toLocaleLowerCase('ru');
    if (normalized === 'all') return true;
    if (normalized === 'enabled') return !!rule.enabled;
    if (normalized === 'disabled') return !rule.enabled;
    return String(rule.action || 'direct').toLocaleLowerCase('ru') === normalized;
  }

  function buildSearchText(rule, routeLabel) {
    const values = [
      rule.id,
      rule.name,
      rule.notes,
      rule.applications,
      rule.target_hosts,
      rule.target_ports,
      rule.action,
      rule.proxy_id,
      rule.chain_id,
      routeLabel,
    ];
    return values
      .flatMap((value) => [String(value || ''), ...splitValues(value)])
      .join('\n')
      .toLocaleLowerCase('ru');
  }

  function filterRules(rules, options) {
    const opts = options || {};
    const tokens = queryTokens(opts.query);
    const routeLabel = typeof opts.routeLabel === 'function' ? opts.routeLabel : () => '';
    const result = [];
    (Array.isArray(rules) ? rules : []).forEach((rule, originalIndex) => {
      if (!actionMatches(rule, opts.filter)) return;
      if (tokens.length) {
        const searchText = buildSearchText(rule, routeLabel(rule));
        if (!tokens.every((token) => searchText.includes(token))) return;
      }
      result.push({ rule, ruleId: String(rule.id || '').trim(), originalIndex });
    });
    return result;
  }

  function paginate(entries, requestedPage, requestedPageSize) {
    const pageSize = Math.max(1, Math.min(MAX_PAGE_SIZE, Number(requestedPageSize) || DEFAULT_PAGE_SIZE));
    const total = Array.isArray(entries) ? entries.length : 0;
    const pageCount = Math.max(1, Math.ceil(total / pageSize));
    const page = Math.max(1, Math.min(pageCount, Number(requestedPage) || 1));
    const start = (page - 1) * pageSize;
    return {
      page,
      pageSize,
      pageCount,
      total,
      start,
      end: Math.min(total, start + pageSize),
      items: (entries || []).slice(start, start + pageSize),
    };
  }

  function previewValues(raw, limit) {
    const values = splitValues(raw);
    const visibleLimit = Math.max(1, Number(limit) || 2);
    return {
      values,
      visible: values.slice(0, visibleLimit),
      hidden: Math.max(0, values.length - visibleLimit),
    };
  }

  function normalizeConditionActivity(payload, expectedRuleID, requestedLimit) {
    const source = payload && typeof payload === 'object' && !Array.isArray(payload) ? payload : {};
    const expected = String(expectedRuleID || '');
    const ruleID = String(source.rule_id || expected);
    if (expected && ruleID && ruleID !== expected) {
      throw new Error('Сервер вернул активность другого правила');
    }
    const numericLimit = Number(requestedLimit);
    const limit = Math.max(1, Math.min(100, Number.isFinite(numericLimit) ? Math.floor(numericLimit) : 20));
    const boundedCount = (value) => {
      const number = Number(value);
      if (!Number.isFinite(number) || number <= 0) return 0;
      return Math.min(Number.MAX_SAFE_INTEGER, Math.floor(number));
    };
    const boundedShare = (value, hits, total) => {
      const number = Number(value);
      if (Number.isFinite(number)) return Math.max(0, Math.min(1, number));
      return total > 0 ? Math.max(0, Math.min(1, hits / total)) : 0;
    };
    const rawConditions = Array.isArray(source.conditions) ? source.conditions : [];
    const totalHits = boundedCount(source.total_hits);
    let malformedConditions = 0;
    const conditions = rawConditions.slice(0, limit).flatMap((raw) => {
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
        malformedConditions += 1;
        return [];
      }
      const application = String(raw.application ?? '');
      const host = String(raw.host ?? '');
      const port = String(raw.port ?? '');
      if (!application || !host || !port) {
        malformedConditions += 1;
        return [];
      }
      const hits = boundedCount(raw.hits);
      const sources = raw.sources && typeof raw.sources === 'object' && !Array.isArray(raw.sources) ? raw.sources : {};
      return [{
        application,
        host,
        port,
        hits,
        share: boundedShare(raw.share, hits, totalHits),
        last_seen: String(raw.last_seen || ''),
        sources: {
          intercepted: boundedCount(sources.intercepted),
          direct_observer: boundedCount(sources.direct_observer),
        },
      }];
    });
    const accuracy = source.accuracy && typeof source.accuracy === 'object' && !Array.isArray(source.accuracy)
      ? source.accuracy
      : {};
    const rawDimensions = source.dimensions && typeof source.dimensions === 'object' && !Array.isArray(source.dimensions)
      ? source.dimensions
      : {};
    const normalizeDimension = (rawDimension) => {
      const available = !!rawDimension && typeof rawDimension === 'object' && !Array.isArray(rawDimension);
      const dimension = available ? rawDimension : {};
      const dimensionTotal = boundedCount(dimension.total_hits);
      const rawValues = Array.isArray(dimension.values) ? dimension.values : [];
      let malformedValues = 0;
      const values = rawValues.slice(0, 512).flatMap((raw) => {
        if (!raw || typeof raw !== 'object' || Array.isArray(raw) || !String(raw.value ?? '')) {
          malformedValues += 1;
          return [];
        }
        const hits = boundedCount(raw.hits);
        const sources = raw.sources && typeof raw.sources === 'object' && !Array.isArray(raw.sources) ? raw.sources : {};
        return [{
          value: String(raw.value),
          hits,
          share: boundedShare(raw.share, hits, dimensionTotal),
          last_seen: String(raw.last_seen || ''),
          sources: {
            intercepted: boundedCount(sources.intercepted),
            direct_observer: boundedCount(sources.direct_observer),
          },
        }];
      });
      return {
        available,
        total_hits: dimensionTotal,
        other_hits: boundedCount(dimension.other_hits),
        truncated: !!dimension.truncated || rawValues.length > 512 || malformedValues > 0,
        values,
      };
    };
    return {
      generated_at: String(source.generated_at || ''),
      rule_id: ruleID,
      window_minutes: Math.max(1, Math.min(60, boundedCount(source.window_minutes) || 15)),
      total_hits: totalHits,
      other_hits: boundedCount(source.other_hits),
      unattributed_hits: boundedCount(source.unattributed_hits),
      malformed_conditions: malformedConditions,
      truncated: !!source.truncated || rawConditions.length > limit || malformedConditions > 0,
      accuracy: {
        scope: String(accuracy.scope || ''),
        intercepted_complete: accuracy.intercepted_complete !== false,
        direct_complete: accuracy.direct_complete !== false,
        notice: String(accuracy.notice || ''),
      },
      dimensions: {
        applications: normalizeDimension(rawDimensions.applications),
        hosts: normalizeDimension(rawDimensions.hosts),
        ports: normalizeDimension(rawDimensions.ports),
      },
      conditions,
    };
  }

  function buildConditionCoverage(raw, dimension, requestedLimit, kind) {
    const rawTokens = splitValues(raw);
    const tokens = rawTokens.length ? rawTokens : ['Any'];
    const numericLimit = Number(requestedLimit);
    const limit = Math.max(1, Math.min(500, Number.isFinite(numericLimit) ? Math.floor(numericLimit) : 200));
    const normalizedKey = (value) => {
      const normalized = String(value || '').trim().toLocaleLowerCase('ru');
      if (kind === 'applications' && (normalized === '*' || normalized === 'any')) return '\u0000any';
      return kind === 'applications' ? normalized.replaceAll('/', '\\') : normalized;
    };
    const byValue = new Map();
    for (const entry of (Array.isArray(dimension?.values) ? dimension.values : [])) {
      const key = normalizedKey(entry?.value);
      if (key && !byValue.has(key)) byValue.set(key, entry);
    }
    const seen = new Set();
    const uniqueTokens = [];
    for (const token of tokens) {
      const key = normalizedKey(token);
      if (!key || seen.has(key)) continue;
      seen.add(key);
      uniqueTokens.push(token);
    }
    const items = uniqueTokens.slice(0, limit).map((token) => {
      const key = normalizedKey(token);
      const observed = byValue.get(key);
      if (observed) return { token, state: 'observed', ...observed };
      const exactZero = !!dimension?.available && !dimension?.truncated;
      return {
        token,
        state: exactZero ? 'zero' : 'unknown',
        hits: exactZero ? 0 : null,
        share: 0,
        last_seen: '',
        sources: { intercepted: 0, direct_observer: 0 },
      };
    });
    return {
      items,
      omitted: Math.max(0, uniqueTokens.length - limit),
      truncated: !!dimension?.truncated,
      available: !!dimension?.available,
    };
  }

  function normalizeWebUIStatus(payload) {
    const source = payload && typeof payload === 'object' && !Array.isArray(payload) ? payload : {};
    const servicePaused = !!source.paused;
    const webUIEnabled = source.enabled !== false;
    return {
      servicePaused,
      webUIEnabled,
      webUIPaused: !servicePaused && !webUIEnabled,
      webUIAutoPaused: !servicePaused && !webUIEnabled && !!source.auto_paused,
      disabledReason: String(source.disabled_reason || ''),
      idleDeadlineAt: String(source.idle_deadline_at || ''),
      idleTimeoutSeconds: Math.max(1, Number(source.idle_timeout_seconds || 3600)),
    };
  }

  function nextWebUIIdleDelay(deadlineAt, nowMs, statusFailures, afterStatusCheck) {
    const deadline = Date.parse(String(deadlineAt || ''));
    const now = Number(nowMs);
    if (!Number.isFinite(deadline) || !Number.isFinite(now)) return null;
    const remaining = deadline - now + 250;
    if (remaining > 0) return Math.min(2147483000, remaining);
    if (!afterStatusCheck) return 0;
    const failures = Math.max(1, Math.min(5, Math.floor(Number(statusFailures) || 0)));
    return Math.min(300000, 30000 * (2 ** (failures - 1)));
  }

  function normalizedSet(raw, anyValues) {
    const values = splitValues(raw).map((value) => value.toLocaleLowerCase('ru'));
    const any = new Set((anyValues || []).map((value) => String(value).toLocaleLowerCase('ru')));
    // Keep the unconditional sentinel distinct from a literal host wildcard.
    // Applications accepts `*` as an Any alias, while Target hosts uses `*`
    // as a hostname pattern and Target ports rejects it.
    if (!values.length || values.some((value) => any.has(value))) return new Set(['\u0000any']);
    return new Set(values);
  }

  function setSimilarity(left, right) {
    const union = new Set([...left, ...right]);
    if (!union.size) return 1;
    let intersection = 0;
    for (const value of left) if (right.has(value)) intersection += 1;
    return intersection / union.size;
  }

  function ruleSimilarity(left, right) {
    const apps = setSimilarity(
      normalizedSet(left.applications, ['any', '*']),
      normalizedSet(right.applications, ['any', '*']),
    );
    const hosts = setSimilarity(
      normalizedSet(left.target_hosts, ['any']),
      normalizedSet(right.target_hosts, ['any']),
    );
    const ports = setSimilarity(
      normalizedSet(left.target_ports, ['any']),
      normalizedSet(right.target_ports, ['any']),
    );
    const action = String(left.action || 'direct') === String(right.action || 'direct') ? 1 : 0;
    const routeLeft = `${String(left.proxy_id || '').trim()}\u001f${String(left.chain_id || '').trim()}`;
    const routeRight = `${String(right.proxy_id || '').trim()}\u001f${String(right.chain_id || '').trim()}`;
    const route = routeLeft === routeRight ? 1 : 0;
    return Math.round((apps * 0.3 + hosts * 0.35 + ports * 0.2 + action * 0.1 + route * 0.05) * 100);
  }

  function ruleCriteriaFingerprint(rule) {
    const sorted = (values) => Array.from(values).sort();
    return JSON.stringify([
      sorted(normalizedSet(rule?.applications, ['any', '*'])),
      sorted(normalizedSet(rule?.target_hosts, ['any'])),
      sorted(normalizedSet(rule?.target_ports, ['any'])),
      String(rule?.action || 'direct'),
      String(rule?.proxy_id || '').trim(),
      String(rule?.chain_id || '').trim(),
    ]);
  }

  function findSimilarRules(candidate, rules, excludedID, minScore) {
    const threshold = Number.isFinite(Number(minScore)) ? Number(minScore) : 55;
    return (Array.isArray(rules) ? rules : [])
      .filter((rule) => String(rule.id || '').trim() !== String(excludedID || '').trim())
      .map((rule) => ({ rule, score: ruleSimilarity(candidate, rule) }))
      .filter((entry) => entry.score >= threshold)
      .sort((left, right) => right.score - left.score || String(left.rule.name || '').localeCompare(String(right.rule.name || ''), 'ru'))
      .slice(0, 3);
  }

  function syntaxWarnings(rule) {
    const warnings = [];
    const fields = [
      ['Applications', rule.applications, ['any', '*'], 'Any/*'],
      ['Target hosts', rule.target_hosts, ['any'], 'Any'],
      ['Target ports', rule.target_ports, ['any'], 'Any'],
    ];
    for (const [label, raw, anyValues, anyLabel] of fields) {
      if (hasUnclosedQuote(raw)) warnings.push(`${label}: незакрытая двойная кавычка`);
      const values = splitValues(raw).map((value) => value.toLocaleLowerCase('ru'));
      const any = new Set(anyValues);
      if (values.length > 1 && values.some((value) => any.has(value))) {
        warnings.push(`${label}: ${anyLabel} уже охватывает остальные значения`);
      }
    }
    return warnings;
  }

  function cloneRule(rule) {
    return JSON.parse(JSON.stringify(rule || {}));
  }

  function logEntryKey(entry) {
    const item = entry || {};
    return JSON.stringify([
      item.time || '',
      item.level || '',
      item.message || '',
      item.connection_id || '',
      Number(item.pid || 0),
      item.exe_path || '',
      item.action || '',
      item.rule_id || '',
      item.rule_name || '',
      item.host || '',
      Number(item.port || 0),
    ]);
  }

  function mergeLogEntries(historyEntries, liveEntries, requestedLimit) {
    const numericLimit = Number(requestedLimit);
    const limit = Number.isFinite(numericLimit) && numericLimit > 0 ? Math.floor(numericLimit) : 1000;
    const seen = new Set();
    const merged = [];
    let ordinal = 0;
    for (const entry of [...(Array.isArray(historyEntries) ? historyEntries : []), ...(Array.isArray(liveEntries) ? liveEntries : [])]) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
      const key = logEntryKey(entry);
      if (seen.has(key)) continue;
      seen.add(key);
      const timestamp = Date.parse(entry.time || '');
      merged.push({ entry, timestamp: Number.isFinite(timestamp) ? timestamp : null, ordinal });
      ordinal += 1;
    }
    merged.sort((left, right) => {
      if (left.timestamp != null && right.timestamp != null && left.timestamp !== right.timestamp) {
        return left.timestamp - right.timestamp;
      }
      return left.ordinal - right.ordinal;
    });
    return merged.slice(-limit).map((item) => item.entry);
  }

  function normalizeImportedRule(value, index) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) {
      return { error: `Правило ${index + 1}: ожидается объект` };
    }
    const rule = cloneRule(value);
    const stringFields = ['id', 'name', 'applications', 'target_hosts', 'target_ports', 'proxy_id', 'chain_id', 'notes'];
    for (const field of stringFields) {
      if (rule[field] == null) rule[field] = '';
      if (typeof rule[field] !== 'string') return { error: `Правило ${index + 1}: поле ${field} должно быть строкой` };
    }
    rule.id = rule.id.trim();
    rule.name = rule.name.trim();
    rule.proxy_id = rule.proxy_id.trim();
    rule.chain_id = rule.chain_id.trim();
    rule.action = String(rule.action || 'direct').trim().toLocaleLowerCase('ru');
    if (rule.enabled != null && typeof rule.enabled !== 'boolean') {
      return { error: `Правило ${index + 1}: поле enabled должно быть boolean` };
    }
    rule.enabled = rule.enabled === true;
    if (!rule.id) return { error: `Правило ${index + 1}: отсутствует id` };
    if (!['direct', 'proxy', 'chain', 'block'].includes(rule.action)) {
      return { error: `Правило ${index + 1}: неизвестное действие ${rule.action}` };
    }
    if (rule.action === 'proxy' && !rule.proxy_id.trim()) return { error: `Правило ${index + 1}: не указан proxy_id` };
    if (rule.action === 'chain' && !rule.chain_id.trim()) return { error: `Правило ${index + 1}: не указан chain_id` };
    if (rule.action === 'proxy') rule.chain_id = '';
    else if (rule.action === 'chain') rule.proxy_id = '';
    else {
      rule.proxy_id = '';
      rule.chain_id = '';
    }
    return { rule };
  }

  function parseImportPayload(payload) {
    let source = payload;
    if (typeof source === 'string') source = JSON.parse(source);
    let values;
    if (Array.isArray(source)) {
      values = source;
    } else if (source && typeof source === 'object' && Array.isArray(source.rules)) {
      if (source.format && source.format !== EXPORT_FORMAT) throw new Error(`Неподдерживаемый формат: ${source.format}`);
      if (source.format === EXPORT_FORMAT && Number(source.version) !== EXPORT_VERSION) {
        throw new Error(`Неподдерживаемая версия формата: ${source.version}`);
      }
      values = source.rules;
    } else {
      throw new Error('Файл не содержит массив rules');
    }
    if (values.length > MAX_IMPORT_RULES) {
      throw new Error(`Файл содержит ${values.length} правил; максимум ${MAX_IMPORT_RULES}`);
    }
    const rules = [];
    const errors = [];
    let omittedErrors = 0;
    const seen = new Set();
    const addError = (message) => {
      if (errors.length < MAX_IMPORT_ERRORS) errors.push(message);
      else omittedErrors += 1;
    };
    values.forEach((value, index) => {
      const result = normalizeImportedRule(value, index);
      if (result.error) {
        addError(result.error);
        return;
      }
      const key = result.rule.id;
      if (seen.has(key)) {
        addError(`Правило ${index + 1}: повторяющийся id ${result.rule.id}`);
        return;
      }
      seen.add(key);
      rules.push(result.rule);
    });
    if (omittedErrors > 0) errors.push(`Ещё ошибок скрыто: ${omittedErrors}`);
    return { rules, errors };
  }

  function makeExportPayload(rules, exportedAt) {
    return {
      format: EXPORT_FORMAT,
      version: EXPORT_VERSION,
      exported_at: exportedAt || new Date().toISOString(),
      rules: (Array.isArray(rules) ? rules : []).map(cloneRule),
    };
  }

  function nextImportedID(base, used) {
    const root = String(base || 'rule').trim() || 'rule';
    let suffix = 1;
    let candidate = `${root}-import`;
    while (used.has(candidate)) {
      suffix += 1;
      candidate = `${root}-import-${suffix}`;
    }
    used.add(candidate);
    return candidate;
  }

  function mergeImportedRules(existing, incoming, strategy) {
    const rules = (Array.isArray(existing) ? existing : []).map(cloneRule);
    const imported = (Array.isArray(incoming) ? incoming : []).map(cloneRule);
    const mode = ['skip', 'replace', 'copy'].includes(strategy) ? strategy : 'skip';
    const byID = new Map(rules.map((rule, index) => [String(rule.id || '').trim(), index]));
    // Reserve every explicit imported ID before generating copy suffixes. An
    // earlier conflict must not claim the ID of a later non-conflicting rule.
    const used = new Set([
      ...byID.keys(),
      ...imported.map((rule) => String(rule.id || '').trim()).filter(Boolean),
    ]);
    const additions = [];
    const summary = { added: 0, replaced: 0, skipped: 0, copied: 0 };
    for (const rule of imported) {
      const key = String(rule.id || '').trim();
      const existingIndex = byID.get(key);
      if (existingIndex == null) {
        additions.push(rule);
        used.add(key);
        summary.added += 1;
        continue;
      }
      if (mode === 'replace') {
        rules[existingIndex] = rule;
        summary.replaced += 1;
      } else if (mode === 'copy') {
        rule.id = nextImportedID(rule.id, used);
        additions.push(rule);
        summary.copied += 1;
      } else {
        summary.skipped += 1;
      }
    }
    const defaultIndex = rules.findIndex((rule) => String(rule.id || '').trim() === 'default');
    const insertAt = defaultIndex >= 0 ? defaultIndex : rules.length;
    rules.splice(insertAt, 0, ...additions);
    return { rules, summary };
  }

  return Object.freeze({
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    EXPORT_FORMAT,
    EXPORT_VERSION,
    MAX_IMPORT_RULES,
    MAX_IMPORT_ERRORS,
    splitValues,
    hasUnclosedQuote,
    queryTokens,
    buildSearchText,
    filterRules,
    paginate,
    previewValues,
    normalizeConditionActivity,
    buildConditionCoverage,
    normalizeWebUIStatus,
    nextWebUIIdleDelay,
    ruleSimilarity,
    ruleCriteriaFingerprint,
    findSimilarRules,
    syntaxWarnings,
    mergeLogEntries,
    parseImportPayload,
    makeExportPayload,
    mergeImportedRules,
  });
}));
