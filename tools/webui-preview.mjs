import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const staticRoot = path.join(repoRoot, 'internal', 'webui', 'dist');
const port = Math.max(1024, Number(process.argv[2]) || 18081);
let paused = false;
let webUIEnabled = true;

const examples = [
  ['Figma', 'Макеты рабочего проекта', 'figma.exe; chrome.exe', '*.figma.com; static.figma.com', '443', 'proxy', 'office'],
  ['Обновления Windows', 'Системные обновления напрямую', 'svchost.exe; MoUsoCoreWorker.exe', '*.windowsupdate.com; download.windowsupdate.com', 'Any', 'direct', ''],
  ['Telegram', 'Звонки и рабочие чаты', 'telegram.exe', '*.telegram.org; *.telegram.me', '80; 443; 1400-1500', 'proxy', 'office'],
  ['GitHub', 'Доступ к репозиториям', 'git.exe; code.exe; "C:\\Program Files\\GitHub Desktop\\GitHubDesktop.exe"', '*.github.com; githubusercontent.com', '443', 'proxy', 'office'],
  ['Bitbucket', 'Исходный код проектов', 'bitbucket.exe; chrome.exe', '*.bitbucket.org', '443', 'proxy', 'office'],
  ['Slack', 'Рабочие чаты и каналы', 'slack.exe', '*.slack.com; *.slack-edge.com', '443', 'proxy', 'office'],
  ['Jira', 'Отслеживание задач', 'chrome.exe; firefox.exe', '*.atlassian.net', '443', 'proxy', 'office'],
  ['YouTube', 'Обучающие видео напрямую', 'chrome.exe; msedge.exe', '*.youtube.com; *.googlevideo.com', '443', 'direct', ''],
];

function makeRule(index) {
  const sample = examples[index % examples.length];
  const number = index + 1;
  const action = index % 11 === 9 ? 'block' : sample[5];
  return {
    id: `rule-${number}`,
    name: `${sample[0]}${number > examples.length ? ` ${number}` : ''}`,
    enabled: index % 9 !== 2,
    applications: sample[2],
    target_hosts: sample[3],
    target_ports: sample[4],
    action,
    proxy_id: action === 'proxy' ? sample[6] : '',
    chain_id: '',
    notes: sample[1],
  };
}

let config = {
  version: 1,
  updated_at: new Date().toISOString(),
  retention_minutes: 15,
  dropped_log_max_bytes: 10 * 1024 * 1024,
  http: { listen: `127.0.0.1:${port}` },
  transparent: {
    ipv4_listener: '0.0.0.0',
    ipv6_listener: '::',
    listener_port: 26001,
    sniff_bytes: 4096,
    sniff_timeout_ms: 1500,
  },
  proxies: [
    { id: 'office', name: 'Рабочий proxy', type: 'http', address: '127.0.0.1:3128', enabled: true },
    { id: 'backup', name: 'Резервный SOCKS5', type: 'socks5', address: '127.0.0.1:1080', enabled: false },
  ],
  chains: [
    { id: 'fallback', name: 'Основной → резервный', proxy_ids: ['office', 'backup'], enabled: false },
  ],
  rules: [
    ...Array.from({ length: 73 }, (_, index) => makeRule(index)),
    {
      id: 'default',
      name: 'Default',
      enabled: true,
      applications: '*',
      target_hosts: 'Any',
      target_ports: 'Any',
      action: 'direct',
      notes: 'Маршрут по умолчанию',
    },
  ],
};

function json(response, status, value) {
  const body = Buffer.from(JSON.stringify(value));
  response.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-store',
  });
  response.end(body);
}

function text(response, status, value) {
  const body = Buffer.from(String(value || ''));
  response.writeHead(status, {
    'Content-Type': 'text/plain; charset=utf-8',
    'Content-Length': body.length,
  });
  response.end(body);
}

async function readBody(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 8 * 1024 * 1024) throw new Error('request too large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function activitySeries(ids, points, windowMinutes) {
  const generatedAt = new Date();
  const bucketSeconds = Math.max(1, Math.ceil((windowMinutes * 60) / points));
  return ids.map((id) => {
    const index = Math.max(0, config.rules.findIndex((rule) => rule.id === id));
    const buckets = Array.from({ length: points }, (_, point) => {
      const wave = Math.max(0, Math.sin((point + index) * 0.63) + Math.sin((point + index * 2) * 0.21));
      const connections = Math.round(wave * ((index % 4) + 1));
      const bytes = connections * (1400 + (index % 6) * 900);
      return {
        time: new Date(generatedAt.getTime() - (points - point) * bucketSeconds * 1000).toISOString(),
        connections,
        up_bytes: Math.round(bytes * 0.32),
        down_bytes: Math.round(bytes * 0.68),
      };
    });
    return {
      rule_id: id,
      connections: buckets.reduce((sum, item) => sum + item.connections, 0),
      up_bytes: buckets.reduce((sum, item) => sum + item.up_bytes, 0),
      down_bytes: buckets.reduce((sum, item) => sum + item.down_bytes, 0),
      buckets,
    };
  });
}

function previewValues(raw) {
  return String(raw || '').split(/[;,\r\n]+/).map((value) => value.trim().replace(/^"|"$/g, '')).filter(Boolean);
}

function conditionActivity(rule, windowMinutes) {
  const applications = previewValues(rule.applications);
  const hosts = previewValues(rule.target_hosts);
  const ports = previewValues(rule.target_ports);
  const app = applications[0] || 'Any';
  const host = hosts[0] || 'Any';
  const portValue = ports[0] || 'Any';
  const sources = { intercepted: 9, direct_observer: 3 };
  const dimension = (values, options = {}) => ({
    total_hits: 12,
    other_hits: options.otherHits || 0,
    truncated: !!options.truncated,
    values: values.map((value, index) => ({
      value,
      hits: Math.max(1, 12 - index * 4),
      share: Math.max(1, 12 - index * 4) / 12,
      last_seen: new Date(Date.now() - index * 70_000).toISOString(),
      sources,
    })),
  });
  return {
    generated_at: new Date().toISOString(),
    rule_id: rule.id,
    window_minutes: windowMinutes,
    total_hits: 12,
    other_hits: 2,
    unattributed_hits: 1,
    truncated: true,
    source_hits: sources,
    conditions: [
      { application: app, host, port: portValue, hits: 7, share: 7 / 12, last_seen: new Date().toISOString(), sources: { intercepted: 5, direct_observer: 2 } },
      { application: applications[1] || app, host, port: ports[1] || portValue, hits: 3, share: 3 / 12, last_seen: new Date(Date.now() - 90_000).toISOString(), sources: { intercepted: 2, direct_observer: 1 } },
    ],
    dimensions: {
      applications: dimension(applications.slice(0, 1).map((value) => value.toLowerCase().replaceAll('/', '\\'))),
      hosts: dimension(hosts.slice(0, 1).map((value) => value.toLowerCase()), { truncated: hosts.length > 1, otherHits: hosts.length > 1 ? 3 : 0 }),
      ports: dimension(ports.slice(0, 1)),
    },
    accuracy: {
      unit: 'tcp_connection',
      attribution: 'first_matching_alternative',
      intercepted_complete: true,
      direct_complete: false,
      notice: 'Перехваченные соединения учтены точно; Direct наблюдается выборочно.',
    },
  };
}

function snapshot() {
  return {
    connections: [],
    new_connections: [],
    logs: [],
    traffic: [],
    traffic_totals: { up_bytes: 0, down_bytes: 0 },
    traffic_bucket_seconds: 1,
    retention_minutes: config.retention_minutes,
    new_baseline_minutes: config.retention_minutes,
    new_recent_minutes: 1,
    rule_stats: config.rules.slice(0, 20).map((rule, index) => ({
      rule_id: rule.id,
      rule_name: rule.name,
      action: rule.action,
      connections: (index + 1) * 3,
      up_bytes: (index + 1) * 18000,
      down_bytes: (index + 1) * 72000,
    })),
  };
}

async function serveStatic(requestPath, response) {
  const relative = requestPath === '/' ? 'index.html' : requestPath.replace(/^\/+/, '');
  const normalized = path.normalize(relative);
  const filePath = path.resolve(staticRoot, normalized);
  if (!filePath.startsWith(`${staticRoot}${path.sep}`) && filePath !== path.join(staticRoot, 'index.html')) {
    text(response, 404, 'not found');
    return;
  }
  try {
    const body = await readFile(filePath);
    const extension = path.extname(filePath).toLowerCase();
    const contentType = {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.png': 'image/png',
      '.ico': 'image/x-icon',
    }[extension] || 'application/octet-stream';
    response.writeHead(200, {
      'Content-Type': contentType,
      'Content-Length': body.length,
      'Cache-Control': 'no-store',
    });
    response.end(body);
  } catch {
    if (!path.extname(relative)) return serveStatic('/', response);
    text(response, 404, 'not found');
  }
}

const server = http.createServer(async (request, response) => {
  const url = new URL(request.url || '/', `http://127.0.0.1:${port}`);
  try {
    if (url.pathname === '/api/health') return json(response, 200, { ok: true, version: 'v0.43-rc.2-preview' });
    if (url.pathname === '/api/control/webui/status') {
      return json(response, 200, {
        enabled: webUIEnabled,
        paused,
        auto_paused: false,
        disabled_reason: '',
        idle_timeout_seconds: 3600,
        idle_deadline_at: new Date(Date.now() + 3600_000).toISOString(),
      });
    }
    if (url.pathname === '/api/control/service/status') return json(response, 200, { paused, webui_enabled: true });
    if (url.pathname === '/api/control/service/pause' && request.method === 'POST') {
      paused = true;
      return json(response, 200, { paused, webui_enabled: true });
    }
    if (url.pathname === '/api/control/service/resume' && request.method === 'POST') {
      paused = false;
      return json(response, 200, { paused, webui_enabled: true });
    }
    if (url.pathname === '/api/config' && request.method === 'GET') return json(response, 200, config);
    if (url.pathname === '/api/config' && request.method === 'PUT') {
      const candidate = JSON.parse(await readBody(request));
      if (candidate.updated_at && candidate.updated_at !== config.updated_at) {
        return text(response, 409, 'configuration changed since it was loaded');
      }
      const previousUpdatedAt = Date.parse(config.updated_at) || 0;
      config = candidate;
      config.updated_at = new Date(Math.max(Date.now(), previousUpdatedAt + 1)).toISOString();
      return json(response, 200, config);
    }
    if (url.pathname === '/api/snapshot') return json(response, 200, snapshot());
    if (url.pathname === '/api/rules/activity') {
      const ids = url.searchParams.getAll('id').slice(0, 50);
      const points = Math.max(2, Math.min(60, Number(url.searchParams.get('points')) || 40));
      const windowMinutes = Math.max(1, Math.min(60, Number(url.searchParams.get('window_minutes')) || 15));
      return json(response, 200, {
        generated_at: new Date().toISOString(),
        window_minutes: windowMinutes,
        bucket_seconds: (windowMinutes * 60) / points,
        points,
        series: activitySeries(ids, points, windowMinutes),
      });
    }
    if (url.pathname === '/api/rules/condition-activity') {
      const ruleID = url.searchParams.get('id') || '';
      const rule = config.rules.find((item) => item.id === ruleID);
      if (!rule) return text(response, 404, 'rule not found');
      const windowMinutes = Math.max(1, Math.min(60, Number(url.searchParams.get('window_minutes')) || 15));
      return json(response, 200, conditionActivity(rule, windowMinutes));
    }
    if (url.pathname === '/api/dropped' && request.method === 'GET') {
      return json(response, 200, { items: [], total: 0, offset: 0, limit: 100, file_bytes: 0, max_bytes: 10 * 1024 * 1024 });
    }
    if (url.pathname === '/api/dropped' && request.method === 'DELETE') return json(response, 200, { ok: true });
    if (url.pathname === '/api/proxy-test') return json(response, 200, { ok: true, message: 'Тестовый proxy доступен' });
    if (url.pathname === '/api/ui/visibility') return json(response, 200, { ok: true });
    if (url.pathname === '/api/events') {
      response.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
      });
      response.write(': preview\n\n');
      const timer = setInterval(() => response.write(': ping\n\n'), 15000);
      request.on('close', () => clearInterval(timer));
      return;
    }
    await serveStatic(url.pathname, response);
  } catch (error) {
    text(response, 500, error.message || String(error));
  }
});

server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`pitchProx WebUI preview: http://127.0.0.1:${port}/#/rules\n`);
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => server.close(() => process.exit(0)));
}
