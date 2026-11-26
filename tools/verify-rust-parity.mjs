import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { copyFile, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { createServer } from "node:net";
import { join, resolve } from "node:path";
import { setTimeout as sleep } from "node:timers/promises";

const args = process.argv.slice(2).filter((arg) => arg !== "--visual");
const visual = process.argv.includes("--visual");
if (args.length !== 2) {
  throw new Error("Usage: node tools/verify-rust-parity.mjs GO_EXE RUST_EXE");
}
const root = resolve("build/parity");
await mkdir(root, { recursive: true });
const run = await mkdtemp(join(root, "run-"));
const installed = [];
const headers = { "X-PitchProx-Agent": "1" };
const webui = { "X-PitchProx-WebUI": "1" };
const revision = "2026-01-01T00:00:00Z";

const rules = [
  {
    id: "local", name: "Local", enabled: true, applications: "*",
    target_hosts: "localhost; 127.0.0.1", target_ports: "Any", action: "direct",
  },
  {
    id: "default", name: "Default", enabled: true, applications: "*",
    target_hosts: "Any", target_ports: "Any", action: "direct",
  },
];

async function server(handler) {
  const listener = createServer(handler);
  listener.listen(0, "127.0.0.1");
  await once(listener, "listening");
  return listener;
}

async function port() {
  const listener = await server();
  const selected = listener.address().port;
  listener.close();
  await once(listener, "close");
  return selected;
}

async function start(executable, name, timestamp) {
  const dir = join(run, name);
  const history = join(dir, "pitchProx.history");
  const config = join(dir, "pitchProx.config.json");
  await mkdir(history + ".segments", { recursive: true });
  const address = `127.0.0.1:${await port()}`;
  const input = {
    version: 1, updated_at: revision, retention_minutes: 7, dropped_log_max_bytes: 10 * 1024 * 1024,
    http: { listen: address },
    transparent: {
      ipv4_listener: "0.0.0.0", ipv6_listener: "::", listener_port: 26001,
      sniff_bytes: 4096, sniff_timeout_ms: 1500,
    },
    proxies: null, chains: [], rules,
  };
  await writeFile(config, JSON.stringify(input));
  await seedHistory(history + ".segments", timestamp);
  const copy = join(dir, "pitchProx.exe");
  await copyFile(resolve(executable), copy);
  const process = spawn(copy, ["run"], {
    cwd: dir,
    windowsHide: true,
    env: {
      ...globalThis.process.env,
      PITCHPROX_ALLOW_UNELEVATED: "1", PITCHPROX_DISABLE_TRAY: "1",
      PITCHPROX_CONFIG: config, PITCHPROX_HISTORY: history,
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const app = { base: `http://${address}`, config, dir, copy, name, process, stderr: "" };
  installed.push(app);
  process.stderr.setEncoding("utf8").on("data", (data) => { app.stderr += data; });
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline && process.exitCode === null) {
    const health = await call(app, "/api/health").catch(() => null);
    if (health?.data?.pid === process.pid) return app;
    await sleep(50);
  }
  throw new Error(`${name} failed to start (${process.exitCode}): ${app.stderr}`);
}

async function seedHistory(dir, seconds) {
  const time = new Date(seconds * 1000).toISOString();
  const stamp = time.replace(/\D/g, "").slice(0, 10);
  const drop = {
    ID: "123456|192.0.2.8|50000|198.51.100.8|443", PID: 123456, ExePath: "C:\\Apps\\fixture.exe",
    SourceIP: "192.0.2.8", SourcePort: 50000, OriginalIP: "198.51.100.8", OriginalPort: 443,
    Hostname: "fixture.test", RuleID: "block-fixture", RuleName: "Block fixture",
    Action: "block", ProxyID: "", ChainID: "", State: "blocked", BytesUp: 0, BytesDown: 0,
    CreatedAt: time, LastUpdatedAt: time, Count: 1,
  };
  const files = new Map([
    [`connections-${stamp}.jsonl`, drop],
    ["dropped.jsonl", { DropID: "fixture-dropped", DroppedAt: time, Connection: drop }],
    [`logs-${stamp}.jsonl`, {
      Time: time, Level: "warn", Message: "history fixture", ConnectionID: "", PID: 0,
      ExePath: "", Action: "", RuleID: "", RuleName: "", Host: "", Port: 0,
    }],
    [`rules-${stamp}.jsonl`, {
      time, RuleID: "block-fixture", RuleName: "Block fixture", Action: "block",
      Connections: 4, UpBytes: 0, DownBytes: 0,
      condition_application: "fixture.exe", condition_host: "fixture.test", condition_port: "443",
      condition_source: "intercepted",
    }],
    [`traffic-${stamp}.jsonl`, { Time: time, UpBytes: 25, DownBytes: 75 }],
  ]);
  await Promise.all([...files].map(([file, data]) => writeFile(join(dir, file), JSON.stringify(data) + "\n")));
}

async function call(app, path, method = "GET", body, extra = {}) {
  const response = await fetch(app.base + path, {
    method, headers: { ...extra, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "manual", signal: AbortSignal.timeout(7500),
  });
  const contentType = response.headers.get("content-type");
  const bytes = Buffer.from(await response.arrayBuffer());
  const data = contentType?.includes("application/json") ? JSON.parse(bytes) : undefined;
  return { code: response.status, contentType, bytes, data };
}

async function stop(app) {
  if (app.process.exitCode !== null) return;
  await call(app, "/api/control/stop", "POST").catch(() => null);
  const deadline = Date.now() + 5000;
  while (app.process.exitCode === null && Date.now() < deadline) await sleep(30);
  if (app.process.exitCode === null) {
    app.process.kill();
    throw new Error(`${app.name} did not shut down after /api/control/stop: ${app.stderr}`);
  }
  assert.equal(app.process.exitCode, 0, app.stderr);
}

function cli(app, ...args) {
  return new Promise((resolve, reject) => {
    const child = spawn(app.copy, ["ctl", ...args], { cwd: app.dir, windowsHide: true });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8").on("data", (s) => { stdout += s; });
    child.stderr.setEncoding("utf8").on("data", (s) => { stderr += s; });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

const checks = [];
function compare(label, actual, expected) {
  assert.deepEqual(actual, expected, label);
  checks.push(label);
}

try {
  const timestamp = Math.floor(Date.now() / 15000) * 15 - 30;
  const go = await start(args[0], "go", timestamp);
  const rust = await start(args[1], "rust", timestamp);
  if (visual) {
    console.log(JSON.stringify({ go: go.base, rust: rust.base }));
    await Promise.race([once(process.stdin,"data"), sleep(180000, undefined, { ref: false })]);
    process.stdin.pause();
  }
  const pair = (path, method, body, extra) => Promise.all([go, rust].map((app) => call(app, path, method, body, extra)));
  for (const asset of ["/", "/monitor", "/design.css", "/styles.css", "/app.js", "/rules-ui.js", "/pp_icon_256.png", "/favicon.ico", "/missing.js"]) {
    const [left, right] = await pair(asset);
    compare(`WebUI ${asset}`, [left.code, left.bytes], [right.code, right.bytes]);
  }
  for (const request of [["/api/config","POST"], ["/api/rules/activity?points=1"], ["/api/rules/condition-activity"], ["/api/dropped?offset=-1"], ["/api/update/releases"], ["/api/update/install","POST",{}], ["/api/unknown"]]) {
    const [left, right] = await pair(...request);
    compare(`HTTP status and text ${request.join(" ")}`, [left.code, left.bytes], [right.code, right.bytes]);
  }
  for (const path of ["/api/control/agent/status", "/api/control/agent/config", "/api/control/agent/unknown"]) {
    const [left, right] = await pair(path);
    compare(`Agent rejects an unmarked ${path}`, [left.code, left.data], [right.code, right.data]);
  }
  for (const path of ["/api/dropped", "/api/dropped?q=fixture.exe+fixture.test"]) {
    const [left, right] = await pair(path);
    compare(`Go history format ${path}`, normalizeTimes(left.data), normalizeTimes(right.data));
  }
  {
    const [left, right] = await pair("/api/rules/condition-activity?id=block-fixture");
    for (const item of [left, right]) delete item.data.generated_at;
    compare("condition statistics from a Go segment", normalizeTimes(left.data), normalizeTimes(right.data));
  }
  {
    const [left, right] = await pair("/api/rules/activity?id=block-fixture&window_minutes=5&points=10");
    for (const result of [left,right]) {
      delete result.data.generated_at;
      for (const series of result.data.series) for (const bucket of series.buckets) delete bucket.time;
    }
    compare("rule activity buckets from a Go segment", left.data, right.data);
  }
  {
    const [left, right] = await pair("/api/snapshot");
    const observed = (result) => ({
      ...result.data,
      connections: (result.data.connections ?? []).filter((r) => r.pid === 123456),
      new_connections: (result.data.new_connections ?? []).filter((r) => r.pid === 123456),
      rule_stats: result.data.rule_stats.filter((r) => r.rule_id === "block-fixture"),
      logs: (result.data.logs ?? []).filter((r) => r.message === "history fixture"),
    });
    compare("snapshot surface and Go history compatibility", normalizeTimes(observed(left)), normalizeTimes(observed(right)));
  }
  {
    const [left, right] = await pair("/api/dropped", "DELETE", { ids: ["fixture-dropped"] });
    compare("delete one dropped connection", [left.code,left.data], [right.code,right.data]);
    const [a,b] = await pair("/api/dropped");
    assert.equal(a.data.total, 0);
    assert.equal(b.data.total, 0);
  }
  for (const action of ["disable", "enable"]) {
    const [left, right] = await pair(`/api/control/webui/${action}`, "POST");
    compare(`WebUI state ${action}`, withoutClock(left.data), withoutClock(right.data));
    const [a,b] = await pair("/");
    compare(`WebUI content after ${action}`, [a.code,a.bytes], [b.code,b.bytes]);
  }
  {
    const [left,right] = await pair("/api/control/service/pause","POST");
    compare("pause runtime",left.data,right.data);
    const [a,b] = await pair("/");
    compare("paused runtime page", [a.code,a.bytes], [b.code,b.bytes]);
    const [c,d] = await pair("/api/control/service/resume","POST");
    compare("resume runtime",c.data,d.data);
  }
  {
    const [left,right] = await Promise.all([go,rust].map((app) => cli(app,"schema")));
    compare("CLI machine-readable schema", [left.code,JSON.parse(left.stdout)], [right.code,JSON.parse(right.stdout)]);
    const tabs = await Promise.all([go,rust].map((app) => cli(app,"--url",app.base,"rules","list")));
    compare("CLI lists installed rules", JSON.parse(tabs[0].stdout), JSON.parse(tabs[1].stdout));
  }
  for (const app of [go,rust]) {
    const config = (await call(app,"/api/control/agent/config","GET",undefined,headers)).data;
    const before = await call(app,"/api/control/agent/config","PUT",{config}, headers);
    assert.equal(before.code,428);
    const stale = await call(app,"/api/control/agent/config","PUT",{config,expected_updated_at:"2020-01-01T00:00:00Z"}, headers);
    assert.equal(stale.code,409);
    assert.equal(stale.data.error.code,"revision_conflict");
    const candidate = { ...config, retention_minutes:8 };
    const plan = await call(app,"/api/control/agent/config/validate","POST",{config:candidate},headers);
    assert.equal(plan.code,200);
    assert.equal(plan.data.plan.mode,"hot_reload");
    assert.equal(plan.data.applied,false);
    const apply = await call(app,"/api/control/agent/config","PUT",{config:candidate,expected_updated_at:config.updated_at},headers);
    assert.equal(apply.code,200);
    assert.equal(apply.data.applied,true);
    assert.equal(apply.data.config.retention_minutes,8);
    const newAddress = `127.0.0.1:${await port()}`;
    const rebind = await call(app,"/api/control/agent/config","PUT",{
      config:{...apply.data.config,http:{listen:newAddress}},
      expected_updated_at:apply.data.config.updated_at,
    }, headers);
    assert.equal(rebind.code,200);
    assert.equal(rebind.data.plan.mode,"listener_rebind");
    app.base = `http://${newAddress}`;
    assert.equal((await call(app,"/api/health")).data.pid,app.process.pid);
    checks.push(`Revision, preview, apply and listener rebind in ${app.name}`);
  }
  {
    const upstream = await server((socket) => {
      socket.on("data", (data) => {
        if (data.toString().startsWith("CONNECT fixture.test:443 HTTP/1.1")) {
          socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
        } else {
          socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
        }
      });
    });
    try {
      const [left,right] = await pair("/api/proxy-test","POST",{
        proxy:{address:`127.0.0.1:${upstream.address().port}`,type:"http"},
        target:"fixture.test",
      });
      for (const probe of [left,right]) {assert.equal(probe.code,200);delete probe.data.duration_ms;}
      compare("HTTP CONNECT through an isolated local upstream",left.data,right.data);
    } finally {
      upstream.close();
      await once(upstream,"close");
    }
  }
  {
    const [left,right] = await pair("/api/update/status","GET",undefined,webui);
    compare("updater idle state", withoutClock(left.data), withoutClock(right.data));
  }
  console.log(JSON.stringify({ checks }, null, 2));
} finally {
  await Promise.all(installed.map(stop));
}

function withoutClock(actual) {
  const result = { ...actual };
  for (const key of ["updated_at", "disabled_at", "idle_deadline_at"]) delete result[key];
  return result;
}

function normalizeTimes(actual) {
  if (Array.isArray(actual)) return actual.map(normalizeTimes);
  if (typeof actual === "string" && /^\d{4}-\d{2}-\d{2}T/.test(actual)) {
    return new Date(actual).toISOString();
  }
  if (!actual || typeof actual !== "object") return actual;
  return Object.fromEntries(Object.entries(actual).map(([k,v]) => [k, normalizeTimes(v)]));
}
