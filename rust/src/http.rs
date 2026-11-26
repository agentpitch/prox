use crate::app::{ApiError, App, ConfigRequest, VERSION};
use crate::config::{parse_legacy_config, ProxyProfile, Revision};
use crate::monitor::Monitor;
use crate::routing::{bind_listener, test_proxy, wake_listener, Stop};
use crate::upstream::split_host_port;
use crate::webui::static_asset;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_BODY: usize = 8 << 20;
const MAX_CLIENTS: usize = 64;
const AGENT_PREFIX: &str = "/api/control/agent/";
const READ_TIMEOUT: Duration = Duration::from_secs(15);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Server {
    state: Arc<ServerState>,
    task: Option<JoinHandle<()>>,
}

pub struct ServerState {
    address: SocketAddr,
    accept_stop: AtomicBool,
    clients: Mutex<HashMap<u64, TcpStream>>,
    drained: Condvar,
    seq: AtomicU64,
    ready: Stop,
}

impl Server {
    pub fn bind(listen: &str, app: Weak<App>) -> io::Result<Self> {
        let mut addresses: Vec<_> = listen
            .to_socket_addrs()?
            .filter(|addr| addr.ip().to_canonical().is_loopback())
            .collect();
        addresses.sort_by_key(SocketAddr::is_ipv6);
        let mut error = io::Error::new(
            io::ErrorKind::InvalidInput,
            "http.listen must use a loopback host",
        );
        let mut successful = None;
        for address in addresses {
            match bind_listener(address, true) {
                Ok(listener) => {
                    successful = Some(listener);
                    break;
                }
                Err(err) => error = err,
            }
        }
        let listener = successful.ok_or(error)?;
        let state = Arc::new(ServerState {
            address: listener.local_addr()?,
            accept_stop: AtomicBool::new(false),
            clients: Mutex::new(HashMap::new()),
            drained: Condvar::new(),
            seq: AtomicU64::new(0),
            ready: Stop::default(),
        });
        let task = thread::Builder::new()
            .name("pitchprox-http".into())
            .spawn({
                let state = state.clone();
                move || {
                    state.ready.wait_forever();
                    if state.accept_stop.load(Ordering::Acquire) {
                        return;
                    }
                    for stream in listener.incoming() {
                        if state.accept_stop.load(Ordering::Acquire) {
                            return;
                        }
                        let Ok(mut stream) = stream else { continue };
                        let Some(app) = app.upgrade() else { return };
                        let _ = stream.set_nodelay(true);
                        let id = state.seq.fetch_add(1, Ordering::Relaxed);
                        let mut clients = state.clients.lock().unwrap();
                        if clients.len() >= MAX_CLIENTS {
                            drop(clients);
                            let _ = stream.set_write_timeout(Some(Duration::from_millis(100)));
                            let _ = write_response(
                                &mut stream,
                                &Response::text(503, "too many HTTP connections"),
                            );
                            continue;
                        }
                        let Ok(clone) = stream.try_clone() else {
                            continue;
                        };
                        clients.insert(id, clone);
                        drop(clients);
                        let track = Track {
                            id,
                            state: state.clone(),
                        };
                        let _ = thread::Builder::new()
                            .name("pitchprox-http-client".into())
                            .spawn(move || {
                                let track = track;
                                let _ = handle(stream, &app, &track.state);
                            });
                    }
                }
            })?;
        Ok(Self {
            state,
            task: Some(task),
        })
    }

    pub fn activate(&self) {
        self.state.ready.signal();
    }
    pub fn state(&self) -> Arc<ServerState> {
        self.state.clone()
    }

    fn close_listener(&mut self) {
        if let Some(task) = self.task.take() {
            self.state.accept_stop.store(true, Ordering::Release);
            self.state.ready.signal();
            wake_listener(self.state.address);
            let _ = task.join();
        }
    }

    pub fn retire(mut self) {
        self.close_listener();
        let state = self.state.clone();
        let _ = thread::Builder::new()
            .name("pitchprox-http-retirement".into())
            .spawn(move || {
                let clients = state.clients.lock().unwrap();
                let _pair = state
                    .drained
                    .wait_timeout_while(clients, Duration::from_secs(5), |clients| {
                        !clients.is_empty()
                    })
                    .unwrap();
                drop(_pair);
                state.close_connections();
            });
    }

    pub fn close(mut self) {
        self.close_listener();
        self.state.close_connections();
        let clients = self.state.clients.lock().unwrap();
        let _ = self
            .state
            .drained
            .wait_timeout_while(clients, Duration::from_secs(5), |clients| {
                !clients.is_empty()
            })
            .unwrap();
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.close_listener();
    }
}

impl ServerState {
    pub fn drained(&self) -> bool {
        self.clients.lock().unwrap().is_empty()
    }
    pub fn close_connections(&self) {
        for socket in self.clients.lock().unwrap().values() {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
}

struct Track {
    state: Arc<ServerState>,
    id: u64,
}
impl Drop for Track {
    fn drop(&mut self) {
        let mut clients = self.state.clients.lock().unwrap();
        clients.remove(&self.id);
        if clients.is_empty() {
            if clients.capacity() > 16 {
                *clients = HashMap::new();
            }
            self.state.drained.notify_all();
        }
    }
}

#[derive(Default)]
struct Request {
    path: String,
    method: String,
    query: Vec<(String, String)>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Request {
    fn get(&self, name: &str) -> &str {
        self.query
            .iter()
            .find(|(key, _)| key == name)
            .map_or("", |(_, value)| value)
    }
    fn values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.query
            .iter()
            .filter_map(move |(key, value)| (key == name).then_some(value.as_str()))
    }
    fn header(&self, name: &str) -> &str {
        self.headers.get(name).map_or("", String::as_str)
    }
    fn agent(&self) -> bool {
        self.path.starts_with(AGENT_PREFIX)
    }
    fn trusted_ui(&self) -> bool {
        self.header("x-pitchprox-webui") == "1" && trusted_host(self.header("host"))
    }
    fn trusted_agent(&self, peer: SocketAddr) -> bool {
        peer.ip().to_canonical().is_loopback()
            && self.header("x-pitchprox-agent") == "1"
            && trusted_host(self.header("host"))
            && !self.headers.contains_key("origin")
            && matches!(
                self.header("sec-fetch-site").to_ascii_lowercase().as_str(),
                "" | "none"
            )
    }
    fn webui_activity(&self) -> bool {
        if !self.path.starts_with("/api/") {
            return self.method == "GET";
        }
        let marked = self.header("x-pitchprox-webui") == "1" || self.get("_ui") == "1";
        marked
            && (self.path != "/api/ui/visibility"
                || serde_json::from_slice::<Visibility>(&self.body).is_ok_and(|s| s.active))
    }
}

fn control_path(path: &str) -> bool {
    path.starts_with(AGENT_PREFIX)
        || matches!(
            path,
            "/api/health"
                | "/api/tray"
                | "/api/control/stop"
                | "/api/control/webui/status"
                | "/api/control/webui/enable"
                | "/api/control/webui/disable"
                | "/api/control/service/status"
                | "/api/control/service/pause"
                | "/api/control/service/resume"
        )
}

struct Response {
    status: u16,
    mime: &'static str,
    body: std::borrow::Cow<'static, [u8]>,
}
impl Response {
    fn json(status: u16, value: impl serde::Serialize) -> Self {
        let mut body = serde_json::to_vec(&value).unwrap();
        body.push(b'\n');
        Self {
            status,
            mime: "application/json",
            body: body.into(),
        }
    }
    fn text(status: u16, message: impl AsRef<str>) -> Self {
        Self {
            status,
            mime: "text/plain; charset=utf-8",
            body: format!("{}\n", message.as_ref()).into_bytes().into(),
        }
    }
    fn empty(status: u16) -> Self {
        Self {
            status,
            mime: "text/plain; charset=utf-8",
            body: (&[][..]).into(),
        }
    }
    fn agent(error: ApiError) -> Self {
        Self::json(error.status(), json!({"error":error}))
    }
}

fn handle(mut stream: TcpStream, app: &Arc<App>, server: &ServerState) -> io::Result<()> {
    stream.set_read_timeout(Some(READ_TIMEOUT))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let peer = stream.peer_addr()?;
    let mut req = Request::default();
    if let Err((code, message)) = read_request(&mut BufReader::new(&stream), &mut req) {
        let response = if req.agent() {
            Response::agent(ApiError::new(
                if code == 413 {
                    "request_too_large"
                } else {
                    "invalid_json"
                },
                message,
            ))
        } else {
            Response::text(code, message)
        };
        return write_response(&mut stream, &response);
    }
    if !control_path(&req.path) && !app.admit_ui(req.webui_activity()) {
        let response = if req.method == "GET" && !req.path.starts_with("/api/") {
            disabled_page(&app.ui_status())
        } else {
            Response::text(503, "WebUI disabled")
        };
        return write_response(&mut stream, &response);
    }
    if matches!(req.path.as_str(), "/api/snapshot" | "/api/events") {
        app.monitor.mark_ui(true);
    }
    if req.path == "/api/events" {
        return events(stream, app);
    }
    let stop = req.path == "/api/control/stop" && req.method == "POST";
    let resp = route(&req, peer, app, server);
    let result = write_response(&mut stream, &resp);
    if stop {
        let token = app.stop.clone();
        let _ = thread::spawn(move || {
            thread::sleep(Duration::from_millis(150));
            token.signal();
        });
    }
    result
}

fn route(req: &Request, peer: SocketAddr, app: &Arc<App>, server: &ServerState) -> Response {
    if req.agent() {
        return agent(req, peer, app, server);
    }
    match req.path.as_str() {
        "/api/health" => {
            let mut health = json!({"ok":true,"version":VERSION,"pid":std::process::id()});
            if let Some(token) = app.updater.health_token() {
                health["update_token"] = json!(token);
            }
            Response::json(200, health)
        }
        "/api/config" => match req.method.as_str() {
            "GET" => Response::json(200, app.current_config()),
            "PUT" => match parse_legacy_config(&req.body) {
                Ok(cfg) => {
                    let expected = cfg.updated_at;
                    match app.apply(
                        ConfigRequest {
                            config: Some(cfg),
                            expected_updated_at: expected,
                            dry_run: false,
                            allow_disruptive: true,
                        },
                        true,
                    ) {
                        Ok(result) => Response::json(200, result.config),
                        Err(err) => Response::text(err.status(), err.message),
                    }
                }
                Err(err) => Response::text(
                    400,
                    format!("invalid json: {}", err.trim_start_matches("parse config: ")),
                ),
            },
            _ => Response::empty(405),
        },
        "/api/snapshot" => {
            Response::json(200, app.monitor.snapshot(req.get("include_logs") != "0"))
        }
        "/api/tray" => Response::json(200, app.monitor.tray(12)),
        "/api/control/webui/status" => Response::json(200, app.ui_status()),
        "/api/control/service/status" => Response::json(200, app.service_status()),
        "/api/control/service/pause" | "/api/control/service/resume" => {
            post(req, || result(app.pause(req.path.ends_with("/pause")), 500))
        }
        "/api/control/webui/enable" | "/api/control/webui/disable" => post(req, || {
            result(app.webui(req.path.ends_with("/enable")), 500)
        }),
        "/api/control/stop" => post(req, || {
            Response::json(202, json!({"ok":true,"stopping":true}))
        }),
        "/api/ui/visibility" => post(req, || match body::<Visibility>(req, true) {
            Ok(visibility) => {
                app.monitor.mark_ui(visibility.active);
                Response::empty(204)
            }
            Err(err) => err,
        }),
        "/api/proxy-test" => post(req, || {
            let payload = match body::<ProxyTest>(req, false) {
                Ok(payload) => payload,
                Err(err) => return err,
            };
            match test_proxy(&payload.proxy, &payload.target) {
                Ok(value) => {
                    let level = if value["ok"] == true { "info" } else { "warn" };
                    let name = [
                        payload.proxy.name.trim(),
                        &payload.proxy.id,
                        &payload.proxy.address,
                    ]
                    .into_iter()
                    .find(|n| !n.is_empty())
                    .unwrap_or_default();
                    app.monitor.log(
                        level,
                        format!(
                            "proxy test [{name}]: {}",
                            value["message"].as_str().unwrap_or_default()
                        ),
                        None,
                    );
                    Response::json(200, value)
                }
                Err(err) => Response::text(400, err),
            }
        }),
        "/api/dropped" => match req.method.as_str() {
            "GET" => {
                let Some(offset) = number(req.get("offset"), 0) else {
                    return Response::text(400, "invalid offset");
                };
                let Some(limit) = number(req.get("limit"), 100) else {
                    return Response::text(400, "invalid limit");
                };
                result(app.monitor.dropped(req.get("q"), offset, limit), 500)
            }
            "DELETE" => {
                let payload = match body::<Dropped>(req, true) {
                    Ok(payload) => payload,
                    Err(err) => return err,
                };
                let ids = payload.ids.unwrap_or_default();
                if ids.len() > 1000 {
                    return Response::text(400, "too many ids");
                }
                result(
                    app.monitor
                        .delete_dropped(&ids)
                        .map(|()| json!({"deleted":ids.len()})),
                    500,
                )
            }
            _ => Response::empty(405),
        },
        "/api/rules/activity" => activity(req, app, false),
        "/api/rules/condition-activity" => activity(req, app, true),
        "/api/update/status" => update(req, "GET", || Response::json(200, app.updater.status())),
        "/api/update/releases" => update(req, "GET", || {
            result(
                app.updater
                    .check()
                    .map_err(|err| format!("check updates: {err}")),
                500,
            )
        }),
        "/api/update/install" => update(req, "POST", || {
            if req.body.is_empty() {
                return Response::text(400, "request body is required");
            }
            let payload = match body::<Install>(req, false) {
                Ok(payload) => payload,
                Err(err) => return err,
            };
            let version = payload.version.trim();
            if version.is_empty() || version.len() > 128 {
                return Response::text(
                    400,
                    "version must be a non-empty release tag of at most 128 bytes",
                );
            }
            match app.start_install(version) {
                Ok(value) => Response::json(202, value),
                Err(err) => Response::text(409, err),
            }
        }),
        path if path.starts_with("/api/") => Response::text(404, "not found"),
        path => match static_asset(path) {
            Some(asset) => Response {
                status: 200,
                mime: asset.content_type,
                body: asset.bytes.into(),
            },
            None => Response::text(404, "not found"),
        },
    }
}

fn activity(req: &Request, app: &App, condition: bool) -> Response {
    if req.method != "GET" {
        return Response::empty(405);
    }
    let mut ids = Vec::<String>::new();
    let mut seen = HashSet::new();
    if condition {
        let mut items = req.values("id");
        let id = items.next().map_or("", str::trim);
        if id.is_empty() || items.next().is_some() {
            return Response::text(400, "exactly one non-empty rule id is required");
        }
        ids.push(id.into());
    } else {
        for id in req.values("id").map(str::trim).filter(|id| !id.is_empty()) {
            if !seen.insert(id) {
                continue;
            }
            if ids.len() == 50 {
                return Response::text(400, "at most 50 rule ids are allowed");
            }
            ids.push(id.into());
        }
    }
    let points = number(req.get("points"), 40).filter(|v| (2..=60).contains(v));
    if !condition && points.is_none() {
        return Response::text(400, "points must be in 2..60");
    }
    let Some(minutes) = number(req.get("window_minutes"), 15).filter(|v| (1..=60).contains(v))
    else {
        return Response::text(400, "window_minutes must be in 1..60");
    };
    let minutes = (minutes as i64).min(app.current_config().retention_minutes);
    if condition {
        let Some(limit) = number(req.get("limit"), 20).filter(|v| (1..=100).contains(v)) else {
            return Response::text(400, "limit must be in 1..100");
        };
        result(app.monitor.conditions(&ids[0], minutes, limit), 500)
    } else {
        result(app.monitor.timeline(&ids, minutes, points.unwrap()), 500)
    }
}

fn agent(req: &Request, peer: SocketAddr, app: &Arc<App>, server: &ServerState) -> Response {
    let fail = |code, message: &str| Response::agent(ApiError::new(code, message));
    if !req.trusted_agent(peer) {
        return fail("forbidden", "local agent request required");
    }
    match (req.path.as_str(), req.method.as_str()) {
        ("/api/control/agent/status", "GET") => {
            Response::json(200, app.agent_status(server.address))
        }
        ("/api/control/agent/config", "GET") => Response::json(200, app.current_config()),
        ("/api/control/agent/config", "PUT") | ("/api/control/agent/config/validate", "POST") => {
            let validate = req.path.ends_with("/validate");
            let input = req
                .body
                .strip_prefix(&[0xef, 0xbb, 0xbf])
                .unwrap_or(&req.body);
            if std::str::from_utf8(input).is_err() {
                return fail("invalid_json", "JSON must be valid UTF-8");
            }
            let mut request = match serde_json::from_slice::<ConfigRequest>(input) {
                Ok(request) => request,
                Err(err) => return fail("invalid_json", &err.to_string()),
            };
            let syntax = serde_json::from_slice::<Value>(input).unwrap();
            if let Some(object) = syntax.get("config") {
                if let Err(err) = strict_config(object) {
                    return fail("invalid_json", &err);
                }
            }
            if request.config.is_none() {
                return fail("invalid_config", "config object is required");
            }
            if !validate && request.expected_updated_at == Revision::default() {
                return fail(
                    "revision_required",
                    "expected_updated_at is required; read the current configuration first",
                );
            }
            if validate {
                request.dry_run = true;
            }
            match app.apply(request, false) {
                Ok(result) => Response::json(200, result),
                Err(err) => Response::agent(err),
            }
        }
        (
            "/api/control/agent/status"
            | "/api/control/agent/config"
            | "/api/control/agent/config/validate",
            _,
        ) => fail("method_not_allowed", "method not allowed"),
        _ => fail("not_found", "unknown agent endpoint"),
    }
}

pub(crate) fn strict_config(config: &Value) -> Result<(), String> {
    fn object(data: &Value, allowed: &[&str], nullable: &[&str]) -> Result<(), String> {
        let entries = data
            .as_object()
            .ok_or_else(|| "config must be a JSON object".to_owned())?;
        for (key, value) in entries {
            if !allowed.contains(&key.as_str()) {
                return Err(format!("unknown JSON field {key:?}"));
            }
            if value.is_null() && !nullable.contains(&key.as_str()) {
                return Err(format!("field {key:?}: null is not allowed"));
            }
        }
        Ok(())
    }
    object(
        config,
        &[
            "version",
            "updated_at",
            "retention_minutes",
            "dropped_log_max_bytes",
            "http",
            "transparent",
            "proxies",
            "chains",
            "rules",
        ],
        &["proxies", "chains", "rules"],
    )?;
    if let Some(http) = config.get("http") {
        object(http, &["listen"], &[])?;
    }
    if let Some(transparent) = config.get("transparent") {
        object(
            transparent,
            &[
                "ipv4_listener",
                "ipv6_listener",
                "listener_port",
                "sniff_bytes",
                "sniff_timeout_ms",
            ],
            &[],
        )?;
    }
    for (field, allowed, nullable) in [
        (
            "proxies",
            &[
                "id", "name", "type", "address", "username", "password", "enabled",
            ][..],
            &[][..],
        ),
        (
            "chains",
            &["id", "name", "proxy_ids", "enabled"][..],
            &["proxy_ids"][..],
        ),
        (
            "rules",
            &[
                "id",
                "name",
                "enabled",
                "applications",
                "target_hosts",
                "target_ports",
                "action",
                "proxy_id",
                "chain_id",
                "notes",
            ][..],
            &[][..],
        ),
    ] {
        if let Some(items) = config.get(field).and_then(Value::as_array) {
            for item in items {
                object(item, allowed, nullable)?;
            }
        }
    }
    Ok(())
}

fn result<T: std::fmt::Display>(value: Result<Value, T>, code: u16) -> Response {
    match value {
        Ok(v) => Response::json(200, v),
        Err(err) => Response::text(code, err.to_string()),
    }
}
fn post(req: &Request, serve: impl FnOnce() -> Response) -> Response {
    if req.method == "POST" {
        serve()
    } else {
        Response::empty(405)
    }
}
fn update(req: &Request, method: &str, serve: impl FnOnce() -> Response) -> Response {
    if req.method != method {
        Response::empty(405)
    } else if !req.trusted_ui() {
        Response::text(403, "trusted WebUI request required")
    } else {
        serve()
    }
}
#[derive(Default, Deserialize)]
#[serde(default)]
struct Visibility {
    active: bool,
}
#[derive(Default, Deserialize)]
#[serde(default)]
struct ProxyTest {
    proxy: ProxyProfile,
    target: String,
}
#[derive(Default, Deserialize)]
#[serde(default)]
struct Dropped {
    ids: Option<Vec<String>>,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Install {
    version: String,
}
fn body<T: Default + serde::de::DeserializeOwned>(
    req: &Request,
    empty_ok: bool,
) -> Result<T, Response> {
    if empty_ok && req.body.is_empty() {
        return Ok(T::default());
    }
    serde_json::from_slice(&req.body)
        .map_err(|err| Response::text(400, format!("invalid json: {err}")))
}

fn read_request(reader: &mut impl BufRead, req: &mut Request) -> Result<(), (u16, String)> {
    let line = line(reader).map_err(|e| (400, e))?;
    let pieces: Vec<_> = line.splitn(3, ' ').collect();
    if pieces.len() != 3 {
        return Err((400, "invalid request line".into()));
    }
    req.method = pieces[0].trim().to_ascii_uppercase();
    let target = pieces[1];
    if !target.starts_with('/') && target != "*" {
        return Err((400, "invalid request path".into()));
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    req.path = decode_component(path, false).ok_or((400, "invalid request path".into()))?;
    req.query = query
        .split('&')
        .filter(|v| !v.is_empty() && !v.contains(';'))
        .filter_map(|p| {
            let (key, value) = p.split_once('=').unwrap_or((p, ""));
            Some((decode_component(key, true)?, decode_component(value, true)?))
        })
        .collect();
    let mut size = 0;
    let mut count = 0;
    let mut body = 0;
    loop {
        let line = crate::http::line(reader).map_err(|e| (400, e))?;
        if line.is_empty() {
            break;
        }
        size += line.len();
        count += 1;
        if size > 32 << 10 || count > 100 {
            return Err((400, "request headers too large".into()));
        }
        let (key, value) = line.split_once(':').ok_or((400, "invalid header".into()))?;
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim();
        if req.agent() && req.headers.contains_key(&key) {
            return Err((400, format!("duplicate request header {key:?}")));
        }
        if key == "transfer-encoding" && value.to_ascii_lowercase().contains("chunked") {
            return Err((400, "chunked requests are not supported".into()));
        }
        if key == "content-length" {
            body = value
                .parse::<usize>()
                .map_err(|_| (400, "invalid content length".into()))?;
            if body > MAX_BODY {
                return Err((
                    if req.agent() { 413 } else { 400 },
                    "request body is too large".into(),
                ));
            }
            if req.path == "/api/update/install" && body > 512 {
                return Err((413, "request body is too large".into()));
            }
        }
        req.headers.insert(key, value.into());
    }
    if body != 0 {
        req.body.resize(body, 0);
        reader
            .read_exact(&mut req.body)
            .map_err(|err| (400, err.to_string()))?;
    }
    Ok(())
}

fn line(reader: &mut impl BufRead) -> Result<String, String> {
    let mut bytes = Vec::new();
    reader
        .take(4097)
        .read_until(b'\n', &mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.is_empty() {
        return Err("EOF".into());
    }
    if bytes.len() > 4096 || bytes.last() != Some(&b'\n') {
        return Err("request line too long".into());
    }
    let line = String::from_utf8_lossy(&bytes);
    Ok(line.trim_end_matches(['\r', '\n']).to_owned())
}

fn number(raw: &str, fallback: usize) -> Option<usize> {
    let raw = raw.trim();
    if raw.is_empty() {
        Some(fallback)
    } else {
        raw.parse().ok()
    }
}
fn decode_component(s: &str, query: bool) -> Option<String> {
    let mut buffer = Vec::with_capacity(s.len());
    let mut iter = s.bytes();
    while let Some(b) = iter.next() {
        match b {
            b'%' => {
                let hi = char::from(iter.next()?).to_digit(16)?;
                let lo = char::from(iter.next()?).to_digit(16)?;
                buffer.push((hi * 16 + lo) as u8);
            }
            b'+' if query => buffer.push(b' '),
            _ => buffer.push(b),
        }
    }
    Some(String::from_utf8_lossy(&buffer).into_owned())
}

pub fn trusted_host(host: &str) -> bool {
    let host = host.trim();
    let (host, port) = split_host_port(host).map_or((host, None), |(h, p)| (h, Some(p)));
    if port.is_some_and(|p| p.parse::<std::num::NonZeroU16>().is_err()) {
        return false;
    }
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    let host = host.trim().trim_end_matches('.');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.to_canonical().is_loopback())
}

fn write_response(stream: &mut TcpStream, resp: &Response) -> io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        resp.status,
        status_text(resp.status),
        resp.mime,
        resp.body.len()
    )?;
    stream.write_all(&resp.body)
}
fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        428 => "Precondition Required",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

pub struct Subscription {
    monitor: Arc<Monitor>,
    id: u64,
    incoming: Receiver<Arc<[u8]>>,
}
impl Subscription {
    pub fn new(monitor: Arc<Monitor>) -> Self {
        let (id, incoming) = monitor.subscribe();
        Self {
            monitor,
            id,
            incoming,
        }
    }
}
impl Drop for Subscription {
    fn drop(&mut self) {
        self.monitor.unsubscribe(self.id);
    }
}

fn events(mut stream: TcpStream, app: &App) -> io::Result<()> {
    let Some(subscription) = app.subscribe() else {
        return write_response(&mut stream, &Response::text(503, "WebUI disabled"));
    };
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n")?;
    stream.set_read_timeout(None)?;
    let mut peer = stream.try_clone()?;
    let eof = AtomicBool::new(false);
    thread::scope(|scope| {
        scope.spawn(|| {
            let _ = peer.read(&mut [0]);
            eof.store(true, Ordering::Release);
        });
        let result = (|| {
            let mut ping = Instant::now();
            while !eof.load(Ordering::Acquire) && !app.stop.stopped() {
                match subscription
                    .incoming
                    .recv_timeout(Duration::from_millis(250))
                {
                    Ok(payload) => {
                        stream.write_all(b"data: ")?;
                        stream.write_all(&payload)?;
                        stream.write_all(b"\n\n")?;
                    }
                    Err(RecvTimeoutError::Disconnected) => break,
                    Err(RecvTimeoutError::Timeout) => {}
                }
                if ping.elapsed() >= Duration::from_secs(25) {
                    stream.write_all(b": ping\n\n")?;
                    ping = Instant::now();
                }
            }
            Ok(())
        })();
        let _ = stream.shutdown(Shutdown::Both);
        result
    })
}

fn disabled_page(status: &Value) -> Response {
    let mut title = "WebUI отключён";
    let mut detail = "Интерфейс управления отключён. Проксирование продолжает работать.";
    let mut hint = "Чтобы снова включить интерфейс, выберите «Включить WebUI» в меню значка pitchProx в системном трее.";
    if status["paused"] == true {
        title = "Сервис приостановлен";
        detail = "Сервис и WebUI приостановлены пользователем.";
        hint = "Чтобы возобновить работу, выберите «Запустить» в меню значка pitchProx в системном трее.";
    } else if status["auto_paused"] == true {
        title = "WebUI приостановлен";
        detail = "В течение часа не было обращений из браузера, поэтому WebUI был автоматически приостановлен. Проксирование продолжает работать.";
    }
    let body = format!(
        r#"<!doctype html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{title} — pitchProx</title><style>body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#f5f8fc;color:#16233a;font:16px system-ui,-apple-system,Segoe UI,sans-serif}}.card{{max-width:560px;margin:24px;padding:32px;border:1px solid #dce5f2;border-radius:18px;background:#fff;box-shadow:0 16px 44px #183d7514}}h1{{margin:0 0 12px;font-size:26px}}p{{line-height:1.55;color:#52627a}}.brand{{color:#086cf0;font-weight:750}}.hint{{margin-top:22px;padding:14px 16px;border-radius:12px;background:#edf5ff;color:#24466f}}</style></head><body><main class="card"><div class="brand">pitchProx</div><h1>{title}</h1><p>{detail}</p><p class="hint">{hint}</p></main></body></html>"#
    );
    Response {
        status: 503,
        mime: "text/html; charset=utf-8",
        body: body.into_bytes().into(),
    }
}
