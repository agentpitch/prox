use crate::config::{Config, Revision, Store};
use crate::http::Server;
use crate::monitor::Monitor;
use crate::routing::{Active, Routes, SharedRoutes, Stop};
use crate::updater::Updater;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub const VERSION: &str = match option_env!("PITCHPROX_VERSION") {
    Some(version) if !version.is_empty() => version,
    _ => "dev",
};
const IDLE: Duration = Duration::from_secs(3600);

pub struct App {
    life: Mutex<Life>,
    routes: SharedRoutes,
    pub monitor: Arc<Monitor>,
    pub stop: Arc<Stop>,
    pub updater: Arc<Updater>,
    idle: Condvar,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

struct Life {
    store: Store,
    runtime: Option<Active>,
    listener: Option<Server>,
    retiring: Vec<Arc<crate::http::ServerState>>,
    ui: Ui,
    paused: bool,
    stopping: bool,
}

struct Ui {
    disabled: Option<(&'static str, DateTime<Utc>)>,
    deadline: Instant,
    wall_deadline: DateTime<Utc>,
}

impl Ui {
    fn enabled(&self) -> bool {
        self.disabled.is_none()
    }
    fn touch(&mut self) {
        self.deadline = Instant::now() + IDLE;
        self.wall_deadline = Utc::now() + chrono::Duration::hours(1);
    }
    fn view(&self, paused: bool) -> Value {
        let mut response = json!({"enabled":self.enabled(),"paused":paused,
            "auto_paused":self.disabled.is_some_and(|(cause, _)| cause == "idle"),
            "idle_timeout_seconds":IDLE.as_secs()});
        if let Some((cause, date)) = self.disabled {
            response["disabled_reason"] = json!(cause);
            response["disabled_at"] = json!(date);
        } else {
            response["idle_deadline_at"] = json!(self.wall_deadline);
        }
        response
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ConfigRequest {
    pub config: Option<Config>,
    pub expected_updated_at: Revision,
    pub dry_run: bool,
    pub allow_disruptive: bool,
}

#[derive(Serialize)]
pub struct Plan {
    mode: &'static str,
    runtime_restart: bool,
    http_rebind: bool,
    connections_preserved: bool,
    listening_address: String,
    reasons: Vec<&'static str>,
}

#[derive(Serialize)]
pub struct ConfigResult {
    pub config: Config,
    plan: Plan,
    applied: bool,
    previous_updated_at: Revision,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current_updated_at: Option<Revision>,
}

impl ApiError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            current_updated_at: None,
        }
    }
    pub fn status(&self) -> u16 {
        match self.code {
            "invalid_config" | "invalid_json" => 400,
            "forbidden" => 403,
            "not_found" => 404,
            "method_not_allowed" => 405,
            "revision_conflict" | "disruptive_change" | "update_busy" => 409,
            "request_too_large" => 413,
            "revision_required" => 428,
            "unavailable" => 503,
            _ => 500,
        }
    }
}

impl App {
    pub fn open(
        config_path: PathBuf,
        history_path: PathBuf,
        mode: &'static str,
    ) -> Result<Arc<Self>, String> {
        let store = Store::load_or_create(config_path)?;
        let cfg = store.current().clone();
        let routes = Arc::new(Routes::compile(cfg.clone())?);
        let monitor = Monitor::open(
            history_path,
            cfg.retention_minutes,
            cfg.dropped_log_max_bytes as u64,
        )
        .map_err(|e| format!("create history dir: {e}"))?;
        let stop = Arc::new(Stop::default());
        let updater = Arc::new(Updater::new(mode, stop.clone())?);
        Ok(Arc::new(Self {
            routes: Arc::new(RwLock::new(routes)),
            monitor,
            stop,
            updater,
            idle: Condvar::new(),
            workers: Mutex::new(Vec::new()),
            life: Mutex::new(Life {
                store,
                runtime: None,
                listener: None,
                retiring: Vec::new(),
                paused: false,
                stopping: false,
                ui: Ui {
                    disabled: None,
                    deadline: Instant::now() + IDLE,
                    wall_deadline: Utc::now() + chrono::Duration::hours(1),
                },
            }),
        }))
    }

    pub fn start(self: &Arc<Self>) -> Result<(), String> {
        let mut life = self.life.lock().unwrap();
        life.runtime = Some(
            Active::start(self.routes.clone(), self.monitor.clone()).map_err(|e| e.to_string())?,
        );
        let http = Server::bind(&life.store.current().http.listen, Arc::downgrade(self))
            .map_err(|e| e.to_string())?;
        http.activate();
        life.listener = Some(http);
        life.ui.touch();
        let monitor = self.monitor.clone();
        let history = thread::Builder::new()
            .name("pitchprox-history".into())
            .spawn(move || monitor.worker())
            .map_err(|e| e.to_string())?;
        self.workers.lock().unwrap().push(history);
        let app = self.clone();
        let idle = thread::Builder::new()
            .name("pitchprox-ui-timeout".into())
            .spawn(move || app.idle_worker())
            .map_err(|e| e.to_string())?;
        self.workers.lock().unwrap().push(idle);
        #[cfg(windows)]
        if let Some(worker) = crate::diagnostics::start(self.clone()) {
            self.workers.lock().unwrap().push(worker);
        }
        Ok(())
    }

    pub fn shutdown(&self) -> Result<(), String> {
        self.stop.signal();
        let (server, retiring, runtime) = {
            let mut life = self.life.lock().unwrap();
            if life.stopping {
                return Ok(());
            }
            life.stopping = true;
            self.idle.notify_all();
            (
                life.listener.take(),
                std::mem::take(&mut life.retiring),
                life.runtime.take(),
            )
        };
        if let Some(server) = server {
            server.close();
        }
        for server in retiring {
            server.close_connections();
        }
        drop(runtime);
        self.updater.close();
        let flushed = self.monitor.close().map_err(|e| e.to_string());
        for worker in self.workers.lock().unwrap().drain(..) {
            let _ = worker.join();
        }
        flushed
    }

    pub fn current_config(&self) -> Config {
        self.routes.read().unwrap().config.clone()
    }
    pub fn address(&self) -> String {
        self.routes.read().unwrap().config.http.listen.clone()
    }
    #[cfg(windows)]
    pub(crate) fn diagnostics(&self) -> Value {
        let life = self.life.lock().unwrap();
        json!({
            "interception_enabled": !self.routes.read().unwrap().engine.all_enabled_direct(),
            "runtime_running": life.runtime.is_some(),
            "flow_table_len": life.runtime.as_ref().map_or(0,Active::flow_count),
            "monitor": self.monitor.diagnostics()
        })
    }
    pub fn url(&self) -> String {
        format!("http://{}", self.address())
    }
    pub fn ui_status(&self) -> Value {
        let life = self.life.lock().unwrap();
        life.ui.view(life.paused)
    }
    pub fn service_status(&self) -> Value {
        let life = self.life.lock().unwrap();
        service_status(&life)
    }
    pub fn agent_status(&self, listening: SocketAddr) -> Value {
        let life = self.life.lock().unwrap();
        json!({"protocol_version":1,"version":VERSION,"pid":std::process::id(),
            "updated_at":life.store.current().updated_at,"listening_address":listening,
            "service_paused":life.paused,"webui_enabled":life.ui.enabled()})
    }
    pub fn admit_ui(&self, browser: bool) -> bool {
        let mut life = self.life.lock().unwrap();
        if !life.ui.enabled() || life.stopping {
            return false;
        }
        if browser {
            life.ui.touch();
            self.idle.notify_all();
        }
        true
    }

    pub fn subscribe(&self) -> Option<crate::http::Subscription> {
        let life = self.life.lock().unwrap();
        life.ui
            .enabled()
            .then(|| crate::http::Subscription::new(self.monitor.clone()))
    }

    pub fn webui(&self, enabled: bool) -> Result<Value, String> {
        let mut life = self.life.lock().unwrap();
        if life.stopping {
            return Err("program is stopping".into());
        }
        if enabled {
            self.resume_locked(&mut life)?;
        }
        self.set_ui(&mut life, enabled, "manual");
        Ok(life.ui.view(life.paused))
    }

    pub fn pause(&self, pause: bool) -> Result<Value, String> {
        let mut life = self.life.lock().unwrap();
        if life.stopping {
            return Err("program is stopping".into());
        }
        if pause && !life.paused {
            life.paused = true;
            self.set_ui(&mut life, false, "manual");
            life.runtime.take();
        } else if !pause {
            self.resume_locked(&mut life)?;
            self.set_ui(&mut life, true, "manual");
        }
        Ok(service_status(&life))
    }

    fn resume_locked(&self, life: &mut Life) -> Result<(), String> {
        if life.paused {
            life.runtime = Some(
                Active::start(self.routes.clone(), self.monitor.clone())
                    .map_err(|e| e.to_string())?,
            );
            life.paused = false;
        }
        Ok(())
    }

    fn set_ui(&self, life: &mut Life, enabled: bool, cause: &'static str) {
        let changed = enabled != life.ui.enabled();
        if enabled {
            life.ui.disabled = None;
            life.ui.touch();
        } else if changed {
            life.ui.disabled = Some((cause, Utc::now()));
            self.monitor.disable_ui(life.ui.view(life.paused));
        }
        if changed {
            self.monitor.log(
                "info",
                if enabled {
                    "WebUI enabled"
                } else {
                    "WebUI disabled"
                },
                None,
            );
        }
        self.idle.notify_all();
    }

    fn idle_worker(&self) {
        let mut life = self.life.lock().unwrap();
        while !life.stopping {
            if !life.ui.enabled() {
                life = self.idle.wait(life).unwrap();
                continue;
            }
            let timeout = life.ui.deadline.saturating_duration_since(Instant::now());
            if timeout.is_zero() {
                self.monitor.log("info", "WebUI automatically paused after 1h0m0s without browser requests; proxy runtime remains active", None);
                self.set_ui(&mut life, false, "idle");
            } else {
                life = self.idle.wait_timeout(life, timeout).unwrap().0;
            }
        }
    }

    pub fn apply(
        self: &Arc<Self>,
        request: ConfigRequest,
        legacy: bool,
    ) -> Result<ConfigResult, ApiError> {
        let mut life = self.life.lock().unwrap();
        if life.stopping {
            return Err(ApiError::new("unavailable", "program is stopping"));
        }
        if self.updater.busy() {
            return Err(ApiError::new(
                "update_busy",
                "configuration cannot be changed while an application update is running",
            ));
        }
        let old = self.routes.read().unwrap().clone();
        let revision = old.config.updated_at;
        let revision_is_zero = request.expected_updated_at == Revision::default();
        let fail = |code, message: String| ApiError {
            code,
            message,
            current_updated_at: Some(revision),
        };
        if !legacy && !request.dry_run && revision_is_zero {
            return Err(fail(
                "revision_required",
                "expected_updated_at is required when applying configuration".into(),
            ));
        }
        if !revision_is_zero && request.expected_updated_at != revision {
            return Err(fail(
                "revision_conflict",
                "configuration changed since it was loaded".into(),
            ));
        }
        let config = request
            .config
            .ok_or_else(|| ApiError::new("invalid_config", "config object is required"))?;
        let mut candidate = Routes::compile(
            config
                .canonicalize()
                .map_err(|e| fail("invalid_config", e))?,
        )
        .map_err(|e| fail("invalid_config", e))?;
        let plan = plan(&old, &candidate, life.runtime.is_some());
        if request.dry_run || plan.mode == "no_change" {
            return Ok(ConfigResult {
                config: if request.dry_run {
                    candidate.config
                } else {
                    old.config.clone()
                },
                plan,
                applied: false,
                previous_updated_at: revision,
            });
        }
        if plan.runtime_restart && !request.allow_disruptive {
            return Err(fail("disruptive_change", "this change restarts routing and closes intercepted connections; review the plan and set allow_disruptive to apply".into()));
        }
        let replacement = if plan.http_rebind && life.listener.is_some() {
            Some(
                Server::bind(&candidate.config.http.listen, Arc::downgrade(self)).map_err(|e| {
                    fail(
                        "activation_failed",
                        format!("bind replacement HTTP listener: {e}"),
                    )
                })?,
            )
        } else {
            None
        };
        if plan.runtime_restart {
            life.runtime.take();
            *self.routes.write().unwrap() = Arc::new(
                Routes::compile(candidate.config.clone()).map_err(|e| fail("invalid_config", e))?,
            );
            match Active::start(self.routes.clone(), self.monitor.clone()) {
                Ok(runtime) => life.runtime = Some(runtime),
                Err(err) => {
                    let restore = self.restore_runtime(&mut life, old.clone());
                    return Err(fail(
                        "activation_failed",
                        combine_activation_error(err, restore),
                    ));
                }
            }
        }
        match life.store.save(candidate.config) {
            Ok(saved) => candidate.config = saved.clone(),
            Err(err) => {
                if plan.runtime_restart {
                    let restore = self.restore_runtime(&mut life, old.clone());
                    return Err(fail(
                        "activation_failed",
                        combine_activation_error(err, restore),
                    ));
                }
                return Err(fail("activation_failed", err));
            }
        }
        let saved = candidate.config.clone();
        *self.routes.write().unwrap() = Arc::new(candidate);
        self.monitor
            .settings(saved.retention_minutes, saved.dropped_log_max_bytes as u64);
        if let Some(server) = replacement {
            server.activate();
            if let Some(old) = life.listener.replace(server) {
                life.retiring.retain(|listener| !listener.drained());
                life.retiring.push(old.state());
                old.retire();
            }
            self.monitor.log(
                "info",
                format!("control HTTP listener moved to {}", saved.http.listen),
                None,
            );
        }
        Ok(ConfigResult {
            config: saved,
            plan,
            applied: true,
            previous_updated_at: revision,
        })
    }

    fn restore_runtime(&self, life: &mut Life, old: Arc<Routes>) -> io::Result<()> {
        life.runtime.take();
        *self.routes.write().unwrap() = old;
        life.runtime = Some(Active::start(self.routes.clone(), self.monitor.clone())?);
        Ok(())
    }

    pub fn start_install(self: &Arc<Self>, version: &str) -> Result<Value, String> {
        let life = self.life.lock().unwrap();
        if life.stopping {
            return Err("program is stopping".into());
        }
        self.updater
            .install(version, life.store.current().http.listen.clone())
    }
}

fn combine_activation_error(error: impl std::fmt::Display, restored: io::Result<()>) -> String {
    restored.err().map_or_else(
        || error.to_string(),
        |restore| format!("{error}; restore previous runtime: {restore}"),
    )
}
fn service_status(life: &Life) -> Value {
    json!({"paused":life.paused,"webui_enabled":life.ui.enabled()})
}
fn plan(old: &Routes, new: &Routes, running: bool) -> Plan {
    let mut a = old.config.clone();
    let mut b = new.config.clone();
    a.updated_at = Revision::default();
    b.updated_at = Revision::default();
    let mut plan = Plan {
        mode: "no_change",
        runtime_restart: false,
        http_rebind: false,
        connections_preserved: true,
        listening_address: b.http.listen.clone(),
        reasons: Vec::new(),
    };
    if a == b {
        return plan;
    }
    plan.mode = "hot_reload";
    if a.http.listen != b.http.listen {
        plan.mode = "listener_rebind";
        plan.http_rebind = true;
        plan.reasons
            .push("HTTP listener moves to a new address without restarting the process");
    }
    if running
        && (a.transparent != b.transparent
            || old.engine.all_enabled_direct() != new.engine.all_enabled_direct())
    {
        plan.mode = "runtime_restart";
        plan.runtime_restart = true;
        plan.connections_preserved = false;
        plan.reasons.push("Changing transparent listener/sniff settings or entering/leaving interception restarts the routing runtime and closes intercepted connections");
    } else {
        plan.reasons.push("New rules and proxy settings apply to new connections; existing connections keep their established route");
    }
    plan
}

pub fn config_path(migrate: bool) -> PathBuf {
    if let Some(path) = override_path("PITCHPROX_CONFIG", "MYPROX_CONFIG") {
        return path;
    }
    let Ok(exe) = env::current_exe() else {
        return default_data_dir().join("config.json");
    };
    let dest = exe.with_file_name("pitchProx.config.json");
    if migrate && !dest.exists() {
        let mut candidates = vec![exe.with_file_name("myprox.config.json")];
        if let Some(program_data) = env::var_os("ProgramData") {
            let base = PathBuf::from(program_data);
            candidates.extend([
                base.join("pitchProx/config.json"),
                base.join("MyProx/config.json"),
            ]);
        }
        if let Some(dir) = user_config_dir() {
            candidates.extend([
                dir.join("pitchprox/config.json"),
                dir.join("myprox/config.json"),
            ]);
        }
        for source in candidates {
            if let Ok(data) = std::fs::read(source) {
                let _ = std::fs::write(&dest, data);
                break;
            }
        }
    }
    dest
}

pub fn history_path() -> PathBuf {
    override_path("PITCHPROX_HISTORY", "MYPROX_HISTORY").unwrap_or_else(|| {
        env::current_exe()
            .map(|p| p.with_file_name("pitchProx.history"))
            .unwrap_or_else(|_| default_data_dir().join("pitchProx.history"))
    })
}

fn override_path(new: &str, legacy: &str) -> Option<PathBuf> {
    [new, legacy]
        .into_iter()
        .filter_map(env::var_os)
        .find(|v| !v.is_empty())
        .map(PathBuf::from)
}
fn default_data_dir() -> PathBuf {
    if cfg!(windows) {
        if let Some(base) = env::var_os("ProgramData").filter(|v| !v.is_empty()) {
            return Path::new(&base).join("pitchProx");
        }
    }
    user_config_dir()
        .unwrap_or_else(env::temp_dir)
        .join("pitchprox")
}
fn user_config_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        env::var_os("APPDATA").map(PathBuf::from)
    } else {
        env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| env::var_os("HOME").map(|base| Path::new(&base).join(".config")))
    }
}
