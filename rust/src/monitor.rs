use crate::rules::{Action, Decision, MatchDetails};
use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

const FLUSH: Duration = Duration::from_secs(3);
const UI_WINDOW: Duration = Duration::from_secs(90);
const CONDITION_BUCKET: i64 = 15;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Connection {
    #[serde(rename = "ID")]
    pub id: String,
    #[serde(rename = "PID")]
    pub pid: u32,
    pub exe_path: String,
    #[serde(rename = "SourceIP")]
    pub source_ip: String,
    pub source_port: u16,
    #[serde(rename = "OriginalIP")]
    pub original_ip: String,
    pub original_port: u16,
    pub hostname: String,
    #[serde(rename = "RuleID")]
    pub rule_id: String,
    pub rule_name: String,
    pub action: String,
    #[serde(rename = "ProxyID")]
    pub proxy_id: String,
    #[serde(rename = "ChainID")]
    pub chain_id: String,
    pub state: String,
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub created_at: DateTime<Utc>,
    pub last_updated_at: DateTime<Utc>,
    pub count: u64,
}

pub fn action_name(action: Action) -> &'static str {
    match action {
        Action::Direct => "direct",
        Action::Proxy => "proxy",
        Action::Chain => "chain",
        Action::Block => "block",
    }
}

impl Connection {
    pub fn new(
        pid: u32,
        exe: &str,
        client: SocketAddr,
        dest: SocketAddr,
        host: &str,
        decision: Decision<'_>,
        state: &str,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: format!(
                "{pid}|{}|{}|{}|{}",
                client.ip(),
                client.port(),
                dest.ip(),
                dest.port()
            ),
            pid,
            exe_path: exe.into(),
            source_ip: client.ip().to_string(),
            source_port: client.port(),
            original_ip: dest.ip().to_string(),
            original_port: dest.port(),
            hostname: host.into(),
            rule_id: decision.rule.map_or("", |r| &r.id).into(),
            rule_name: decision.rule.map_or("", |r| &r.name).into(),
            action: action_name(decision.action()).into(),
            proxy_id: decision.rule.map_or("", |r| &r.proxy_id).into(),
            chain_id: decision.rule.map_or("", |r| &r.chain_id).into(),
            state: state.into(),
            bytes_up: 0,
            bytes_down: 0,
            created_at: now,
            last_updated_at: now,
            count: 1,
        }
    }

    fn view(&self) -> Value {
        let mut result = json!({
            "id": self.id, "pid": self.pid, "exe_path": self.exe_path, "source_ip": self.source_ip,
            "source_port": self.source_port, "original_ip": self.original_ip,
            "original_port": self.original_port, "action": self.action, "state": self.state,
            "bytes_up": self.bytes_up, "bytes_down": self.bytes_down, "created_at": self.created_at,
            "last_updated_at": self.last_updated_at,
        });
        if self.count != 0 {
            result["count"] = json!(self.count);
        }
        for (key, value) in [
            ("hostname", &self.hostname),
            ("rule_id", &self.rule_id),
            ("rule_name", &self.rule_name),
            ("proxy_id", &self.proxy_id),
            ("chain_id", &self.chain_id),
        ] {
            if !value.is_empty() {
                result[key] = json!(value);
            }
        }
        result
    }

    fn novelty_key(&self) -> (String, &str, u16) {
        (
            self.exe_path.to_lowercase(),
            &self.original_ip,
            self.original_port,
        )
    }

    fn aggregate_key(&self) -> String {
        let separator = "\x1f";
        [
            self.pid.to_string(),
            self.exe_path.clone(),
            self.original_ip.clone(),
            self.original_port.to_string(),
            self.hostname.clone(),
            self.rule_id.clone(),
            self.rule_name.clone(),
            self.action.clone(),
            self.proxy_id.clone(),
            self.chain_id.clone(),
        ]
        .join(separator)
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", default)]
struct Log {
    time: DateTime<Utc>,
    level: String,
    message: String,
    #[serde(rename = "ConnectionID")]
    connection_id: String,
    #[serde(rename = "PID")]
    pid: u32,
    exe_path: String,
    action: String,
    #[serde(rename = "RuleID")]
    rule_id: String,
    rule_name: String,
    host: String,
    port: u16,
}

impl Default for Log {
    fn default() -> Self {
        Self {
            time: Utc::now(),
            level: String::new(),
            message: String::new(),
            connection_id: String::new(),
            pid: 0,
            exe_path: String::new(),
            action: String::new(),
            rule_id: String::new(),
            rule_name: String::new(),
            host: String::new(),
            port: 0,
        }
    }
}

impl Log {
    fn view(&self) -> Value {
        let mut result = json!({"time": self.time, "level": self.level, "message": self.message});
        for (key, value) in [
            ("connection_id", &self.connection_id),
            ("exe_path", &self.exe_path),
            ("action", &self.action),
            ("rule_id", &self.rule_id),
            ("rule_name", &self.rule_name),
            ("host", &self.host),
        ] {
            if !value.is_empty() {
                result[key] = json!(value);
            }
        }
        if self.pid != 0 {
            result["pid"] = json!(self.pid);
        }
        if self.port != 0 {
            result["port"] = json!(self.port);
        }
        result
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct DropRecord {
    #[serde(rename = "DropID")]
    drop_id: String,
    dropped_at: DateTime<Utc>,
    connection: Connection,
}

impl DropRecord {
    fn matches(&self, terms: &[&str]) -> bool {
        if terms.is_empty() {
            return true;
        }
        let fields = self.connection.view();
        let search = format!(
            "{} {} {}",
            self.drop_id,
            self.dropped_at.to_rfc3339(),
            fields
        )
        .to_lowercase();
        terms.iter().all(|term| search.contains(term))
    }

    fn view(&self) -> Value {
        let mut value = self.connection.view();
        value["drop_id"] = json!(self.drop_id);
        value["dropped_at"] = json!(self.dropped_at);
        value
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct Traffic {
    time: DateTime<Utc>,
    up_bytes: u64,
    down_bytes: u64,
}

impl Traffic {
    fn view(&self) -> Value {
        json!({"time": self.time, "up_bytes": self.up_bytes, "down_bytes": self.down_bytes})
    }
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase", default)]
struct RuleRecord {
    #[serde(rename = "time")]
    time: DateTime<Utc>,
    #[serde(rename = "RuleID")]
    rule_id: String,
    rule_name: String,
    action: String,
    connections: u64,
    up_bytes: u64,
    down_bytes: u64,
    #[serde(
        rename = "condition_application",
        skip_serializing_if = "String::is_empty"
    )]
    application: String,
    #[serde(rename = "condition_host", skip_serializing_if = "String::is_empty")]
    host: String,
    #[serde(rename = "condition_port", skip_serializing_if = "String::is_empty")]
    port: String,
    #[serde(rename = "condition_source", skip_serializing_if = "String::is_empty")]
    source: String,
    #[serde(
        rename = "condition_overflow",
        skip_serializing_if = "std::ops::Not::not"
    )]
    overflow: bool,
}

impl RuleRecord {
    fn merge(&mut self, other: &Self) {
        if other.time >= self.time {
            self.time = other.time;
            self.rule_name.clone_from(&other.rule_name);
            self.action.clone_from(&other.action);
        }
        self.connections += other.connections;
        self.up_bytes += other.up_bytes;
        self.down_bytes += other.down_bytes;
    }

    fn view(&self) -> Value {
        let mut value = json!({"action": self.action, "connections": self.connections, "up_bytes": self.up_bytes, "down_bytes": self.down_bytes});
        if !self.rule_id.is_empty() {
            value["rule_id"] = json!(self.rule_id);
        }
        if !self.rule_name.is_empty() {
            value["rule_name"] = json!(self.rule_name);
        }
        value
    }
}

#[derive(Default)]
struct Pending {
    conn: VecDeque<Connection>,
    log: VecDeque<Log>,
    drop: VecDeque<DropRecord>,
    traffic: BTreeMap<i64, Traffic>,
    rules: HashMap<(i64, String, String, String, String, String), RuleRecord>,
}

impl Pending {
    fn is_empty(&self) -> bool {
        self.conn.is_empty()
            && self.log.is_empty()
            && self.drop.is_empty()
            && self.traffic.is_empty()
            && self.rules.is_empty()
    }
}

struct State {
    active: HashMap<String, Connection>,
    live: BTreeMap<i64, Traffic>,
    subscribers: HashMap<u64, SyncSender<Arc<[u8]>>>,
    next_subscriber: u64,
    ui_until: Option<Instant>,
    retention: i64,
    dropped_limit: u64,
    drop_sequence: u64,
    pending: Pending,
    flush_at: Option<Instant>,
    closed: bool,
}

pub struct Monitor {
    pub wake: Condvar,
    state: Mutex<State>,
    history: PathBuf,
    disk: Mutex<()>,
}

impl Monitor {
    pub fn open(mut path: PathBuf, retention: i64, dropped_limit: u64) -> io::Result<Arc<Self>> {
        if let Some(ext) = path.extension() {
            if ext.eq_ignore_ascii_case("sqlite") {
                path.set_extension("");
            } else {
                path.as_mut_os_string().push(".segments");
            }
        }
        fs::create_dir_all(&path)?;
        for file in fs::read_dir(&path)? {
            let file = file?;
            if file.file_type()?.is_file()
                && file
                    .path()
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("jsonl"))
            {
                recover_tail(&file.path())?;
            }
        }
        Ok(Arc::new(Self {
            wake: Condvar::new(),
            history: path,
            disk: Mutex::new(()),
            state: Mutex::new(State {
                active: HashMap::new(),
                live: BTreeMap::new(),
                subscribers: HashMap::new(),
                next_subscriber: 0,
                ui_until: None,
                retention,
                dropped_limit,
                drop_sequence: 0,
                pending: Pending::default(),
                flush_at: None,
                closed: false,
            }),
        }))
    }

    pub fn worker(&self) {
        let mut state = self.state.lock().unwrap();
        while !state.closed {
            let Some(deadline) = state.flush_at else {
                state = self.wake.wait(state).unwrap();
                continue;
            };
            if deadline > Instant::now() {
                state = self
                    .wake
                    .wait_timeout(state, deadline.saturating_duration_since(Instant::now()))
                    .unwrap()
                    .0;
                continue;
            }
            drop(state);
            let _ = self.flush(false);
            state = self.state.lock().unwrap();
        }
    }

    pub fn close(&self) -> io::Result<()> {
        self.state.lock().unwrap().closed = true;
        self.wake.notify_all();
        self.flush(true)
    }

    pub fn settings(&self, retention: i64, dropped_limit: u64) {
        let mut state = self.state.lock().unwrap();
        state.retention = retention;
        state.dropped_limit = dropped_limit;
        self.arm_flush(&mut state);
    }

    fn arm_flush(&self, state: &mut State) {
        if state.flush_at.is_none() {
            state.flush_at = Some(Instant::now() + FLUSH);
            self.wake.notify_all();
        }
    }

    pub fn mark_ui(&self, active: bool) {
        self.state.lock().unwrap().ui_until = active.then(|| Instant::now() + UI_WINDOW);
        self.wake.notify_all();
    }

    pub fn wake_observer(&self) {
        let _state = self.state.lock().unwrap();
        self.wake.notify_all();
    }

    pub fn disable_ui(&self, event: Value) {
        self.event("webui_status", event);
        let mut state = self.state.lock().unwrap();
        state.subscribers.clear();
        state.ui_until = None;
        self.wake.notify_all();
    }

    pub fn wait_ui(&self, stopped: impl Fn() -> bool) -> bool {
        let state = self.state.lock().unwrap();
        let state = self
            .wake
            .wait_while(state, |s| !s.closed && !stopped() && !ui_active(s))
            .unwrap();
        !state.closed && !stopped()
    }

    pub fn ui_active(&self) -> bool {
        ui_active(&self.state.lock().unwrap())
    }

    pub(crate) fn diagnostics(&self) -> Value {
        let state = self.state.lock().unwrap();
        json!({
            "active_connections":state.active.len(), "traffic_live_buckets":state.live.len(),
            "subscribers":state.subscribers.len(),"ui_active":ui_active(&state),
            "retention_seconds":state.retention*60,
            "history":{
                "pending_logs":state.pending.log.len(),"pending_connections":state.pending.conn.len(),
                "pending_dropped":state.pending.drop.len(),"pending_traffic_buckets":state.pending.traffic.len(),
                "pending_rule_buckets":state.pending.rules.len(),
                "pending_condition_buckets":state.pending.rules.values().filter(|r|!r.source.is_empty()).count(),
                "retention_seconds":state.retention*60,"dropped_max_bytes":state.dropped_limit,
            }
        })
    }

    pub fn subscribe(&self) -> (u64, Receiver<Arc<[u8]>>) {
        let (tx, rx) = mpsc::sync_channel(64);
        let mut state = self.state.lock().unwrap();
        state.next_subscriber += 1;
        let id = state.next_subscriber;
        state.subscribers.insert(id, tx);
        (id, rx)
    }

    pub fn unsubscribe(&self, id: u64) {
        self.state.lock().unwrap().subscribers.remove(&id);
    }

    fn event(&self, kind: &str, data: Value) {
        let mut state = self.state.lock().unwrap();
        if state.subscribers.is_empty() {
            return;
        }
        let payload: Arc<[u8]> = serde_json::to_vec(&json!({"type": kind, "data": data}))
            .unwrap()
            .into();
        state.subscribers.retain(|_, tx| {
            !matches!(
                tx.try_send(payload.clone()),
                Err(TrySendError::Disconnected(_))
            )
        });
    }

    pub fn log(&self, level: &str, message: impl Into<String>, connection: Option<&Connection>) {
        let mut state = self.state.lock().unwrap();
        if state.closed || !(matches!(level, "warn" | "warning" | "error") || ui_active(&state)) {
            return;
        }
        let mut entry = Log {
            level: level.into(),
            message: message.into(),
            ..Log::default()
        };
        if let Some(conn) = connection {
            entry.connection_id.clone_from(&conn.id);
            entry.pid = conn.pid;
            entry.exe_path.clone_from(&conn.exe_path);
            entry.action.clone_from(&conn.action);
            entry.rule_id.clone_from(&conn.rule_id);
            entry.rule_name.clone_from(&conn.rule_name);
            entry.host = display_host(conn).to_owned();
            entry.port = conn.original_port;
        }
        let event = (!state.subscribers.is_empty()).then(|| entry.view());
        if state.pending.log.len() < 8192 {
            state.pending.log.push_back(entry);
            self.arm_flush(&mut state);
        }
        drop(state);
        if let Some(event) = event {
            self.event("log", event);
        }
    }

    pub fn upsert(&self, mut conn: Connection) {
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return;
        }
        conn.last_updated_at = Utc::now();
        if let Some(existing) = state.active.get(&conn.id) {
            conn.created_at = conn.created_at.min(existing.created_at);
            if conn.bytes_up == 0 {
                conn.bytes_up = existing.bytes_up;
            }
            if conn.bytes_down == 0 {
                conn.bytes_down = existing.bytes_down;
            }
        }
        if !matches!(conn.state.as_str(), "closed" | "blocked" | "error") {
            state.active.insert(conn.id.clone(), conn);
            return;
        }
        state.active.remove(&conn.id);
        if state.active.len() * 4 < state.active.capacity() && state.active.capacity() > 256 {
            state.active.shrink_to_fit();
        }
        if conn.state == "blocked" && state.pending.drop.len() < 1024 {
            state.drop_sequence += 1;
            let time = conn.last_updated_at;
            let drop_id = format!(
                "{:016x}-{:08x}",
                time.timestamp_nanos_opt().unwrap_or_default(),
                state.drop_sequence
            );
            state.pending.drop.push_back(DropRecord {
                drop_id,
                dropped_at: time,
                connection: conn.clone(),
            });
        }
        if state.pending.conn.len() < 8192 {
            state.pending.conn.push_back(conn);
        }
        self.arm_flush(&mut state);
    }

    pub fn rule_hit(&self, conn: &Connection, labels: MatchDetails<'_>, source: &str) {
        self.rule(conn, 1, 0, 0, labels, source);
    }

    pub fn transferred(&self, conn: &Connection, up: u64, down: u64) {
        self.rule(conn, 0, up, down, MatchDetails::default(), "");
        if !matches!(conn.action.as_str(), "proxy" | "chain") || up + down == 0 {
            return;
        }
        let now = Utc::now().timestamp();
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return;
        }
        add_traffic(&mut state.live, now, up, down);
        while state
            .live
            .first_key_value()
            .is_some_and(|(k, _)| *k < now - 120)
        {
            state.live.pop_first();
        }
        if state.pending.traffic.len() < 2048 || state.pending.traffic.contains_key(&now) {
            add_traffic(&mut state.pending.traffic, now, up, down);
            self.arm_flush(&mut state);
        }
    }

    fn rule(
        &self,
        conn: &Connection,
        hits: u64,
        up: u64,
        down: u64,
        labels: MatchDetails<'_>,
        source: &str,
    ) {
        if hits + up + down == 0 {
            return;
        }
        let t = Utc::now().timestamp().div_euclid(CONDITION_BUCKET) * CONDITION_BUCKET;
        let mut state = self.state.lock().unwrap();
        if state.closed {
            return;
        }
        let identity = if conn.rule_id.is_empty() {
            format!("{}\x1f{}", conn.rule_name, conn.action)
        } else {
            conn.rule_id.clone()
        };
        let has_conditions =
            !source.is_empty() && ![labels.application, labels.host, labels.port].contains(&"");
        let mut key = (
            t,
            identity,
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        );
        let mut overflow = false;
        if has_conditions {
            key.2 = source.into();
            key.3 = truncate(labels.application, 512);
            key.4 = truncate(labels.host, 512);
            key.5 = truncate(labels.port, 512);
            if !state.pending.rules.contains_key(&key)
                && state
                    .pending
                    .rules
                    .keys()
                    .filter(|k| k.0 == t && !k.3.is_empty())
                    .take(256)
                    .count()
                    == 256
            {
                key.3.clear();
                key.4.clear();
                key.5.clear();
                overflow = true;
            }
        }
        if state.pending.rules.len() >= 4096 && !state.pending.rules.contains_key(&key) {
            return;
        }
        let item = state
            .pending
            .rules
            .entry(key.clone())
            .or_insert_with(|| RuleRecord {
                time: timestamp(t),
                rule_id: conn.rule_id.clone(),
                rule_name: conn.rule_name.clone(),
                action: conn.action.clone(),
                source: key.2,
                application: key.3,
                host: key.4,
                port: key.5,
                overflow,
                ..RuleRecord::default()
            });
        item.connections += hits;
        item.up_bytes += up;
        item.down_bytes += down;
        self.arm_flush(&mut state);
    }

    pub fn tray(&self, seconds: i64) -> Value {
        let now = Utc::now().timestamp();
        let state = self.state.lock().unwrap();
        let traffic: Vec<_> = ((now - seconds.max(12) + 1)..=now)
            .map(|t| {
                state
                    .live
                    .get(&t)
                    .copied()
                    .unwrap_or(Traffic {
                        time: timestamp(t),
                        up_bytes: 0,
                        down_bytes: 0,
                    })
                    .view()
            })
            .collect();
        json!({"traffic": traffic})
    }

    fn flush(&self, force: bool) -> io::Result<()> {
        let _disk = self.disk.lock().unwrap();
        let mut state = self.state.lock().unwrap();
        let now = Utc::now();
        let result = (|| {
            while let Some(record) = state.pending.conn.front() {
                append(
                    &segment_path(&self.history, "connections", record.last_updated_at),
                    record,
                )?;
                state.pending.conn.pop_front();
            }
            while let Some(record) = state.pending.log.front() {
                append(&segment_path(&self.history, "logs", record.time), record)?;
                state.pending.log.pop_front();
            }
            while let Some(record) = state.pending.drop.front() {
                append(&self.history.join("dropped.jsonl"), record)?;
                state.pending.drop.pop_front();
            }
            while let Some((key, record)) = state.pending.traffic.first_key_value() {
                if !force && *key >= now.timestamp() {
                    break;
                }
                append(&segment_path(&self.history, "traffic", record.time), record)?;
                state.pending.traffic.pop_first();
            }
            let rule_keys: Vec<_> = state
                .pending
                .rules
                .iter()
                .filter_map(|(key, record)| {
                    (force
                        || record.source.is_empty()
                        || key.0 + CONDITION_BUCKET <= now.timestamp())
                    .then_some(key.clone())
                })
                .collect();
            for key in rule_keys {
                let record = &state.pending.rules[&key];
                append(&segment_path(&self.history, "rules", record.time), record)?;
                state.pending.rules.remove(&key);
            }
            self.prune(now, state.retention)?;
            self.trim_dropped(state.dropped_limit)
        })();
        state.flush_at = if result.is_err() {
            Some(Instant::now() + Duration::from_secs(30))
        } else if state.pending.is_empty() {
            None
        } else {
            Some(Instant::now() + FLUSH)
        };
        result
    }

    fn prune(&self, now: DateTime<Utc>, retention: i64) -> io::Result<()> {
        let hour = (now - chrono::Duration::minutes(retention))
            .format("%Y%m%d%H")
            .to_string();
        for entry in fs::read_dir(&self.history)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if let Some((kind, suffix)) = name
                .strip_suffix(".jsonl")
                .and_then(|name| name.split_once('-'))
            {
                if matches!(kind, "logs" | "traffic" | "rules" | "connections")
                    && suffix.len() == 10
                    && suffix < hour.as_str()
                {
                    fs::remove_file(entry.path())?;
                }
            }
        }
        Ok(())
    }

    fn trim_dropped(&self, limit: u64) -> io::Result<()> {
        let path = self.history.join("dropped.jsonl");
        let Ok(metadata) = path.metadata() else {
            return Ok(());
        };
        if metadata.len() <= limit {
            return Ok(());
        }
        let target = limit.saturating_mul(9) / 10;
        let mut reader = BufReader::new(File::open(&path)?);
        reader.seek(SeekFrom::Start(metadata.len() - target))?;
        reader.read_until(b'\n', &mut Vec::new())?;
        let tmp = path.with_extension("jsonl.tmp");
        {
            let mut out = BufWriter::new(File::create(&tmp)?);
            io::copy(&mut reader, &mut out)?;
            out.flush()?;
        }
        drop(reader);
        fs::rename(tmp, path)
    }

    fn visit<T: DeserializeOwned>(
        &self,
        kind: &str,
        cutoff: DateTime<Utc>,
        mut record: impl FnMut(T),
    ) -> io::Result<()> {
        let oldest = cutoff.format("%Y%m%d%H").to_string();
        let prefix = format!("{kind}-");
        let mut paths: Vec<_> = fs::read_dir(&self.history)?
            .filter_map(Result::ok)
            .filter_map(|e| {
                let name = e.file_name();
                let hour = name
                    .to_str()?
                    .strip_prefix(&prefix)?
                    .strip_suffix(".jsonl")?;
                (hour.len() == 10 && hour >= oldest.as_str()).then(|| e.path())
            })
            .collect();
        paths.sort_unstable();
        for path in paths {
            read_records(&path, &mut record)?;
        }
        Ok(())
    }

    pub fn dropped(&self, query: &str, offset: usize, limit: usize) -> io::Result<Value> {
        let _disk = self.disk.lock().unwrap();
        let state = self.state.lock().unwrap();
        let path = self.history.join("dropped.jsonl");
        let file_bytes = path.metadata().map_or(0, |metadata| metadata.len());
        let query = query.to_lowercase();
        let terms: Vec<_> = query.split_whitespace().collect();
        let limit = if limit == 0 { 100 } else { limit.min(500) };
        let mut total = 0usize;
        read_records(&path, |r: DropRecord| {
            if r.matches(&terms) {
                total += 1;
            }
        })?;
        total += state
            .pending
            .drop
            .iter()
            .filter(|r| r.matches(&terms))
            .count();
        let first = total.saturating_sub(offset.saturating_add(limit));
        let end = total.saturating_sub(offset);
        let mut index = 0;
        let mut items = Vec::new();
        let mut collect = |record: &DropRecord| {
            if record.matches(&terms) {
                if (first..end).contains(&index) {
                    items.push(record.view());
                }
                index += 1;
            }
        };
        read_records(&path, |record| collect(&record))?;
        for record in &state.pending.drop {
            collect(record);
        }
        items.reverse();
        Ok(
            json!({"items": items, "total": total, "offset": offset, "limit": limit, "max_bytes": state.dropped_limit, "file_bytes": file_bytes}),
        )
    }

    pub fn delete_dropped(&self, ids: &[String]) -> io::Result<()> {
        if ids.is_empty() {
            return Ok(());
        }
        let _disk = self.disk.lock().unwrap();
        let mut state = self.state.lock().unwrap();
        let ids: HashSet<_> = ids
            .iter()
            .map(|id| id.trim())
            .filter(|id| !id.is_empty())
            .collect();
        let path = self.history.join("dropped.jsonl");
        if path.is_file() {
            let tmp = path.with_extension("jsonl.tmp");
            let mut output = BufWriter::new(File::create(&tmp)?);
            read_lines(&path, |line| {
                let keep = serde_json::from_slice::<DropRecord>(line)
                    .map_or(true, |r| !ids.contains(r.drop_id.as_str()));
                if keep {
                    output.write_all(line)?;
                }
                Ok(())
            })?;
            output.flush()?;
            drop(output);
            fs::rename(tmp, path)?;
        }
        state
            .pending
            .drop
            .retain(|r| !ids.contains(r.drop_id.as_str()));
        Ok(())
    }

    pub fn snapshot(&self, include_logs: bool) -> Value {
        let _disk = self.disk.lock().unwrap();
        let mut state = self.state.lock().unwrap();
        let now = Utc::now();
        let cutoff = now - chrono::Duration::minutes(state.retention);
        state.active.retain(|_, c| {
            c.state == "open"
                || (c.state == "opening" && c.last_updated_at > now - chrono::Duration::minutes(2))
                || c.last_updated_at > cutoff && c.state != "opening"
        });
        let mut groups = HashMap::<String, Connection>::new();
        let mut novelty = HashMap::<(String, String, u16), (DateTime<Utc>, Connection)>::new();
        let mut observe = |c: &Connection| {
            if state.retention <= 1 {
                return;
            }
            let (exe, ip, port) = c.novelty_key();
            let entry = novelty
                .entry((exe, ip.into(), port))
                .or_insert_with(|| (c.created_at, c.clone()));
            entry.0 = entry.0.min(c.created_at);
            if c.last_updated_at > entry.1.last_updated_at {
                entry.1 = c.clone();
            }
        };
        for c in state.active.values() {
            observe(c);
        }
        let mut collect = |c: Connection| {
            if c.last_updated_at < cutoff {
                return;
            }
            observe(&c);
            let key = c.aggregate_key();
            groups
                .entry(key)
                .and_modify(|item| merge_conn(item, &c))
                .or_insert(c);
            if groups.len() > 4096 {
                let mut values: Vec<_> = groups.drain().collect();
                values.select_nth_unstable_by_key(2048, |(_, c)| {
                    std::cmp::Reverse(c.last_updated_at)
                });
                groups.extend(values.into_iter().take(2048));
            }
        };
        let _ = self.visit("connections", cutoff, &mut collect);
        for c in &state.pending.conn {
            collect(c.clone());
        }
        let mut connections: Vec<_> = state
            .active
            .values()
            .cloned()
            .chain(groups.into_values())
            .collect();
        order_connections(&mut connections);
        let mut new_connections: Vec<_> = novelty
            .into_values()
            .filter_map(|(first, c)| (first >= now - chrono::Duration::minutes(1)).then_some(c))
            .collect();
        order_connections(&mut new_connections);
        new_connections.truncate(512);
        let logs = include_logs.then(|| {
            let mut logs = VecDeque::new();
            let mut collect = |log: Log| {
                if log.time >= cutoff {
                    if logs.len() == 5000 {
                        logs.pop_front();
                    }
                    logs.push_back(log);
                }
            };
            let _ = self.visit("logs", cutoff, &mut collect);
            for record in &state.pending.log {
                collect(record.clone());
            }
            logs.into_iter().map(|log| log.view()).collect::<Vec<_>>()
        });
        let interval = (state.retention * 60 + 119) / 120;
        let mut traffic = BTreeMap::new();
        let (mut up, mut down) = (0, 0);
        let mut collect = |item: Traffic| {
            if item.time < cutoff {
                return;
            }
            up += item.up_bytes;
            down += item.down_bytes;
            let key = item.time.timestamp().div_euclid(interval) * interval;
            traffic
                .entry(key)
                .and_modify(|bucket: &mut Traffic| {
                    bucket.time = bucket.time.max(item.time);
                    bucket.up_bytes += item.up_bytes;
                    bucket.down_bytes += item.down_bytes;
                })
                .or_insert(item);
        };
        let _ = self.visit("traffic", cutoff, &mut collect);
        for item in state.pending.traffic.values() {
            collect(*item);
        }
        let mut rules = BTreeMap::<String, RuleRecord>::new();
        let mut collect = |item: RuleRecord| {
            if item.time + chrono::Duration::seconds(15) < cutoff {
                return;
            }
            let key = if item.rule_id.is_empty() {
                format!("{}\x1f{}", item.rule_name, item.action)
            } else {
                item.rule_id.clone()
            };
            rules
                .entry(key)
                .and_modify(|rule| rule.merge(&item))
                .or_insert(item);
        };
        let _ = self.visit(
            "rules",
            cutoff - chrono::Duration::seconds(15),
            &mut collect,
        );
        for item in state.pending.rules.values() {
            collect(item.clone());
        }
        let mut rule_stats: Vec<_> = rules.into_values().collect();
        rule_stats.sort_by_key(|r| std::cmp::Reverse(r.connections));
        let connections: Vec<_> = connections.iter().map(Connection::view).collect();
        json!({"connections": if connections.is_empty() { Value::Null } else { json!(connections) },
            "new_connections": new_connections.iter().map(Connection::view).collect::<Vec<_>>(), "logs": logs,
            "traffic": traffic.values().map(Traffic::view).collect::<Vec<_>>(),
            "traffic_totals":{"up_bytes":up,"down_bytes":down}, "traffic_bucket_seconds":interval,
            "rule_stats":rule_stats.iter().map(RuleRecord::view).collect::<Vec<_>>(),
            "retention_minutes":state.retention,"new_baseline_minutes":state.retention,"new_recent_minutes":1})
    }

    pub fn timeline(&self, ids: &[String], minutes: i64, points: usize) -> io::Result<Value> {
        let _disk = self.disk.lock().unwrap();
        let state = self.state.lock().unwrap();
        let now = Utc::now();
        let start = now - chrono::Duration::minutes(minutes);
        let width = minutes * 60_000 / points as i64;
        let mut series =
            vec![(RuleRecord::default(), vec![(0_u64, 0_u64, 0_u64); points]); ids.len()];
        let indexes: HashMap<_, _> = ids
            .iter()
            .enumerate()
            .map(|(i, id)| (id.as_str(), i))
            .collect();
        let mut collect = |record: RuleRecord| {
            if record.time + chrono::Duration::seconds(15) < start {
                return;
            }
            if let Some(&i) = indexes.get(record.rule_id.as_str()) {
                let bucket = ((record.time.timestamp_millis() - start.timestamp_millis()).max(0)
                    / width) as usize;
                series[i].0.merge(&record);
                let counts = &mut series[i].1[bucket.min(points - 1)];
                counts.0 += record.connections;
                counts.1 += record.up_bytes;
                counts.2 += record.down_bytes;
            }
        };
        self.visit("rules", start - chrono::Duration::seconds(15), &mut collect)?;
        for rule in state.pending.rules.values() {
            collect(rule.clone());
        }
        let series: Vec<_> =
            ids.iter()
                .zip(series)
                .map(|(id, (mut rule, buckets))| {
                    rule.rule_id.clone_from(id);
                    let mut data = rule.view();
                    if rule.action.is_empty() {
                        data.as_object_mut().unwrap().remove("action");
                    }
                    data["buckets"] =
                        json!(buckets.into_iter().enumerate().map(|(i,(connections,up,down))| {
                json!({"time": start + chrono::Duration::milliseconds(i as i64 * width),
                    "connections":connections,"up_bytes":up,"down_bytes":down})
            }).collect::<Vec<_>>());
                    data
                })
                .collect();
        Ok(
            json!({"generated_at":now,"window_minutes":minutes,"bucket_seconds":width as f64 / 1000.0,"points":points,"series":series}),
        )
    }

    pub fn conditions(&self, id: &str, minutes: i64, limit: usize) -> io::Result<Value> {
        let _disk = self.disk.lock().unwrap();
        let state = self.state.lock().unwrap();
        let now = Utc::now();
        let cutoff = now - chrono::Duration::minutes(minutes);
        let mut total = Counts::default();
        let mut groups = HashMap::<(String, String, String), Counts>::new();
        let mut dimensions = [
            HashMap::<String, Counts>::new(),
            HashMap::new(),
            HashMap::new(),
        ];
        let mut lost = 0;
        let mut collect = |r: RuleRecord| {
            if r.rule_id != id
                || r.time + chrono::Duration::seconds(15) < cutoff
                || r.source.is_empty()
                || r.connections == 0
            {
                return;
            }
            total.add(&r);
            if r.overflow || r.application.is_empty() || r.host.is_empty() || r.port.is_empty() {
                lost += r.connections;
                return;
            }
            for (index, key) in [&r.application, &r.host, &r.port].into_iter().enumerate() {
                let map = &mut dimensions[index];
                if map.len() < 512 || map.contains_key(key) {
                    map.entry(key.clone()).or_default().add(&r);
                }
            }
            let key = (r.application.clone(), r.host.clone(), r.port.clone());
            if groups.len() < 1024 || groups.contains_key(&key) {
                groups.entry(key).or_default().add(&r);
            }
        };
        self.visit(
            "rules",
            cutoff - chrono::Duration::seconds(15),
            &mut collect,
        )?;
        for rule in state.pending.rules.values() {
            collect(rule.clone());
        }
        let groups = top(
            groups,
            limit,
            total.hits,
            |(application, host, port), counts| {
                counts.describe(
                    json!({"application":application,"host":host,"port":port}),
                    total.hits,
                )
            },
        );
        let mut dimensions = dimensions.into_iter().map(|items| {
            let top = top(items, limit, total.hits, |value, counts| counts.describe(json!({"value":value}), total.hits));
            json!({"values":top.0,"total_hits":total.hits,"other_hits":total.hits - top.1,"truncated":top.2 || lost > 0})
        });
        Ok(
            json!({"generated_at":now,"rule_id":id,"window_minutes":minutes,
            "total_hits":total.hits,"other_hits":total.hits.saturating_sub(groups.1 + lost),"unattributed_hits":lost,
            "truncated":groups.2 || lost > 0,"source_hits":total.sources(),"conditions":groups.0,
            "dimensions":{"applications":dimensions.next(),"hosts":dimensions.next(),"ports":dimensions.next()},
            "accuracy": {"unit":"tcp_connection","attribution":"first_matching_alternative","intercepted_complete":lost == 0,
                "direct_complete":false,"boundary_seconds":15,
                "notice":"Перехваченные соединения имеют точную атрибуцию, кроме явно указанного числа неатрибутированных срабатываний; DIRECT учитывается выборочно только во время работы наблюдателя WebUI и может повторно учесть долгоживущее соединение после паузы. Одно срабатывание — новое наблюдаемое TCP-соединение, а не отдельный HTTP-запрос. Если сводка измерения не усечена, отсутствующий вариант имеет 0 наблюдавшихся срабатываний в выбранном окне; если усечена, его значение неизвестно."}}),
        )
    }
}

#[derive(Default)]
struct Counts {
    hits: u64,
    intercepted: u64,
    observer: u64,
    last: DateTime<Utc>,
}

impl Counts {
    fn add(&mut self, record: &RuleRecord) {
        self.hits += record.connections;
        self.last = self.last.max(record.time);
        match record.source.as_str() {
            "intercepted" => self.intercepted += record.connections,
            "direct_observer" => self.observer += record.connections,
            _ => {}
        }
    }
    fn sources(&self) -> Value {
        json!({"intercepted":self.intercepted,"direct_observer":self.observer})
    }
    fn describe(&self, mut value: Value, total: u64) -> Value {
        value["hits"] = json!(self.hits);
        value["share"] = json!(self.hits as f64 / total.max(1) as f64);
        value["last_seen"] = json!(self.last);
        value["sources"] = self.sources();
        value
    }
}

fn top<K: Ord>(
    items: HashMap<K, Counts>,
    limit: usize,
    total: u64,
    map: impl Fn(K, Counts) -> Value,
) -> (Vec<Value>, u64, bool) {
    let mut items: Vec<_> = items.into_iter().collect();
    items.sort_by(|(ka, a), (kb, b)| {
        b.hits
            .cmp(&a.hits)
            .then(b.last.cmp(&a.last))
            .then(ka.cmp(kb))
    });
    let sum = items.iter().take(limit).map(|(_, item)| item.hits).sum();
    (
        items
            .into_iter()
            .take(limit)
            .map(|(key, value)| map(key, value))
            .collect(),
        sum,
        sum < total,
    )
}

pub fn display_host(c: &Connection) -> &str {
    if c.hostname.is_empty() {
        &c.original_ip
    } else {
        &c.hostname
    }
}

fn order_connections(items: &mut [Connection]) {
    items.sort_by(|a, b| {
        b.last_updated_at
            .cmp(&a.last_updated_at)
            .then(b.created_at.cmp(&a.created_at))
            .then(a.id.cmp(&b.id))
    });
}

fn merge_conn(item: &mut Connection, other: &Connection) {
    let created = item.created_at.min(other.created_at);
    let up = item.bytes_up + other.bytes_up;
    let down = item.bytes_down + other.bytes_down;
    let count = item.count.max(1) + other.count.max(1);
    let state = if item.state == "error" || other.state == "error" {
        "error"
    } else if item.state == "blocked" && other.state == "blocked" {
        "blocked"
    } else {
        "closed"
    };
    if item.last_updated_at < other.last_updated_at {
        *item = other.clone();
    }
    item.created_at = created;
    item.bytes_up = up;
    item.bytes_down = down;
    item.count = count;
    item.state = state.into();
}

fn ui_active(state: &State) -> bool {
    state.ui_until.is_some_and(|until| until > Instant::now())
}
fn timestamp(t: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(t, 0).unwrap()
}
fn truncate(value: &str, limit: usize) -> String {
    let mut length = value.len().min(limit);
    while !value.is_char_boundary(length) {
        length -= 1;
    }
    value[..length].into()
}
fn add_traffic(map: &mut BTreeMap<i64, Traffic>, t: i64, up: u64, down: u64) {
    let item = map.entry(t).or_insert_with(|| Traffic {
        time: timestamp(t),
        up_bytes: 0,
        down_bytes: 0,
    });
    item.up_bytes += up;
    item.down_bytes += down;
}
fn segment_path(dir: &Path, kind: &str, time: DateTime<Utc>) -> PathBuf {
    dir.join(format!("{kind}-{}.jsonl", time.format("%Y%m%d%H")))
}
fn append(path: &Path, entry: &impl Serialize) -> io::Result<()> {
    let mut data = serde_json::to_vec(entry)?;
    data.push(b'\n');
    OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)?
        .write_all(&data)
}
fn read_records<T: DeserializeOwned>(path: &Path, mut apply: impl FnMut(T)) -> io::Result<()> {
    read_lines(path, |line| {
        if let Ok(record) = serde_json::from_slice(line) {
            apply(record);
        }
        Ok(())
    })
}
fn read_lines(path: &Path, mut apply: impl FnMut(&[u8]) -> io::Result<()>) -> io::Result<()> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    let mut reader = BufReader::new(file);
    let mut line = Vec::new();
    while reader.by_ref().take(4 << 20).read_until(b'\n', &mut line)? != 0 {
        if line.ends_with(b"\n") {
            apply(&line)?;
        } else {
            reader.skip_until(b'\n')?;
        }
        line.clear();
    }
    Ok(())
}
fn recover_tail(path: &Path) -> io::Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let end = file.metadata()?.len();
    let mut position = end;
    let mut buffer = [0; 4096];
    while position > 0 {
        let n = position.min(buffer.len() as u64) as usize;
        position -= n as u64;
        file.seek(SeekFrom::Start(position))?;
        file.read_exact(&mut buffer[..n])?;
        if let Some(i) = buffer[..n].iter().rposition(|b| *b == b'\n') {
            let keep = position + i as u64 + 1;
            if keep != end {
                file.set_len(keep)?;
            }
            return Ok(());
        }
    }
    if end != 0 {
        file.set_len(0)?;
    }
    Ok(())
}
