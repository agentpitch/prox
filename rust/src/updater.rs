use crate::app::VERSION;
use crate::routing::Stop;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

#[cfg(windows)]
mod native;

const REPOSITORY: &str = "https://api.github.com/repos/agentpitch/prox/releases";
const EXECUTABLE: &str = "pitchProx.exe";
const ARCHIVE: &str = "pitchProx-windows-amd64.zip";
const CHECKSUM: &str = "pitchProx-windows-amd64.sha256";
const MANIFEST: &str = "pitchProx-build-manifest.json";
const STAGE: &str = ".pitchProx-update-stage.exe";
const BACKUP: &str = ".pitchProx-update-backup.exe";
const RECOVERY: &str = ".pitchProx-update-recovery.exe";
const PLAN: &str = ".pitchProx-update-plan.json";
const STATE: &str = ".pitchProx-update-state.json";
const READY: &str = ".pitchProx-update-ready";
const PROCEED: &str = ".pitchProx-update-proceed";
const HELPER: &str = ".pitchProx-update-helper.exe";
const LOCK: &str = ".pitchProx-update.lock";
const PLAN_FORMAT: &str = "pitchprox.update-plan";
const TOKEN: &str = "PITCHPROX_UPDATE_TOKEN";

pub struct Updater {
    target: PathBuf,
    directory: PathBuf,
    mode: &'static str,
    stop: Arc<Stop>,
    session: Mutex<Session>,
    check: Mutex<()>,
    limited_until: Mutex<Option<DateTime<Utc>>>,
}

struct Session {
    state: Status,
    cache: Option<(Instant, DateTime<Utc>, Vec<Release>)>,
    worker: Option<JoinHandle<()>>,
    health: Option<String>,
    tracked_persisted: bool,
    closed: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct Status {
    phase: String,
    busy: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    transaction_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    message: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(default, skip_serializing_if = "zero")]
    downloaded_bytes: u64,
    #[serde(default, skip_serializing_if = "zero")]
    total_bytes: u64,
    updated_at: DateTime<Utc>,
}
fn zero(value: &u64) -> bool {
    *value == 0
}
impl Status {
    fn new(phase: &str, version: &str, message: &str) -> Self {
        Self {
            phase: phase.into(),
            busy: matches!(
                phase,
                "checking" | "downloading" | "verifying" | "restarting"
            ),
            version: version.into(),
            message: message.into(),
            transaction_id: String::new(),
            error: String::new(),
            downloaded_bytes: 0,
            total_bytes: 0,
            updated_at: Utc::now(),
        }
    }
}

#[derive(Clone, Default, Deserialize)]
#[serde(default)]
struct Asset {
    id: u64,
    name: String,
    size: u64,
    digest: String,
    state: String,
}

#[derive(Deserialize)]
struct GithubRelease {
    id: u64,
    tag_name: String,
    name: Option<String>,
    html_url: String,
    draft: bool,
    prerelease: bool,
    published_at: Option<DateTime<Utc>>,
    #[serde(default)]
    assets: Vec<Asset>,
}

#[derive(Clone, Serialize)]
struct Release {
    version: String,
    name: String,
    page_url: String,
    prerelease: bool,
    published_at: DateTime<Utc>,
    size: u64,
    installable: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    verification: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    reason: String,
    #[serde(skip)]
    assets: Vec<Asset>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Handoff {
    format: String,
    format_version: u32,
    mode: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    service_name: String,
    target_path: PathBuf,
    stage_path: PathBuf,
    backup_path: PathBuf,
    recovery_path: PathBuf,
    plan_path: PathBuf,
    ready_path: PathBuf,
    proceed_path: PathBuf,
    state_path: PathBuf,
    parent_pid: u32,
    parent_started: u64,
    listen_address: String,
    version: String,
    old_version: String,
    old_sha256: String,
    new_sha256: String,
    update_token: String,
    transaction_id: String,
    legacy_health: bool,
    created_at: DateTime<Utc>,
}

impl Updater {
    pub fn new(mode: &'static str, stop: Arc<Stop>) -> Result<Self, String> {
        let target = std::env::current_exe().map_err(|e| e.to_string())?;
        let directory = target
            .parent()
            .ok_or("executable has no installation directory")?
            .to_path_buf();
        let persisted = read_json::<Status>(&directory.join(STATE), 64 << 10).ok();
        let tracked_persisted = directory.join(PLAN).is_file();
        let health = read_json::<Handoff>(&directory.join(PLAN), 64 << 10)
            .ok()
            .filter(|plan| {
                eqpath(&target, &plan.target_path)
                    && plan.format == PLAN_FORMAT
                    && plan.format_version == 2
                    && plan.version == VERSION
                    && valid_digest(&plan.update_token)
                    && sha(plan.update_token.as_bytes()) == plan.transaction_id
                    && (0..600).contains(&(Utc::now() - plan.created_at).num_seconds())
            })
            .map(|plan| plan.update_token);
        let state = persisted.unwrap_or_else(|| Status::new("idle", "", ""));
        let updater = Self {
            target,
            directory,
            mode,
            stop,
            session: Mutex::new(Session {
                state,
                cache: None,
                worker: None,
                health,
                tracked_persisted,
                closed: false,
            }),
            check: Mutex::new(()),
            limited_until: Mutex::new(None),
        };
        updater.reconcile();
        Ok(updater)
    }
    pub fn busy(&self) -> bool {
        self.session.lock().unwrap().state.busy
    }
    pub fn status(&self) -> Value {
        self.reconcile();
        let mut session = self.session.lock().unwrap();
        if session.tracked_persisted {
            if let Ok(state) = read_json::<Status>(&self.directory.join(STATE), 64 << 10) {
                if state.updated_at >= session.state.updated_at {
                    session.state = state;
                }
            }
        }
        json!(session.state)
    }
    pub fn health_token(&self) -> Option<String> {
        let mut session = self.session.lock().unwrap();
        if session.health.is_some() && !self.directory.join(PLAN).is_file() {
            session.health = None;
        }
        session.health.clone()
    }
    pub fn close(&self) {
        let worker = {
            let mut session = self.session.lock().unwrap();
            session.closed = true;
            session.worker.take()
        };
        if let Some(worker) = worker {
            let _ = worker.join();
        }
    }
    pub fn check(&self) -> Result<Value, String> {
        let releases = self.list(true, Instant::now() + Duration::from_secs(30))?;
        let latest = releases
            .1
            .iter()
            .filter(|r| !r.prerelease && parse(&r.version).is_some())
            .max_by(|a, b| compare(&a.version, &b.version).unwrap_or(Ordering::Equal))
            .map(|r| r.version.as_str());
        let known = latest.and_then(|latest| compare(VERSION, latest));
        let visible: Vec<_> = releases.1.iter().take(5).collect();
        let mut out = json!({"current_version":VERSION,"update_available":known==Some(Ordering::Less),
            "comparison_known":known.is_some(),"checked_at":releases.0,"releases":visible});
        if let Some(version) = latest {
            out["latest_version"] = json!(version);
        }
        Ok(out)
    }
    fn list(
        &self,
        cached: bool,
        deadline: Instant,
    ) -> Result<(DateTime<Utc>, Vec<Release>), String> {
        let _check = self.check.lock().unwrap();
        if cached {
            if let Some((started, time, releases)) = &self.session.lock().unwrap().cache {
                if started.elapsed() < Duration::from_secs(300) {
                    return Ok((*time, releases.clone()));
                }
            }
        }
        let url = format!("{REPOSITORY}?per_page=20&page=1");
        let body = self.bytes(
            &url,
            "application/vnd.github+json",
            2 << 20,
            "release list",
            deadline,
        )?;
        let mut source: Vec<GithubRelease> = serde_json::from_slice(&body)
            .map_err(|e| format!("decode GitHub release list: {e}"))?;
        source.retain(|r| !r.draft && !r.tag_name.trim().is_empty() && r.published_at.is_some());
        source.sort_by(|a, b| b.published_at.cmp(&a.published_at).then(b.id.cmp(&a.id)));
        source.truncate(20);
        let mut releases = Vec::new();
        for (i, item) in source.into_iter().enumerate() {
            let version = item.tag_name.trim().to_owned();
            let name = item
                .name
                .as_deref()
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .unwrap_or(&version)
                .to_owned();
            let mut release = Release {
                version,
                name,
                page_url: item.html_url,
                prerelease: item.prerelease,
                published_at: item.published_at.unwrap(),
                size: 0,
                installable: false,
                verification: String::new(),
                reason: String::new(),
                assets: item.assets,
            };
            if i < 5 && needs_lookup(&release, item.id) {
                let url = format!("{REPOSITORY}/{}/assets?per_page=33&page=1", item.id);
                let fetch = self
                    .bytes(
                        &url,
                        "application/vnd.github+json",
                        2 << 20,
                        "release asset list",
                        deadline,
                    )
                    .and_then(|body| {
                        serde_json::from_slice(&body)
                            .map_err(|e| format!("decode GitHub release assets: {e}"))
                    });
                match fetch {
                    Ok(assets) => release.assets = assets,
                    Err(err) => {
                        if Instant::now() >= deadline {
                            return Err(err);
                        }
                        release.reason = format!("не удалось получить полный список файлов: {err}");
                        releases.push(release);
                        continue;
                    }
                }
            }
            release.size = asset(&release, EXECUTABLE).map_or(0, |a| a.size);
            match metadata(&release) {
                Ok(kind) => {
                    release.installable = true;
                    release.verification = kind.into();
                    if kind == "legacy" {
                        release.reason="старый формат: SHA-256 сверяется с метаданными GitHub и checksum-файлом, но манифеста сборки нет".into();
                    }
                }
                Err(err) => release.reason = err,
            }
            releases.push(release);
        }
        let checked = Utc::now();
        self.session.lock().unwrap().cache = Some((Instant::now(), checked, releases.clone()));
        Ok((checked, releases))
    }
    fn bytes(
        &self,
        url: &str,
        accept: &str,
        limit: u64,
        description: &str,
        deadline: Instant,
    ) -> Result<Vec<u8>, String> {
        let body = self.request(url, accept, deadline, description)?;
        if body.length().is_some_and(|n| n > limit) {
            return Err(format!("{description} is too large"));
        }
        let mut data = Vec::new();
        body.take(limit + 1)
            .read_to_end(&mut data)
            .map_err(|e| e.to_string())?;
        if data.len() as u64 > limit {
            return Err(format!("{description} is too large"));
        }
        Ok(data)
    }
    fn request(
        &self,
        url: &str,
        accept: &str,
        deadline: Instant,
        description: &str,
    ) -> Result<Response, String> {
        if self.stop.stopped() {
            return Err("update request canceled".into());
        }
        if let Some(retry) = *self.limited_until.lock().unwrap() {
            if retry > Utc::now() {
                return Err(rate_limit(retry));
            }
        }
        let response = Response::open(url, accept, deadline, self.stop.clone())?;
        if response.status() == 200 {
            return Ok(response);
        }
        if matches!(response.status(), 403 | 429) {
            let now = Utc::now();
            let header = response.header("Retry-After").unwrap_or_default();
            let mut retry = header
                .parse::<i64>()
                .ok()
                .filter(|n| (0..=i32::MAX as i64).contains(n))
                .and_then(|n| now.checked_add_signed(chrono::Duration::seconds(n)))
                .or_else(|| {
                    DateTime::parse_from_rfc2822(&header)
                        .ok()
                        .map(|d| d.with_timezone(&Utc))
                });
            let exhausted = response.header("X-RateLimit-Remaining").as_deref() == Some("0");
            if exhausted {
                if let Some(t) = response
                    .header("X-RateLimit-Reset")
                    .and_then(|s| s.parse().ok())
                    .and_then(|s| DateTime::from_timestamp(s, 0))
                {
                    retry = Some(retry.map_or(t, |r| r.max(t)));
                }
            }
            if exhausted || retry.is_some() || response.status() == 429 {
                let retry = retry
                    .filter(|r| *r > now)
                    .unwrap_or(now + chrono::Duration::minutes(1));
                let mut limit = self.limited_until.lock().unwrap();
                *limit = Some(limit.map_or(retry, |r| r.max(retry)));
                return Err(rate_limit(limit.unwrap()));
            }
        }
        Err(format!(
            "GitHub returned HTTP {} for {description}",
            response.status()
        ))
    }
    pub fn install(self: &Arc<Self>, version: &str, listen: String) -> Result<Value, String> {
        #[cfg(not(windows))]
        {
            let _ = (version, listen);
            Err("application update requires Windows".into())
        }
        #[cfg(windows)]
        {
            if parse(version).is_none() {
                return Err("invalid release version".into());
            }
            self.reconcile();
            let mut session = self.session.lock().unwrap();
            if session.closed {
                return Err("updater is closed".into());
            }
            if session.state.busy || session.worker.as_ref().is_some_and(|w| !w.is_finished()) {
                return Err("an update operation is already running".into());
            }
            if self.directory.join(PLAN).exists() {
                return Err("an unfinished update transaction must be resolved before another version can be installed".into());
            }
            if compare(VERSION, version) == Some(Ordering::Equal) {
                session.state =
                    Status::new("completed", version, "Выбранная версия уже установлена");
                return Ok(json!(session.state));
            }
            let lock = native::FileLock::manager(&self.directory)?;
            session.state = Status::new("checking", version, "Подготовка обновления…");
            session.tracked_persisted = false;
            let version = version.to_owned();
            let updater = self.clone();
            match thread::Builder::new()
                .name("pitchprox-updater".into())
                .spawn(move || {
                    if let Err(err) = updater.run_install(&version, &listen, lock) {
                        let mut state = Status::new("failed", &version, "");
                        state.error = err;
                        updater.session.lock().unwrap().state = state;
                    }
                }) {
                Ok(worker) => session.worker = Some(worker),
                Err(err) => {
                    session.state = Status::new("idle", "", "");
                    return Err(err.to_string());
                }
            }
            Ok(json!(session.state))
        }
    }
    #[cfg(windows)]
    fn run_install(
        &self,
        version: &str,
        listen: &str,
        lock: native::FileLock,
    ) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(600);
        let (_, mut releases) = self.list(true, deadline)?;
        if !releases.iter().take(5).any(|r| r.version == version) {
            releases = self.list(false, deadline)?.1;
        }
        let release = releases
            .into_iter()
            .take(5)
            .find(|r| r.version == version)
            .ok_or_else(|| format!("release {version} was not found"))?;
        if !release.installable {
            return Err(format!("release cannot be installed: {}", release.reason));
        }
        for name in [BACKUP, RECOVERY, PLAN] {
            if self.directory.join(name).exists() {
                return Err(format!("unfinished update transaction contains {name}"));
            }
        }
        for name in [STAGE, READY, PROCEED] {
            remove(&self.directory.join(name)).map_err(|e| e.to_string())?;
        }
        let stage = self.directory.join(STAGE);
        let guard = Staging(stage.clone());
        let mut status = Status::new("downloading", version, "Загрузка и проверка файлов…");
        status.total_bytes = release.size;
        self.session.lock().unwrap().state = status;
        self.stage(&release, &stage, deadline)?;
        let mut status = Status::new("verifying", version, "Подготовка безопасной замены…");
        status.downloaded_bytes = release.size;
        status.total_bytes = release.size;
        self.session.lock().unwrap().state = status;
        let mut token = [0u8; 32];
        getrandom::fill(&mut token).map_err(|e| format!("generate update token: {e}"))?;
        let token = hex(&token);
        let plan = Handoff {
            format: PLAN_FORMAT.into(),
            format_version: 2,
            mode: self.mode.into(),
            service_name: crate::service::NAME.into(),
            target_path: self.target.clone(),
            stage_path: stage.clone(),
            backup_path: self.directory.join(BACKUP),
            recovery_path: self.directory.join(RECOVERY),
            plan_path: self.directory.join(PLAN),
            ready_path: self.directory.join(READY),
            proceed_path: self.directory.join(PROCEED),
            state_path: self.directory.join(STATE),
            parent_pid: std::process::id(),
            parent_started: native::current_start()?,
            listen_address: listen.into(),
            version: version.into(),
            old_version: VERSION.into(),
            old_sha256: hash_file(&self.target).map_err(|e| e.to_string())?,
            new_sha256: hash_file(&stage).map_err(|e| e.to_string())?,
            transaction_id: sha(token.as_bytes()),
            update_token: token,
            legacy_health: release.verification == "legacy",
            created_at: Utc::now(),
        };
        if plan.mode == "service" {
            native::verify_service(&plan, true)?;
        }
        atomic_json(&plan.plan_path, &plan).map_err(|e| e.to_string())?;
        let mut status = Status::new("restarting", version, "Перезапуск приложения…");
        status.transaction_id = plan.transaction_id.clone();
        status.downloaded_bytes = release.size;
        status.total_bytes = release.size;
        atomic_json(&plan.state_path, &status).map_err(|e| e.to_string())?;
        {
            let mut state = self.session.lock().unwrap();
            state.state = status;
            state.tracked_persisted = true;
        }
        std::mem::forget(guard);
        match native::handoff(&plan, lock) {
            Ok(()) => {
                self.stop.signal();
                Ok(())
            }
            Err((error, true)) => {
                // The helper may already be preparing to replace the files.
                // Leave the transaction to its owner.
                let _ = error;
                Ok(())
            }
            Err((error, false)) => {
                let _ = remove(&plan.plan_path);
                let _ = remove(&plan.stage_path);
                let _ = remove(&plan.ready_path);
                let _ = remove(&plan.proceed_path);
                let mut failed = Status::new("failed", version, "");
                failed.transaction_id = plan.transaction_id;
                failed.error = error.clone();
                let _ = atomic_json(&plan.state_path, &failed);
                Err(error)
            }
        }
    }
    #[cfg(windows)]
    fn stage(&self, release: &Release, dest: &Path, deadline: Instant) -> Result<(), String> {
        let checks_asset = asset(release, CHECKSUM).ok_or("missing checksum file")?;
        let checks = self.asset_bytes(checks_asset, deadline)?;
        let exe = asset(release, EXECUTABLE).ok_or("missing executable")?;
        let exe_hash = checksum_for(&checks, EXECUTABLE)?;
        if digest(&exe.digest) != Some(exe_hash.clone()) {
            return Err(
                "executable SHA-256 differs between GitHub metadata and checksum file".into(),
            );
        }
        if let Some(manifest) = asset(release, MANIFEST) {
            if digest(&manifest.digest) != Some(checksum_for(&checks, MANIFEST)?) {
                return Err(
                    "manifest SHA-256 differs between GitHub metadata and checksum file".into(),
                );
            }
            let data = self.asset_bytes(manifest, deadline)?;
            validate_manifest(&data, release, &exe_hash, &self.directory)?;
        } else {
            let archive = asset(release, ARCHIVE).ok_or("missing legacy archive")?;
            let want = checksum_for(&checks, ARCHIVE)?;
            if digest(&archive.digest) != Some(want) {
                return Err(
                    "archive SHA-256 differs between GitHub metadata and checksum file".into(),
                );
            }
            let temp = self.directory.join(".pitchProx-update-runtime.zip");
            let _delete = Staging(temp.clone());
            remove(&temp).map_err(|e| e.to_string())?;
            self.download(archive, &temp, deadline, false)?;
            verify_legacy(&temp, &self.directory, &exe_hash)?;
        }
        self.download(exe, dest, deadline, true)?;
        check_pe(dest).map_err(|e| e.to_string())
    }
    #[cfg(windows)]
    fn asset_bytes(&self, asset: &Asset, deadline: Instant) -> Result<Vec<u8>, String> {
        let url = format!("{REPOSITORY}/assets/{}", asset.id);
        let bytes = self.bytes(
            &url,
            "application/octet-stream",
            asset.size,
            &asset.name,
            deadline,
        )?;
        if bytes.len() as u64 != asset.size || digest(&asset.digest) != Some(sha(&bytes)) {
            return Err(format!(
                "{} failed SHA-256 or size verification",
                asset.name
            ));
        }
        Ok(bytes)
    }
    #[cfg(windows)]
    fn download(
        &self,
        asset: &Asset,
        path: &Path,
        deadline: Instant,
        progress: bool,
    ) -> Result<(), String> {
        let url = format!("{REPOSITORY}/assets/{}", asset.id);
        let mut response = self.request(&url, "application/octet-stream", deadline, &asset.name)?;
        if response.length().is_some_and(|length| length != asset.size) {
            return Err(format!("{} size differs from GitHub metadata", asset.name));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|e| e.to_string())?;
        let mut buf = vec![0_u8; 64 << 10];
        let mut sha = Sha256::new();
        let mut read = 0_u64;
        loop {
            let count = response.read(&mut buf).map_err(|e| e.to_string())?;
            if count == 0 {
                break;
            }
            read += count as u64;
            if read > asset.size {
                return Err(format!("{} exceeds its expected size", asset.name));
            }
            sha.update(&buf[..count]);
            file.write_all(&buf[..count]).map_err(|e| e.to_string())?;
            if progress {
                let mut session = self.session.lock().unwrap();
                session.state.downloaded_bytes = read;
                session.state.updated_at = Utc::now();
            }
        }
        if read != asset.size || digest(&asset.digest) != Some(hex(&sha.finalize())) {
            return Err(format!(
                "{} failed SHA-256 or size verification",
                asset.name
            ));
        }
        file.sync_all().map_err(|e| e.to_string())
    }
    fn reconcile(&self) {
        #[cfg(windows)]
        if self.directory.join(PLAN).is_file() {
            let Ok(_lock) = native::FileLock::manager(&self.directory) else {
                return;
            };
            let result = native::reconcile(&self.target);
            if let Err(error) = result {
                let mut session = self.session.lock().unwrap();
                let mut state = Status::new("failed", &session.state.version, "");
                state.error = error;
                session.state = state;
            }
        }
    }
}

fn rate_limit(time: DateTime<Utc>) -> String {
    format!(
        "GitHub API rate limit reached; try again after {}",
        time.to_rfc3339()
    )
}
fn asset<'a>(release: &'a Release, name: &str) -> Option<&'a Asset> {
    release.assets.iter().find(|asset| asset.name == name)
}
fn limit(name: &str) -> Option<u64> {
    match name {
        EXECUTABLE => Some(64 << 20),
        CHECKSUM => Some(64 << 10),
        MANIFEST => Some(1 << 20),
        ARCHIVE => Some(128 << 20),
        _ => None,
    }
}
fn validate_asset(asset: &Asset) -> Result<(), String> {
    if asset.state != "uploaded" {
        return Err(format!("файл {} не готов к загрузке", asset.name));
    }
    if asset.id == 0 {
        return Err(format!("файл {} имеет неполные метаданные", asset.name));
    }
    if digest(&asset.digest).is_none() {
        return Err(format!("файл {}: invalid SHA-256 digest", asset.name));
    }
    if asset.size == 0 || limit(&asset.name).is_some_and(|limit| asset.size > limit) {
        return Err(format!("недопустимый размер файла {}", asset.name));
    }
    Ok(())
}
fn needs_lookup(release: &Release, id: u64) -> bool {
    if id == 0
        || !canonical(&release.version)
        || release.assets.len() > 32
        || release.prerelease != release.version.contains('-')
    {
        return false;
    }
    let mut names = std::collections::HashSet::new();
    for asset in &release.assets {
        if !names.insert(asset.name.as_str())
            || limit(&asset.name).is_some() && validate_asset(asset).is_err()
        {
            return false;
        }
    }
    !names.contains(EXECUTABLE)
        || !names.contains(CHECKSUM)
        || !names.contains(MANIFEST)
            && (compare(&release.version, "v0.42") != Some(Ordering::Less)
                || !names.contains(ARCHIVE))
}
fn metadata(release: &Release) -> Result<&'static str, String> {
    if release.assets.len() > 32 {
        return Err("в релизе слишком много файлов".into());
    }
    if !canonical(&release.version) {
        return Err("неподдерживаемый формат версии".into());
    }
    let count = |name: &str| release.assets.iter().filter(|a| a.name == name).count();
    for name in [EXECUTABLE, CHECKSUM] {
        if count(name) != 1 {
            return Err(format!("не найден единственный обязательный файл {name}"));
        }
    }
    if count(MANIFEST) > 1 {
        return Err("файл манифеста опубликован более одного раза".into());
    }
    for name in [EXECUTABLE, CHECKSUM] {
        validate_asset(asset(release, name).unwrap())?;
    }
    if release.prerelease != release.version.contains('-') {
        return Err("признак prerelease не соответствует версии".into());
    }
    if let Some(manifest) = asset(release, MANIFEST) {
        validate_asset(manifest)?;
        return Ok("manifest");
    }
    if compare(&release.version, "v0.42") != Some(Ordering::Less) {
        return Err("в релизе отсутствует обязательный манифест сборки".into());
    }
    if count(ARCHIVE) != 1 {
        return Err("для старого релиза не найден единственный полный пакет".into());
    }
    validate_asset(asset(release, ARCHIVE).unwrap())?;
    Ok("legacy")
}
fn parse(value: &str) -> Option<([u64; 3], Vec<String>)> {
    let raw = value.trim();
    if raw.len() > 64 {
        return None;
    }
    let value = raw.strip_prefix(['v', 'V']).unwrap_or(raw);
    let value = value.split('+').next()?;
    let (core, pre) = value
        .split_once('-')
        .map_or((value, None), |(core, pre)| (core, Some(pre)));
    let mut numbers = [0; 3];
    let mut count = 0;
    for (index, part) in core.split('.').enumerate() {
        if index >= 3 || !digits(part) {
            return None;
        }
        let value = part.parse::<u64>().ok()?;
        if value > i64::MAX as u64 / 2 {
            return None;
        }
        numbers[index] = value;
        count += 1;
    }
    if count < 2 {
        return None;
    }
    let mut suffix = Vec::new();
    if let Some(pre) = pre {
        for id in pre.split('.') {
            if id.is_empty()
                || id.len() > 32
                || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return None;
            }
            suffix.push(id.to_ascii_lowercase());
        }
    }
    Some((numbers, suffix))
}
fn digits(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit())
}
fn canonical(value: &str) -> bool {
    if !value.starts_with('v') || value.contains('+') || parse(value).is_none() {
        return false;
    }
    let raw = &value[1..];
    let (core, suffix) = raw.split_once('-').map_or((raw, ""), |(a, b)| (a, b));
    core.split('.').all(|id| id == "0" || !id.starts_with('0'))
        && suffix
            .split('.')
            .all(|id| !digits(id) || id == "0" || !id.starts_with('0'))
}
fn compare(left: &str, right: &str) -> Option<Ordering> {
    let (left, a) = parse(left)?;
    let (right, b) = parse(right)?;
    if left != right {
        return Some(left.cmp(&right));
    }
    if a.is_empty() != b.is_empty() {
        return Some(a.is_empty().cmp(&b.is_empty()));
    }
    for (a, b) in a.iter().zip(&b) {
        let order = match (digits(a), digits(b)) {
            (true, true) => {
                let a = a.trim_start_matches('0');
                let b = b.trim_start_matches('0');
                a.len().cmp(&b.len()).then(a.cmp(b))
            }
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => a.cmp(b),
        };
        if order != Ordering::Equal {
            return Some(order);
        }
    }
    Some(a.len().cmp(&b.len()))
}
fn checksum_for(data: &[u8], name: &str) -> Result<String, String> {
    let input = std::str::from_utf8(data)
        .map_err(|e| e.to_string())?
        .trim_start_matches('\u{feff}');
    let mut found = None;
    for line in input.lines() {
        let mut fields = line.split_whitespace();
        let Some(hash) = fields.next() else {
            continue;
        };
        let Some(file) = fields.next() else {
            continue;
        };
        if file.trim_start_matches('*') != name {
            continue;
        }
        if fields.next().is_some() || !valid_digest(hash) || found.is_some() {
            return Err(format!("invalid or duplicate checksum for {name}"));
        }
        found = Some(hash.to_ascii_lowercase());
    }
    found.ok_or_else(|| format!("no SHA-256 checksum for {name}"))
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}
fn digest(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    let hash = value.strip_prefix("sha256:")?;
    valid_digest(hash).then(|| hash.into())
}
fn hex(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(ALPHABET[usize::from(b >> 4)] as char);
        out.push(ALPHABET[usize::from(b & 15)] as char);
    }
    out
}
fn sha(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}
fn hash_file(path: &Path) -> io::Result<String> {
    hash_reader(File::open(path)?, u64::MAX)
}
fn hash_reader(mut reader: impl Read, limit: u64) -> io::Result<String> {
    let mut sha = Sha256::new();
    let mut data = vec![0; 64 << 10];
    let mut total = 0u64;
    loop {
        let size = reader.read(&mut data)?;
        if size == 0 {
            break;
        }
        total += size as u64;
        if total > limit {
            return Err(io::Error::other("file exceeds size limit"));
        }
        sha.update(&data[..size]);
    }
    Ok(hex(&sha.finalize()))
}
fn has_hash(path: &Path, hash: &str) -> bool {
    valid_digest(hash) && hash_file(path).is_ok_and(|actual| actual.eq_ignore_ascii_case(hash))
}
fn eqpath(a: &Path, b: &Path) -> bool {
    a.to_string_lossy()
        .eq_ignore_ascii_case(&b.to_string_lossy())
}
fn remove(path: &Path) -> io::Result<()> {
    fs::remove_file(path).or_else(|err| {
        if err.kind() == io::ErrorKind::NotFound {
            Ok(())
        } else {
            Err(err)
        }
    })
}
fn read_json<T: serde::de::DeserializeOwned>(path: &Path, max: u64) -> io::Result<T> {
    let mut bytes = Vec::new();
    File::open(path)?.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(io::Error::other("JSON file exceeds limit"));
    }
    Ok(serde_json::from_slice(&bytes)?)
}
fn atomic_json(path: &Path, value: &impl Serialize) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _cleanup = Staging(tmp.clone());
    let mut file = File::create(&tmp)?;
    serde_json::to_writer(&mut file, value)?;
    file.sync_all()?;
    drop(file);
    fs::rename(tmp, path)
}
struct Staging(PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = remove(&self.0);
    }
}

#[cfg(windows)]
fn check_pe(path: &Path) -> io::Result<()> {
    use std::io::{Seek, SeekFrom};
    let mut file = File::open(path)?;
    let mut dos = [0; 64];
    file.read_exact(&mut dos)?;
    let offset = u32::from_le_bytes(dos[60..64].try_into().unwrap()) as u64;
    if dos[..2] != *b"MZ" || offset < 64 || offset > file.metadata()?.len().saturating_sub(26) {
        return Err(io::Error::other("invalid PE executable"));
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut header = [0; 26];
    file.read_exact(&mut header)?;
    if header[..4] != *b"PE\0\0" || header[4..6] != [0x64, 0x86] || header[24..26] != [0x0b, 0x02] {
        return Err(io::Error::other("release executable is not Windows amd64"));
    }
    Ok(())
}

#[cfg(windows)]
fn validate_manifest(
    content: &[u8],
    release: &Release,
    want: &str,
    directory: &Path,
) -> Result<(), String> {
    let manifest: Value =
        serde_json::from_slice(content).map_err(|e| format!("decode build manifest: {e}"))?;
    if manifest["format"] != "pitchprox.build-manifest" || manifest["format_version"] != 1 {
        return Err("unsupported build manifest format".into());
    }
    if manifest["version"] != release.version {
        return Err("build manifest version does not match release tag".into());
    }
    let source = &manifest["source"];
    if [
        "working_tree_dirty",
        "binary_vcs_modified",
        "checks_skipped",
    ]
    .iter()
    .any(|key| source[key] != false)
    {
        return Err("build manifest describes an unverified or modified build".into());
    }
    let target = &manifest["target"];
    if target["goos"] != "windows"
        || target["goarch"] != "amd64"
        || target["goamd64"] != "v1"
        || target["cgo_enabled"] != "0"
        || target["gui_subsystem"] != true
    {
        return Err("build manifest target is not supported by this updater".into());
    }
    let executable = &manifest["executable"];
    if executable["file"] != EXECUTABLE
        || executable["size"] != release.size
        || executable["injected_version_verified"] != true
    {
        return Err("build manifest executable metadata is invalid".into());
    }
    if !executable["sha256"]
        .as_str()
        .is_some_and(|hash| hash.eq_ignore_ascii_case(want))
    {
        return Err("build manifest executable SHA-256 does not match checksum file".into());
    }
    let runtime = &manifest["windivert"];
    if runtime["runtime_source"] != "verified-official-archive"
        || runtime["archive_verified"] != true
    {
        return Err("build manifest does not describe a verified WinDivert runtime".into());
    }
    for (name, key) in [
        ("WinDivert.dll", "dll_sha256"),
        ("WinDivert64.sys", "driver_sha256"),
    ] {
        if !runtime[key]
            .as_str()
            .is_some_and(|hash| has_hash(&directory.join(name), hash))
        {
            return Err(format!(
                "installed {name} is incompatible with this release: SHA-256 mismatch"
            ));
        }
    }
    Ok(())
}
#[cfg(windows)]
fn verify_legacy(path: &Path, directory: &Path, want_executable: &str) -> Result<(), String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let mut zip = zip::ZipArchive::new(file).map_err(|e| e.to_string())?;
    let mut seen = std::collections::HashSet::new();
    for i in 0..zip.len() {
        let entry = zip.by_index(i).map_err(|e| e.to_string())?;
        let name = entry.name().to_owned();
        if !matches!(
            name.as_str(),
            EXECUTABLE | "WinDivert.dll" | "WinDivert64.sys"
        ) {
            continue;
        }
        if !seen.insert(name.clone()) || entry.is_dir() || entry.is_symlink() {
            return Err(format!("invalid or duplicate archive entry {name}"));
        }
        let limit = if name == EXECUTABLE {
            64 << 20
        } else {
            16 << 20
        };
        if entry.size() > limit {
            return Err(format!("invalid size for archive entry {name}"));
        }
        let hash = hash_reader(entry, limit).map_err(|e| e.to_string())?;
        if name == EXECUTABLE {
            if hash != want_executable {
                return Err("archive executable SHA-256 does not match checksum file".into());
            }
        } else if !has_hash(&directory.join(&name), &hash) {
            return Err(format!(
                "installed {name} is incompatible with this release"
            ));
        }
    }
    if seen.len() != 3 {
        return Err("legacy archive is missing the executable or runtime files".into());
    }
    Ok(())
}

#[cfg(windows)]
use native::Response;

#[cfg(not(windows))]
struct Response;
#[cfg(not(windows))]
impl Response {
    fn open(_: &str, _: &str, _: Instant, _: Arc<Stop>) -> Result<Self, String> {
        Err("application updater requires Windows".into())
    }
    fn status(&self) -> u32 {
        0
    }
    fn length(&self) -> Option<u64> {
        None
    }
    fn header(&self, _: &str) -> Option<String> {
        None
    }
}
#[cfg(not(windows))]
impl Read for Response {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

pub fn run_helper(args: &[String]) -> Result<(), String> {
    if args.len() != 2 || args[0] != "--plan" || args[1].trim().is_empty() {
        return Err("usage: update-helper --plan <path>".into());
    }
    #[cfg(windows)]
    {
        native::helper(Path::new(&args[1]))
    }
    #[cfg(not(windows))]
    {
        Err("application updater helper requires Windows".into())
    }
}
