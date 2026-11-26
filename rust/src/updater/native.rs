use super::*;
use crate::{localhttp, platform, service};
use std::ffi::c_void;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Networking::WinHttp::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::Services::{SERVICE_RUNNING, SERVICE_STOPPED};
use windows_sys::Win32::System::Threading::*;
use windows_sys::Win32::System::IO::OVERLAPPED;

struct Internet(*mut c_void);
impl Internet {
    fn open(handle: *mut c_void) -> Result<Self, String> {
        if handle.is_null() {
            Err(io::Error::last_os_error().to_string())
        } else {
            Ok(Self(handle))
        }
    }
}
impl Drop for Internet {
    fn drop(&mut self) {
        unsafe {
            WinHttpCloseHandle(self.0);
        }
    }
}

pub(super) struct Response {
    request: Internet,
    _connection: Internet,
    _session: Internet,
    status: u32,
    deadline: Instant,
    stop: Arc<Stop>,
}
impl Response {
    pub fn open(
        url: &str,
        accept: &str,
        deadline: Instant,
        stop: Arc<Stop>,
    ) -> Result<Self, String> {
        let mut url = url.to_owned();
        for _ in 0..5 {
            if stop.stopped() || Instant::now() >= deadline {
                return Err("update request canceled or timed out".into());
            }
            let (host, path) = split_url(&url)?;
            let agent = platform::wide("pitchProx-updater");
            let server = platform::wide(host);
            let target = platform::wide(path);
            let method = platform::wide("GET");
            let override_proxy = proxy_for(host);
            let session = if override_proxy.as_deref() == Some("") {
                Internet::open(unsafe {
                    WinHttpOpen(
                        agent.as_ptr(),
                        WINHTTP_ACCESS_TYPE_NO_PROXY,
                        null(),
                        null(),
                        0,
                    )
                })?
            } else if let Some(proxy) = &override_proxy {
                let proxy = platform::wide(proxy);
                Internet::open(unsafe {
                    WinHttpOpen(
                        agent.as_ptr(),
                        WINHTTP_ACCESS_TYPE_NAMED_PROXY,
                        proxy.as_ptr(),
                        null(),
                        0,
                    )
                })?
            } else {
                Internet::open(unsafe {
                    WinHttpOpen(
                        agent.as_ptr(),
                        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                        null(),
                        null(),
                        0,
                    )
                })?
            };
            let millis = deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .clamp(1, 30_000) as i32;
            win(unsafe { WinHttpSetTimeouts(session.0, millis, millis, millis, millis) })?;
            let conn =
                Internet::open(unsafe { WinHttpConnect(session.0, server.as_ptr(), 443, 0) })?;
            let request = Internet::open(unsafe {
                WinHttpOpenRequest(
                    conn.0,
                    method.as_ptr(),
                    target.as_ptr(),
                    null(),
                    null(),
                    null(),
                    WINHTTP_FLAG_SECURE,
                )
            })?;
            let forbid = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
            win(unsafe {
                WinHttpSetOption(
                    request.0,
                    WINHTTP_OPTION_REDIRECT_POLICY,
                    (&forbid as *const u32).cast(),
                    4,
                )
            })?;
            let headers=platform::wide(format!("Accept: {accept}\r\nX-GitHub-Api-Version: 2026-03-10\r\nUser-Agent: pitchProx-updater\r\n"));
            win(unsafe {
                WinHttpSendRequest(request.0, headers.as_ptr(), u32::MAX, null(), 0, 0, 0)
            })?;
            win(unsafe { WinHttpReceiveResponse(request.0, null_mut()) })?;
            let mut status = 0_u32;
            let mut length = 4;
            win(unsafe {
                WinHttpQueryHeaders(
                    request.0,
                    WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                    null(),
                    (&mut status as *mut u32).cast(),
                    &mut length,
                    null_mut(),
                )
            })?;
            let response = Self {
                request,
                _connection: conn,
                _session: session,
                status,
                deadline,
                stop: stop.clone(),
            };
            if matches!(status, 301 | 302 | 303 | 307 | 308) {
                let location = response
                    .header("Location")
                    .ok_or("update redirect does not contain a Location header")?;
                url = if location.starts_with("//") {
                    format!("https:{location}")
                } else if location.starts_with('/') {
                    format!("https://{host}{location}")
                } else if location.contains("://") {
                    location
                } else {
                    format!(
                        "https://{host}{}/{location}",
                        path.rsplit_once('/').map_or("", |(p, _)| p)
                    )
                };
                continue;
            }
            return Ok(response);
        }
        Err("too many update download redirects".into())
    }
    pub fn status(&self) -> u32 {
        self.status
    }
    pub fn length(&self) -> Option<u64> {
        self.header("Content-Length")?.parse().ok()
    }
    pub fn header(&self, name: &str) -> Option<String> {
        let name = platform::wide(name);
        let mut size = 0;
        unsafe {
            WinHttpQueryHeaders(
                self.request.0,
                WINHTTP_QUERY_CUSTOM,
                name.as_ptr(),
                null_mut(),
                &mut size,
                null_mut(),
            );
        }
        if size == 0 || size > 64 << 10 {
            return None;
        }
        let mut data = vec![0_u16; (size as usize).div_ceil(2)];
        if unsafe {
            WinHttpQueryHeaders(
                self.request.0,
                WINHTTP_QUERY_CUSTOM,
                name.as_ptr(),
                data.as_mut_ptr().cast(),
                &mut size,
                null_mut(),
            )
        } == 0
        {
            return None;
        }
        Some(
            String::from_utf16_lossy(&data[..(size as usize / 2).min(data.len())])
                .trim_end_matches('\0')
                .to_owned(),
        )
    }
}
impl Read for Response {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.stop.stopped() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if self.deadline <= Instant::now() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let mut count = 0;
        let max = buf.len().min(u32::MAX as usize) as u32;
        if unsafe { WinHttpReadData(self.request.0, buf.as_mut_ptr().cast(), max, &mut count) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(count as usize)
    }
}
fn win(ok: i32) -> Result<(), String> {
    if ok == 0 {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}
fn split_url(url: &str) -> Result<(&str, &str), String> {
    let Some(url) = url.strip_prefix("https://") else {
        return Err("update URL must use HTTPS".into());
    };
    let end = url.find('/').unwrap_or(url.len());
    let host = &url[..end];
    let path = if end == url.len() { "/" } else { &url[end..] };
    if host.is_empty()
        || !host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        || path.contains(['\r', '\n', '\\', '#'])
    {
        return Err("invalid update URL".into());
    }
    let lower = host.to_ascii_lowercase();
    if !matches!(lower.as_str(), "api.github.com" | "github.com")
        && !lower.ends_with(".githubusercontent.com")
    {
        return Err(format!("update URL host {host:?} is not allowed"));
    }
    Ok((host, path))
}
fn proxy_for(host: &str) -> Option<String> {
    let excluded = std::env::var("NO_PROXY").unwrap_or_default();
    if excluded.split(',').map(str::trim).any(|part| {
        let part = part.trim_start_matches('.');
        part == "*"
            || !part.is_empty()
                && (host.eq_ignore_ascii_case(part) || host.ends_with(&format!(".{part}")))
    }) {
        return Some(String::new());
    }
    let raw = std::env::var("HTTPS_PROXY")
        .ok()
        .filter(|v| !v.trim().is_empty())?;
    let value = raw
        .trim()
        .strip_prefix("http://")
        .unwrap_or(raw.trim())
        .trim_end_matches('/');
    if value.contains(['@', '/', '\r', '\n']) || value.is_empty() {
        None
    } else {
        Some(value.into())
    }
}

pub(super) struct FileLock(File);
impl FileLock {
    fn open(directory: &Path, create: bool) -> io::Result<Self> {
        let path = directory.join(LOCK);
        ensure_regular(&path, true)?;
        OpenOptions::new()
            .create(create)
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(path)
            .map(Self)
    }
    pub fn manager(directory: &Path) -> Result<Self, String> {
        let lock = Self::open(directory, true).map_err(|e| format!("open update lock: {e}"))?;
        let claim = lock
            .range(0, true)
            .and_then(|()| lock.range(1, true))
            .and_then(|()| lock.range(1, false));
        match claim {
            Ok(()) => Ok(lock),
            Err(err) if is_lock(&err) => {
                Err("another pitchProx update transaction is active".into())
            }
            Err(err) => Err(format!("acquire update lock: {err}")),
        }
    }
    fn observer(directory: &Path) -> Result<Self, String> {
        let lock = Self::open(directory, false).map_err(|e| e.to_string())?;
        match lock.range(0, true) {
            Ok(()) => {
                return Err("update manager lock was not held before helper acknowledgement".into())
            }
            Err(err) if !is_lock(&err) => return Err(err.to_string()),
            _ => {}
        }
        lock.range(1, true)
            .map_err(|e| format!("acquire update transfer guard: {e}"))?;
        Ok(lock)
    }
    fn range(&self, offset: u32, lock: bool) -> io::Result<()> {
        let mut ov = OVERLAPPED::default();
        ov.Anonymous.Anonymous.Offset = offset;
        let handle = self.0.as_raw_handle();
        let ok = unsafe {
            if lock {
                LockFileEx(
                    handle,
                    LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                    0,
                    1,
                    0,
                    &mut ov,
                )
            } else {
                UnlockFileEx(handle, 0, 1, 0, &mut ov)
            }
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    fn wait_primary(&self) -> Result<(), String> {
        wait(Duration::from_secs(30), || match self.range(0, true) {
            Ok(()) => Ok(true),
            Err(err) if is_lock(&err) => Ok(false),
            Err(err) => Err(err.to_string()),
        })
        .map_err(|e| format!("take over update transaction: {e}"))
    }
}
fn is_lock(err: &io::Error) -> bool {
    err.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32)
}
fn ensure_regular(path: &Path, missing_ok: bool) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    match fs::symlink_metadata(path) {
        Ok(meta)
            if meta.is_file() && meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 =>
        {
            Ok(())
        }
        Err(err) if missing_ok && err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
        _ => Err(io::Error::other(format!(
            "update location is not a regular file: {}",
            path.display()
        ))),
    }
}
pub(super) fn current_start() -> Result<u64, String> {
    platform::current_creation_time().map_err(|e| e.to_string())
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq)]
struct Acknowledgement {
    phase: String,
    token: String,
    transaction_id: String,
    helper_pid: u32,
    parent_started: u64,
}
impl Acknowledgement {
    fn new(plan: &Handoff, pid: u32, phase: &str) -> Self {
        Self {
            phase: phase.into(),
            token: plan.update_token.clone(),
            transaction_id: plan.transaction_id.clone(),
            helper_pid: pid,
            parent_started: plan.parent_started,
        }
    }
}

pub(super) fn handoff(plan: &Handoff, lock: FileLock) -> Result<(), (String, bool)> {
    let directory = plan.target_path.parent().unwrap();
    let helper = directory.join(HELPER);
    let prepare = (|| {
        ensure_regular(&helper, true)?;
        let part = directory.join(".pitchProx-update-helper.exe.part");
        ensure_regular(&part, true)?;
        remove(&part)?;
        copy_verified(&plan.target_path, &part, &plan.old_sha256)?;
        fs::rename(&part, &helper)?;
        remove(&plan.ready_path)?;
        remove(&plan.proceed_path)
    })();
    prepare.map_err(|e| (format!("prepare update helper: {e}"), false))?;
    let mut process = Command::new(&helper)
        .args(["update-helper", "--plan"])
        .arg(&plan.plan_path)
        .current_dir(directory)
        .creation_flags(CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|err| (format!("start update helper: {err}"), false))?;
    let pid = process.id();
    let transition = (|| {
        wait_helper(
            &mut process,
            &plan.ready_path,
            &Acknowledgement::new(plan, pid, "observing"),
        )?;
        drop(lock);
        wait_helper(
            &mut process,
            &plan.ready_path,
            &Acknowledgement::new(plan, pid, "acquired"),
        )?;
        atomic_json(
            &plan.proceed_path,
            &Acknowledgement::new(plan, pid, "proceed"),
        )
        .map_err(|e| e.to_string())?;
        wait_helper(
            &mut process,
            &plan.ready_path,
            &Acknowledgement::new(plan, pid, "proceeding"),
        )
    })();
    match transition {
        Ok(()) => Ok(()),
        Err(err) => {
            let _ = process.kill();
            let uncertain = wait(Duration::from_secs(5), || {
                process
                    .try_wait()
                    .map(|v| v.is_some())
                    .map_err(|e| e.to_string())
            })
            .is_err();
            Err((format!("start update helper: {err}"), uncertain))
        }
    }
}
fn wait_helper(process: &mut Child, path: &Path, want: &Acknowledgement) -> Result<(), String> {
    wait(Duration::from_secs(10), || {
        if let Some(status) = process.try_wait().map_err(|e| e.to_string())? {
            return Err(format!("helper exited before {}: {status}", want.phase));
        }
        Ok(read_json::<Acknowledgement>(path, 16 << 10).is_ok_and(|content| content == *want))
    })
    .map_err(|e| format!("helper did not acknowledge {}: {e}", want.phase))
}

pub(super) fn helper(path: &Path) -> Result<(), String> {
    let self_path = std::env::current_exe().map_err(|e| e.to_string())?;
    let directory = self_path
        .parent()
        .ok_or("helper has no installation directory")?;
    if !eqpath(&self_path, &directory.join(HELPER)) || !eqpath(path, &directory.join(PLAN)) {
        return Err("update helper is not running from the installation directory".into());
    }
    let plan = load(path, directory)?;
    if (Utc::now() - plan.created_at).num_seconds() < 0
        || (Utc::now() - plan.created_at).num_seconds() > 600
    {
        return Err("stale or invalid update plan".into());
    }
    let lock = FileLock::observer(directory)?;
    let parent = tracked_process(plan.parent_pid)?;
    if parent.creation_time().map_err(|e| e.to_string())? != plan.parent_started {
        return Err("parent process identity changed".into());
    }
    verify_executable(plan.parent_pid, &plan.target_path)?;
    if plan.mode == "service" {
        verify_service(&plan, true)?;
    }
    if !has_hash(&self_path, &plan.old_sha256) {
        return Err("helper is not an exact copy of the current executable".into());
    }
    verify_prepared(&plan)?;
    let mut ready = Acknowledgement::new(&plan, std::process::id(), "observing");
    atomic_json(&plan.ready_path, &ready).map_err(|e| e.to_string())?;
    lock.wait_primary()?;
    if load(path, directory)? != plan {
        return Err("update plan changed during lock transfer".into());
    }
    verify_prepared(&plan)?;
    ready.phase = "acquired".into();
    atomic_json(&plan.ready_path, &ready).map_err(|e| e.to_string())?;
    let proceed = Acknowledgement::new(&plan, std::process::id(), "proceed");
    wait(Duration::from_secs(15), || {
        Ok(read_json::<Acknowledgement>(&plan.proceed_path, 16 << 10)
            .is_ok_and(|ready| ready == proceed))
    })?;
    ready.phase = "proceeding".into();
    atomic_json(&plan.ready_path, &ready).map_err(|e| e.to_string())?;
    let result = complete(&plan, parent);
    if let Err(err) = &result {
        let mut state = Status::new("failed", &plan.version, "");
        state.error = err.clone();
        state.transaction_id = plan.transaction_id.clone();
        let _ = atomic_json(&plan.state_path, &state);
    }
    result
}
fn load(path: &Path, directory: &Path) -> Result<Handoff, String> {
    ensure_regular(path, false).map_err(|e| e.to_string())?;
    let plan =
        read_json::<Handoff>(path, 64 << 10).map_err(|e| format!("read update plan: {e}"))?;
    if plan.format != PLAN_FORMAT
        || plan.format_version != 2
        || !matches!(plan.mode.as_str(), "desktop" | "service")
    {
        return Err("unsupported update plan".into());
    }
    let valid = [
        &plan.update_token,
        &plan.transaction_id,
        &plan.old_sha256,
        &plan.new_sha256,
    ]
    .into_iter()
    .all(|v| valid_digest(v));
    if !valid
        || sha(plan.update_token.as_bytes()) != plan.transaction_id
        || plan.parent_pid == 0
        || plan.parent_started == 0
        || parse(&plan.version).is_none()
        || plan.old_version.trim().is_empty()
        || plan.old_version.len() > 64
        || plan.old_version.contains('\0')
    {
        return Err("stale or invalid update plan".into());
    }
    if !plan
        .target_path
        .parent()
        .is_some_and(|path| eqpath(path, directory))
        || !plan.target_path.is_absolute()
        || [
            STAGE, BACKUP, RECOVERY, PLAN, READY, PROCEED, STATE, HELPER, LOCK,
        ]
        .iter()
        .any(|name| eqpath(&plan.target_path, &directory.join(name)))
    {
        return Err("invalid executable path in update plan".into());
    }
    for (value, name) in [
        (&plan.stage_path, STAGE),
        (&plan.backup_path, BACKUP),
        (&plan.recovery_path, RECOVERY),
        (&plan.plan_path, PLAN),
        (&plan.ready_path, READY),
        (&plan.proceed_path, PROCEED),
        (&plan.state_path, STATE),
    ] {
        if !eqpath(value, &directory.join(name)) {
            return Err(format!("invalid {name} path in update plan"));
        }
        ensure_regular(value, true).map_err(|e| e.to_string())?;
    }
    ensure_regular(&plan.target_path, false).map_err(|e| e.to_string())?;
    localhttp::normalize(&format!("http://{}", plan.listen_address))?;
    Ok(plan)
}
fn verify_prepared(plan: &Handoff) -> Result<(), String> {
    let state = read_json::<Status>(&plan.state_path, 64 << 10).map_err(|e| e.to_string())?;
    if state.phase != "restarting"
        || !state.busy
        || state.transaction_id != plan.transaction_id
        || state.version != plan.version
    {
        return Err("update transaction is no longer active".into());
    }
    if !has_hash(&plan.target_path, &plan.old_sha256)
        || !has_hash(&plan.stage_path, &plan.new_sha256)
        || plan.recovery_path.exists()
        || plan.backup_path.exists()
    {
        return Err("update file verification failed".into());
    }
    Ok(())
}
pub(super) fn verify_service(plan: &Handoff, verify_pid: bool) -> Result<(), String> {
    if !plan.service_name.eq_ignore_ascii_case(service::NAME) {
        return Err("service name is not pitchProx".into());
    }
    let command = service::binary_command(&plan.service_name).map_err(|e| e.to_string())?;
    let command = platform::wide(command);
    let mut argc = 0;
    let ptr =
        unsafe { windows_sys::Win32::UI::Shell::CommandLineToArgvW(command.as_ptr(), &mut argc) };
    if ptr.is_null() {
        return Err(io::Error::last_os_error().to_string());
    }
    let result = (|| {
        if argc != 2 {
            return Err("service image command does not match update plan".into());
        }
        let argv = unsafe { std::slice::from_raw_parts(ptr, argc as usize) };
        let path = unsafe { wide_string(argv[0]) };
        let arg = unsafe { wide_string(argv[1]) };
        if !eqpath(Path::new(&path), &plan.target_path) || arg != "service" {
            return Err("service image command does not match update plan".into());
        }
        if verify_pid {
            let status = service::state(&plan.service_name).map_err(|e| e.to_string())?;
            if status.dwProcessId != plan.parent_pid || status.dwCurrentState != SERVICE_RUNNING {
                return Err("service process identity changed".into());
            }
        }
        Ok(())
    })();
    unsafe {
        LocalFree(ptr.cast());
    }
    result
}
unsafe fn wide_string(ptr: *const u16) -> String {
    if ptr.is_null() {
        return String::new();
    }
    let n = (0..32768)
        .find(|i| unsafe { *ptr.add(*i) == 0 })
        .unwrap_or(32768);
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ptr, n) })
}
fn verify_executable(pid: u32, target: &Path) -> Result<(), String> {
    let (_, path) = platform::process_info(pid, 0).map_err(|e| e.to_string())?;
    if path.is_some_and(|path| eqpath(Path::new(&path), target)) {
        Ok(())
    } else {
        Err("process executable path did not match the update plan".into())
    }
}
fn tracked_process(pid: u32) -> Result<platform::Handle, String> {
    platform::Handle::new(unsafe {
        OpenProcess(
            PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
            0,
            pid,
        )
    })
    .map_err(|e| e.to_string())
}
fn complete(plan: &Handoff, parent: platform::Handle) -> Result<(), String> {
    let result = unsafe { WaitForSingleObject(parent.raw(), 120_000) };
    if result == WAIT_TIMEOUT {
        win(unsafe { TerminateProcess(parent.raw(), 1) })?;
        if unsafe { WaitForSingleObject(parent.raw(), 30_000) } != WAIT_OBJECT_0 {
            return Err("application remained alive after termination request".into());
        }
    } else if result != WAIT_OBJECT_0 {
        return Err("failed to confirm parent exit".into());
    }
    if plan.mode == "service" {
        verify_service(plan, false)?;
        wait_service(&plan.service_name, SERVICE_STOPPED)?;
    }
    let replacement: Result<(), String> = (|| {
        verify_prepared(plan)?;
        copy_verified(&plan.target_path, &plan.recovery_path, &plan.old_sha256)
            .map_err(|e| e.to_string())?;
        replace(&plan.target_path, &plan.stage_path, Some(&plan.backup_path))
            .map_err(|e| e.to_string())?;
        if !has_hash(&plan.target_path, &plan.new_sha256) {
            return Err("installed executable SHA-256 does not match staged file".into());
        }
        if !has_hash(&plan.recovery_path, &plan.old_sha256) {
            return Err("verified recovery copy is unavailable".into());
        }
        Ok(())
    })();
    if let Err(err) = replacement {
        return restore(plan, &err);
    }
    let (pid, process) = match launch(plan, true) {
        Ok(app) => app,
        Err(err) => {
            if plan.mode == "service"
                && service::state(&plan.service_name)
                    .is_ok_and(|s| s.dwCurrentState != SERVICE_STOPPED)
            {
                return Err(format!("replacement service may still be running: {err}"));
            }
            return restore(plan, &err);
        }
    };
    if let Err(err) = healthy(plan, pid, &process, true) {
        if plan.mode == "service" {
            verify_service(plan, false)?;
            if service::state(&plan.service_name).is_ok_and(|s| s.dwCurrentState != SERVICE_STOPPED)
            {
                service::manage("stop")?;
                wait_service(&plan.service_name, SERVICE_STOPPED)?;
            }
        } else if unsafe { WaitForSingleObject(process.raw(), 0) } != WAIT_OBJECT_0 {
            win(unsafe { TerminateProcess(process.raw(), 1) })?;
        }
        if unsafe { WaitForSingleObject(process.raw(), 30_000) } != WAIT_OBJECT_0 {
            return Err("new process could not be stopped for rollback".into());
        }
        return restore(plan, &err);
    }
    let mut success = Status::new("completed", &plan.version, "Версия успешно установлена");
    success.transaction_id = plan.transaction_id.clone();
    atomic_json(&plan.state_path, &success).map_err(|e| e.to_string())?;
    if clean(plan).is_err() {
        success.message =
            "Версия установлена; часть служебных файлов будет очищена при следующем запуске".into();
        let _ = atomic_json(&plan.state_path, &success);
    }
    Ok(())
}
fn restore(plan: &Handoff, cause: &str) -> Result<(), String> {
    if !has_hash(&plan.target_path, &plan.old_sha256) {
        let recovery = [&plan.recovery_path, &plan.backup_path]
            .into_iter()
            .find(|path| has_hash(path, &plan.old_sha256))
            .ok_or_else(|| format!("{cause}; verified rollback copy is unavailable"))?;
        let temp = plan
            .target_path
            .with_file_name(".pitchProx-update-restore.exe");
        ensure_regular(&temp, true).map_err(|e| e.to_string())?;
        remove(&temp).map_err(|e| e.to_string())?;
        let _guard = Staging(temp.clone());
        copy_verified(recovery, &temp, &plan.old_sha256).map_err(|e| e.to_string())?;
        if plan.target_path.is_file() {
            replace(&plan.target_path, &temp, None).map_err(|e| e.to_string())?;
        } else {
            move_file(&temp, &plan.target_path).map_err(|e| e.to_string())?;
        }
    }
    if !has_hash(&plan.target_path, &plan.old_sha256) {
        return Err("rollback executable failed verification".into());
    }
    let (pid, process) = launch(plan, false)?;
    healthy(plan, pid, &process, false)?;
    let mut failed = Status::new(
        "failed",
        &plan.version,
        "Прежняя рабочая версия восстановлена",
    );
    failed.error = format!("{cause}; previous version restored");
    failed.transaction_id = plan.transaction_id.clone();
    atomic_json(&plan.state_path, &failed).map_err(|e| e.to_string())?;
    clean(plan).map_err(|e| e.to_string())?;
    Err(failed.error)
}
fn launch(plan: &Handoff, install: bool) -> Result<(u32, platform::Handle), String> {
    if plan.mode == "service" {
        verify_service(plan, false)?;
        service::manage("start")?;
        let mut pid = 0;
        wait(Duration::from_secs(45), || {
            let status = service::state(&plan.service_name).map_err(|e| e.to_string())?;
            pid = status.dwProcessId;
            Ok(status.dwCurrentState == SERVICE_RUNNING && pid != 0)
        })?;
        verify_executable(pid, &plan.target_path)?;
        return Ok((pid, tracked_process(pid)?));
    }
    let mut command = Command::new(&plan.target_path);
    command
        .current_dir(plan.target_path.parent().unwrap())
        .arg("run")
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_remove(TOKEN);
    if install && !plan.legacy_health {
        command.env(TOKEN, &plan.update_token);
    }
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let pid = child.id();
    match tracked_process(pid) {
        Ok(process) => Ok((pid, process)),
        Err(err) => {
            let _ = child.kill();
            let _ = child.wait();
            Err(err)
        }
    }
}
fn healthy(
    plan: &Handoff,
    pid: u32,
    process: &platform::Handle,
    installing: bool,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut count = 0;
    let url = format!("http://{}", plan.listen_address);
    while Instant::now() < deadline {
        if unsafe { WaitForSingleObject(process.raw(), 0) } != WAIT_TIMEOUT {
            return Err("application exited before becoming healthy".into());
        }
        let good = localhttp::request(
            &url,
            "GET",
            "/api/health",
            &[],
            false,
            Duration::from_millis(800),
        )
        .ok()
        .filter(|(code, data)| *code == 200 && data.len() <= 8192)
        .and_then(|(_, data)| serde_json::from_slice::<Value>(&data).ok())
        .is_some_and(|status| {
            status["ok"] == true
                && if installing && plan.legacy_health {
                    true
                } else if installing {
                    status["pid"] == pid
                        && status["version"] == plan.version
                        && status["update_token"] == plan.update_token
                } else {
                    status["pid"] == pid && status["version"] == plan.old_version
                }
        });
        count = if good { count + 1 } else { 0 };
        if count >= 3 {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(400));
    }
    Err("application did not pass the health check".into())
}
fn wait_service(name: &str, wanted: u32) -> Result<(), String> {
    wait(Duration::from_secs(45), || {
        service::state(name)
            .map(|status| status.dwCurrentState == wanted)
            .map_err(|e| e.to_string())
    })
}
fn wait(time: Duration, mut test: impl FnMut() -> Result<bool, String>) -> Result<(), String> {
    let start = Instant::now();
    while start.elapsed() < time {
        if test()? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(50));
    }
    Err("operation timed out".into())
}
fn copy_verified(input: &Path, output: &Path, digest: &str) -> io::Result<()> {
    ensure_regular(input, false)?;
    let mut input = File::open(input)?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?;
    let mut bytes = [0_u8; 64 << 10];
    let mut hash = Sha256::new();
    loop {
        let size = input.read(&mut bytes)?;
        if size == 0 {
            break;
        }
        hash.update(&bytes[..size]);
        destination.write_all(&bytes[..size])?;
    }
    destination.sync_all()?;
    if !hex(&hash.finalize()).eq_ignore_ascii_case(digest) {
        return Err(io::Error::other("copied file failed SHA-256 verification"));
    }
    Ok(())
}
fn replace(target: &Path, source: &Path, backup: Option<&Path>) -> io::Result<()> {
    let target = platform::wide(target.as_os_str());
    let source = platform::wide(source.as_os_str());
    let backup = backup.map(|name| platform::wide(name.as_os_str()));
    if unsafe {
        ReplaceFileW(
            target.as_ptr(),
            source.as_ptr(),
            backup.as_ref().map_or(null(), |p| p.as_ptr()),
            0,
            null(),
            null(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn move_file(source: &Path, dest: &Path) -> io::Result<()> {
    let source = platform::wide(source.as_os_str());
    let dest = platform::wide(dest.as_os_str());
    if unsafe {
        MoveFileExW(
            source.as_ptr(),
            dest.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn clean(plan: &Handoff) -> io::Result<()> {
    for path in [
        &plan.stage_path,
        &plan.ready_path,
        &plan.proceed_path,
        &plan.backup_path,
        &plan.recovery_path,
        &plan.plan_path,
    ] {
        ensure_regular(path, true)?;
        remove(path)?;
    }
    Ok(())
}
pub(super) fn reconcile(target: &Path) -> Result<(), String> {
    let directory = target.parent().ok_or("invalid installation path")?;
    let plan = load(&directory.join(PLAN), directory)?;
    if !eqpath(&plan.target_path, target) {
        return Err("Незавершённое обновление содержит небезопасные пути".into());
    }
    let mut status = if VERSION == plan.version && has_hash(target, &plan.new_sha256) {
        let saved=read_json::<Status>(&plan.state_path,64<<10).map_err(|_|"Новая версия запущена, но helper не подтвердил завершение; резервная копия сохранена для ручного восстановления")?;
        if saved.phase != "completed"
            || saved.busy
            || saved.version != plan.version
            || saved.transaction_id != plan.transaction_id
            || saved.updated_at < plan.created_at
        {
            return Err("Новая версия запущена, но helper не подтвердил завершение; резервная копия сохранена для ручного восстановления".into());
        }
        let mut saved = saved;
        saved.message =
            "Обновление завершено; служебные файлы очищены после прерывания helper".into();
        saved
    } else if VERSION == plan.old_version && has_hash(target, &plan.old_sha256) {
        let mut state = Status::new("failed", &plan.version, "");
        state.transaction_id = plan.transaction_id.clone();
        state.error =
            "Предыдущее обновление было прервано; сохранена прежняя рабочая версия".into();
        state
    } else {
        return Err(
            "Состояние незавершённого обновления неоднозначно; автоматическая очистка отменена"
                .into(),
        );
    };
    status.updated_at = Utc::now();
    atomic_json(&plan.state_path, &status).map_err(|e| e.to_string())?;
    clean(&plan).map_err(|e| e.to_string())
}
