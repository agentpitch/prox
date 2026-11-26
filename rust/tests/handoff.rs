#![cfg(windows)]

use chrono::Utc;
use pitchprox_core::{config::Config, localhttp, platform::Handle};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Write;
use std::net::TcpListener;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use windows_sys::Win32::Storage::FileSystem::{
    LockFileEx, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, CREATE_NO_WINDOW, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

struct Fixture {
    root: PathBuf,
    url: String,
    original: Option<Child>,
    helper: Option<Child>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = http(&self.url, "POST", "/api/control/stop");
        for process in [&mut self.original, &mut self.helper].into_iter().flatten() {
            let _ = process.kill();
            let _ = process.wait();
        }
    }
}

#[test]
fn windows_helper_replaces_and_restarts_a_disposable_copy() {
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = probe.local_addr().unwrap().to_string();
    drop(probe);
    let root = std::env::temp_dir().join(format!(
        "pitchprox-handoff-test-{}-{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap()
    ));
    fs::create_dir_all(&root).unwrap();
    let mut fixture = Fixture {
        root,
        url: format!("http://{address}"),
        original: None,
        helper: None,
    };
    let target = fixture.root.join("pitchProx.exe");
    let helper = fixture.root.join(".pitchProx-update-helper.exe");
    let stage = fixture.root.join(".pitchProx-update-stage.exe");
    let recovery = fixture.root.join(".pitchProx-update-recovery.exe");
    let backup = fixture.root.join(".pitchProx-update-backup.exe");
    let plan_path = fixture.root.join(".pitchProx-update-plan.json");
    let state = fixture.root.join(".pitchProx-update-state.json");
    let ready = fixture.root.join(".pitchProx-update-ready");
    let proceed = fixture.root.join(".pitchProx-update-proceed");
    let config_path = fixture.root.join("pitchProx.config.json");
    let history_path = fixture.root.join("history");
    let built = Path::new(env!("CARGO_BIN_EXE_pitchProx"));
    for path in [&target, &helper, &stage] {
        fs::copy(built, path).unwrap();
    }
    let old_hash = hash(&target);
    let mut file = File::options().append(true).open(&stage).unwrap();
    file.write_all(b"disposable update fixture").unwrap();
    drop(file);
    let new_hash = hash(&stage);
    assert_ne!(old_hash, new_hash);
    let mut config = Config::fresh();
    config.http.listen = address.clone();
    fs::write(&config_path, serde_json::to_vec(&config).unwrap()).unwrap();

    let child = spawn(&target, &["run"], &config_path, &history_path);
    let parent_pid = child.id();
    fixture.original = Some(child);
    let previous = await_value(Duration::from_secs(12), || {
        http(&fixture.url, "GET", "/api/health").filter(|value| value["pid"] == parent_pid)
    });
    let parent =
        Handle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, parent_pid) })
            .unwrap();
    let start = parent.creation_time().unwrap();
    let token = "81".repeat(32);
    let transaction = format!("{:x}", Sha256::digest(token.as_bytes()));
    let created = Utc::now();
    let plan = json!({
        "format":"pitchprox.update-plan","format_version":2,"mode":"desktop",
        "target_path":target,"stage_path":stage,"backup_path":backup,"recovery_path":recovery,"plan_path":plan_path,
        "ready_path":ready,"proceed_path":proceed,"state_path":state,"parent_pid":parent_pid,"parent_started":start,
        "listen_address":address,"version":"v0.41","old_version":previous["version"],
        "old_sha256":old_hash,"new_sha256":new_hash,"update_token":token,"transaction_id":transaction,
        "legacy_health":true,"created_at":created
    });
    let lock = File::create(fixture.root.join(".pitchProx-update.lock")).unwrap();
    let mut request = OVERLAPPED::default();
    assert_ne!(
        unsafe {
            LockFileEx(
                lock.as_raw_handle(),
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut request,
            )
        },
        0
    );
    write_json(&plan_path, &plan);
    write_json(
        &state,
        &json!({"phase":"restarting","busy":true,"version":"v0.41",
        "transaction_id":transaction,"updated_at":created}),
    );
    let worker = spawn(
        &helper,
        &["update-helper", "--plan", plan_path.to_str().unwrap()],
        &config_path,
        &history_path,
    );
    let helper_pid = worker.id();
    fixture.helper = Some(worker);
    let matches = |phase| {
        let record = read_json(&ready)?;
        (record["phase"] == phase
            && record["helper_pid"] == helper_pid
            && record["transaction_id"] == transaction)
            .then_some(record)
    };
    await_value(Duration::from_secs(10), || matches("observing"));
    drop(lock);
    await_value(Duration::from_secs(10), || matches("acquired"));
    write_json(
        &proceed,
        &json!({"phase":"proceed","token":token,"transaction_id":transaction,
        "helper_pid":helper_pid,"parent_started":start}),
    );
    await_value(Duration::from_secs(10), || matches("proceeding"));
    assert_eq!(
        http(&fixture.url, "POST", "/api/control/stop").unwrap()["stopping"],
        true
    );
    let restarted = await_value(Duration::from_secs(30), || {
        http(&fixture.url, "GET", "/api/health")
            .filter(|health| health["ok"] == true && health["pid"] != parent_pid)
    });
    let completed = await_value(Duration::from_secs(12), || {
        read_json(&state).filter(|value| value["phase"] == "completed")
    });
    assert_eq!(completed["transaction_id"], transaction);
    assert_eq!(hash(&target), new_hash);
    assert_eq!(restarted["version"], previous["version"]);
    await_value(Duration::from_secs(5), || {
        (!plan_path.exists() && !backup.exists() && !recovery.exists()).then_some(())
    });
    assert!(fixture.helper.as_mut().unwrap().wait().unwrap().success());
    assert!(fixture.original.as_mut().unwrap().wait().unwrap().success());
}

fn spawn(executable: &Path, args: &[&str], config: &Path, history: &Path) -> Child {
    Command::new(executable)
        .args(args)
        .current_dir(executable.parent().unwrap())
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env("PITCHPROX_CONFIG", config)
        .env("PITCHPROX_HISTORY", history)
        .env("PITCHPROX_ALLOW_UNELEVATED", "1")
        .env("PITCHPROX_DISABLE_TRAY", "1")
        .env("PITCHPROX_RESOURCE_LOG", "off")
        .spawn()
        .unwrap()
}

fn hash(path: &Path) -> String {
    format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
}
fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn read_json(path: &Path) -> Option<Value> {
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}
fn http(url: &str, method: &str, path: &str) -> Option<Value> {
    let (_, bytes) =
        localhttp::request(url, method, path, &[], false, Duration::from_millis(500)).ok()?;
    serde_json::from_slice(&bytes).ok()
}
fn await_value<T>(timeout: Duration, mut task: impl FnMut() -> Option<T>) -> T {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Some(value) = task() {
            return value;
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    panic!("handoff timed out during isolated verification");
}
