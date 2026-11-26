use crate::app::{App, VERSION};
use chrono::Utc;
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::Win32::System::ProcessStatus::{
    K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS_EX,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetGuiResources, GetProcessHandleCount, GetProcessIoCounters,
    GetProcessTimes, IO_COUNTERS,
};

pub fn start(app: Arc<App>) -> Option<JoinHandle<()>> {
    let (filename, interval) = configuration()?;
    let worker = app.clone();
    match thread::Builder::new()
        .name("pitchprox-diagnostics".into())
        .spawn(move || {
            if let Err(error) = log(&worker, filename, interval) {
                worker.monitor.log(
                    "warn",
                    format!("resource diagnostics stopped: {error}"),
                    None,
                );
            }
        }) {
        Ok(worker) => Some(worker),
        Err(error) => {
            app.monitor.log(
                "warn",
                format!("resource diagnostics disabled: {error}"),
                None,
            );
            None
        }
    }
}

fn configuration() -> Option<(PathBuf, Duration)> {
    let get = |key| std::env::var(key).unwrap_or_default().trim().to_owned();
    let on = |s: &str| {
        matches!(
            s.to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on" | "default"
        )
    };
    let named = get("PITCHPROX_RESOURCE_DIAGNOSTIC_DEFAULTS");
    let exe = std::env::current_exe().ok();
    let diagnostic = if named.is_empty() {
        exe.as_ref()
            .and_then(|path| path.file_name())
            .is_some_and(|name| {
                name.to_string_lossy()
                    .to_ascii_lowercase()
                    .contains("diagnostic")
            })
    } else {
        on(&named)
    };
    let mut path = get("PITCHPROX_RESOURCE_LOG");
    if path.is_empty() {
        path = get("PITCHPROX_DIAG_RESOURCE_LOG");
    }
    if path.is_empty() && diagnostic {
        path = "default".into();
    }
    if path.is_empty()
        || matches!(
            path.to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off" | "disabled"
        )
    {
        return None;
    }
    let path = if on(&path) {
        exe.map(|path| path.with_file_name("pitchProx.resources.jsonl"))
            .unwrap_or_else(|| std::env::temp_dir().join("pitchProx.resources.jsonl"))
    } else {
        PathBuf::from(path)
    };
    let interval = parse_interval(&get("PITCHPROX_RESOURCE_LOG_INTERVAL"))
        .unwrap_or(Duration::from_secs(if diagnostic { 15 } else { 30 }));
    Some((path, interval))
}

fn parse_interval(value: &str) -> Option<Duration> {
    if let Ok(seconds) = value.parse::<u64>() {
        return (seconds > 0).then(|| Duration::from_secs(seconds));
    }
    let mut value = value;
    let mut seconds = 0.0;
    while !value.is_empty() {
        let unit = value.find(|c: char| !c.is_ascii_digit() && c != '.')?;
        let size = value[..unit].parse::<f64>().ok()?;
        let suffix = &value[unit..];
        let (multiplier, length) = if suffix.starts_with("ms") {
            (0.001, 2)
        } else if suffix.starts_with('h') {
            (3600.0, 1)
        } else if suffix.starts_with('m') {
            (60.0, 1)
        } else if suffix.starts_with('s') {
            (1.0, 1)
        } else {
            return None;
        };
        seconds += size * multiplier;
        value = &suffix[length..];
    }
    (seconds >= 1.0)
        .then(|| Duration::try_from_secs_f64(seconds).ok())
        .flatten()
}

fn log(app: &App, path: PathBuf, interval: Duration) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut output = BufWriter::new(OpenOptions::new().create(true).append(true).open(path)?);
    let start = Instant::now();
    write_record(
        &mut output,
        json!({"event":"resource_diagnostics_manifest","time":Utc::now(),
        "pid":std::process::id(),"version":VERSION,"runtime":"rust","interval_seconds":interval.as_secs_f64()}),
    )?;
    let mut previous = None;
    loop {
        let os = sample_os()?;
        let app_state = app.diagnostics();
        let stopped = app.stop.stopped();
        let mut entry = json!({"event":if stopped {"stop"}else{"sample"},"time":Utc::now(),"uptime_seconds":start.elapsed().as_secs_f64(),
            "pid":std::process::id(),"ui_active":app_state["monitor"]["ui_active"],"os":os,"app":app_state});
        if let Some(old) = previous {
            let delta = |field: &str| os[field].as_i64().unwrap_or_default() - old_os(&old, field);
            entry["delta"] = json!({"private_bytes":delta("private_bytes"),"working_set_bytes":delta("working_set_bytes"),
                "handle_count":delta("handle_count"),"user_time_ms":delta("user_time_ms"),"kernel_time_ms":delta("kernel_time_ms")});
        }
        write_record(&mut output, entry)?;
        if stopped {
            return Ok(());
        }
        previous = Some(os);
        app.stop.wait(interval);
    }
}
fn old_os(value: &Value, name: &str) -> i64 {
    value[name].as_i64().unwrap_or_default()
}
fn write_record(output: &mut impl Write, value: Value) -> io::Result<()> {
    serde_json::to_writer(&mut *output, &value)?;
    output.write_all(b"\n")?;
    output.flush()
}
fn sample_os() -> io::Result<Value> {
    let process = unsafe { GetCurrentProcess() };
    let mut mem = PROCESS_MEMORY_COUNTERS_EX {
        cb: std::mem::size_of::<PROCESS_MEMORY_COUNTERS_EX>() as u32,
        ..PROCESS_MEMORY_COUNTERS_EX::default()
    };
    let mut io = IO_COUNTERS::default();
    let mut handles = 0;
    let (mut created, mut exit, mut kernel, mut user) = (
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
        FILETIME::default(),
    );
    unsafe {
        if K32GetProcessMemoryInfo(
            process,
            (&mut mem as *mut PROCESS_MEMORY_COUNTERS_EX).cast(),
            mem.cb,
        ) == 0
            || GetProcessHandleCount(process, &mut handles) == 0
            || GetProcessIoCounters(process, &mut io) == 0
            || GetProcessTimes(process, &mut created, &mut exit, &mut kernel, &mut user) == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    let millis = |time: FILETIME| {
        ((u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)) / 10000
    };
    Ok(
        json!({"private_bytes":mem.PrivateUsage,"working_set_bytes":mem.WorkingSetSize,"peak_working_set_bytes":mem.PeakWorkingSetSize,
        "pagefile_bytes":mem.PagefileUsage,"peak_pagefile_bytes":mem.PeakPagefileUsage,"page_fault_count":mem.PageFaultCount,"handle_count":handles,
        "gdi_handle_count":unsafe{GetGuiResources(process,0)},"user_handle_count":unsafe{GetGuiResources(process,1)},
        "user_time_ms":millis(user),"kernel_time_ms":millis(kernel),"read_operation_count":io.ReadOperationCount,
        "write_operation_count":io.WriteOperationCount,"other_operation_count":io.OtherOperationCount,
        "read_transfer_bytes":io.ReadTransferCount,"write_transfer_bytes":io.WriteTransferCount,"other_transfer_bytes":io.OtherTransferCount}),
    )
}
