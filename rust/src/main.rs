#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use pitchprox_core::app::{config_path, history_path, App};
use pitchprox_core::config::Store;
use pitchprox_core::{cli, platform, updater};
use std::sync::Arc;

const USAGE: &str = "pitchProx commands:
  ctl         headless agent control (ctl help / ctl schema; JSON, no elevation)
  run         run desktop mode (single process: runtime + WebUI + tray)
  service     run under Windows Service Manager (headless)
  install     install Windows service
  uninstall   uninstall Windows service
  start       start Windows service
  stop        stop Windows service
  open        open localhost WebUI
  tray        run tray loop only (diagnostic mode against URL)";

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let command = args.first().map_or("run", String::as_str);
    if command == "run" {
        platform::hide_own_console();
    } else {
        platform::prepare_console();
    }
    if command == "ctl" {
        std::process::exit(cli::run(&args[1..]));
    }
    if let Err(error) = execute(command, &args) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn execute(command: &str, args: &[String]) -> Result<(), String> {
    match command {
        "run" => {
            if !platform::elevated() && !environment_is_one("PITCHPROX_ALLOW_UNELEVATED") {
                return platform::relaunch_elevated(args).map_err(|e| e.to_string());
            }
            let app = App::open(config_path(true), history_path(), "desktop")?;
            let outcome = desktop(app.clone());
            let shutdown = app.shutdown();
            outcome.and(shutdown)
        }
        "service" => {
            require_elevated(command)?;
            #[cfg(windows)]
            {
                pitchprox_core::service::run(App::open(
                    config_path(true),
                    history_path(),
                    "service",
                )?)
            }
            #[cfg(not(windows))]
            {
                Err("service mode is only available on Windows".into())
            }
        }
        "install" | "uninstall" | "start" | "stop" => {
            require_elevated(command)?;
            #[cfg(windows)]
            {
                pitchprox_core::service::manage(command)?;
                println!(
                    "service {}",
                    match command {
                        "install" => "installed",
                        "uninstall" => "uninstalled",
                        "start" => "started",
                        _ => "stopped",
                    }
                );
                Ok(())
            }
            #[cfg(not(windows))]
            {
                Err("service management is only available on Windows".into())
            }
        }
        "open" => {
            let config = Store::load_or_create(config_path(true))?;
            platform::open_browser(&format!("http://{}", config.current().http.listen))
                .map_err(|e| e.to_string())
        }
        "tray" => {
            #[cfg(windows)]
            {
                let mut url = String::new();
                let mut iter = args.iter().skip(1);
                while let Some(arg) = iter.next() {
                    if arg == "--url" {
                        if let Some(value) = iter.next() {
                            url = value.clone();
                        }
                    }
                }
                if url.is_empty() {
                    url = format!(
                        "http://{}",
                        Store::load_or_create(config_path(true))?
                            .current()
                            .http
                            .listen
                    );
                }
                pitchprox_core::tray::run(pitchprox_core::tray::Provider::Remote(url))
            }
            #[cfg(not(windows))]
            {
                Err("tray is only available on Windows".into())
            }
        }
        "update-helper" => updater::run_helper(args.get(1..).unwrap_or_default()),
        "windivert-license" => {
            println!(
                "WinDivert 2.2.2 (Copyright Basil)\nSource: https://github.com/basil00/WinDivert/tree/v2.2.2\n\n{}",
                include_str!("../../licenses/WinDivert-LICENSE.txt")
            );
            Ok(())
        }
        "help" | "--help" | "-h" => {
            println!("{USAGE}");
            Ok(())
        }
        _ => {
            println!("{USAGE}");
            std::process::exit(2);
        }
    }
}

fn desktop(app: Arc<App>) -> Result<(), String> {
    #[cfg(windows)]
    console_stop::install(app.stop.clone());
    app.start()?;
    #[cfg(windows)]
    if !environment_is_one("PITCHPROX_DISABLE_TRAY") && !environment_is_one("MYPROX_DISABLE_TRAY") {
        let app = app.clone();
        std::thread::Builder::new()
            .name("pitchprox-tray".into())
            .spawn(move || {
                if let Err(error) =
                    pitchprox_core::tray::run(pitchprox_core::tray::Provider::App(app.clone()))
                {
                    app.monitor.log("warn", format!("tray: {error}"), None);
                }
            })
            .map_err(|e| e.to_string())?;
    }
    app.stop.wait_forever();
    Ok(())
}

fn require_elevated(command: &str) -> Result<(), String> {
    if platform::elevated() {
        Ok(())
    } else {
        Err(format!(
            "{command} requires an elevated shell. Re-run PowerShell or Terminal as Administrator"
        ))
    }
}
fn environment_is_one(name: &str) -> bool {
    std::env::var(name).as_deref() == Ok("1")
}

#[cfg(windows)]
mod console_stop {
    use pitchprox_core::routing::Stop;
    use std::sync::{Arc, OnceLock};
    use windows_sys::Win32::System::Console::{
        SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_CLOSE_EVENT, CTRL_C_EVENT,
        CTRL_SHUTDOWN_EVENT,
    };
    static STOP: OnceLock<Arc<Stop>> = OnceLock::new();
    pub fn install(stop: Arc<Stop>) {
        let _ = STOP.set(stop);
        unsafe {
            SetConsoleCtrlHandler(Some(run), 1);
        }
    }
    unsafe extern "system" fn run(event: u32) -> i32 {
        if matches!(
            event,
            CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT | CTRL_SHUTDOWN_EVENT
        ) {
            if let Some(stop) = STOP.get() {
                stop.signal();
            }
            1
        } else {
            0
        }
    }
}
