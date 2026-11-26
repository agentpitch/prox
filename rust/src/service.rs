use crate::app::App;
use crate::platform;
use std::io;
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::{Arc, OnceLock};
use windows_sys::Win32::System::Services::*;

pub const NAME: &str = "pitchProx";
const DISPLAY: &str = "pitchProx Transparent Proxy";
const DESCRIPTION: &str = "Local WebUI + WinDivert transparent proxy service";
static APP: OnceLock<Arc<App>> = OnceLock::new();
static OUTCOME: OnceLock<Result<(), String>> = OnceLock::new();

pub(crate) struct ServiceHandle(SC_HANDLE);
impl ServiceHandle {
    pub(crate) fn new(handle: SC_HANDLE) -> io::Result<Self> {
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }

    pub(crate) fn raw(&self) -> SC_HANDLE {
        self.0
    }
}
impl Drop for ServiceHandle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

pub fn run(app: Arc<App>) -> Result<(), String> {
    APP.set(app).map_err(|_| "service is already running")?;
    let mut name = platform::wide(NAME);
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: null_mut(),
            lpServiceProc: None,
        },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
        return Err(io::Error::last_os_error().to_string());
    }
    OUTCOME.get().cloned().unwrap_or(Ok(()))
}

unsafe extern "system" fn service_main(_: u32, _: *mut *mut u16) {
    let name = platform::wide(NAME);
    let status = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), null()) };
    if status.is_null() {
        let _ = OUTCOME.set(Err(io::Error::last_os_error().to_string()));
        return;
    }
    let app = APP.get().unwrap();
    publish(status, SERVICE_START_PENDING, 0);
    let result = match app.start() {
        Ok(()) => {
            publish(status, SERVICE_RUNNING, 0);
            app.stop.wait_forever();
            publish(status, SERVICE_STOP_PENDING, 0);
            app.shutdown()
        }
        Err(err) => {
            let _ = app.shutdown();
            Err(err)
        }
    };
    publish(status, SERVICE_STOPPED, u32::from(result.is_err()));
    let _ = OUTCOME.set(result);
}

unsafe extern "system" fn control(
    command: u32,
    _: u32,
    _: *mut std::ffi::c_void,
    _: *mut std::ffi::c_void,
) -> u32 {
    if matches!(command, SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN) {
        if let Some(app) = APP.get() {
            app.stop.signal();
        }
    }
    0
}

fn publish(handle: SERVICE_STATUS_HANDLE, state: u32, exit: u32) {
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        } else {
            0
        },
        dwWin32ExitCode: exit,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: u32::from(matches!(
            state,
            SERVICE_START_PENDING | SERVICE_STOP_PENDING
        )),
        dwWaitHint: if matches!(state, SERVICE_START_PENDING | SERVICE_STOP_PENDING) {
            15000
        } else {
            0
        },
    };
    unsafe {
        SetServiceStatus(handle, &status);
    }
}

pub(crate) fn manager(access: u32) -> io::Result<ServiceHandle> {
    ServiceHandle::new(unsafe { OpenSCManagerW(null(), null(), access) })
}
fn open(name: &str, access: u32) -> io::Result<ServiceHandle> {
    let manager = manager(SC_MANAGER_CONNECT)?;
    let name = platform::wide(name);
    ServiceHandle::new(unsafe { OpenServiceW(manager.0, name.as_ptr(), access) })
}
pub fn manage(command: &str) -> Result<(), String> {
    if command == "install" {
        return install(&std::env::current_exe().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string());
    }
    let access = match command {
        "uninstall" => 0x0001_0000,
        "start" => SERVICE_START,
        "stop" => SERVICE_STOP,
        _ => return Err("unknown service command".into()),
    };
    let handle = open(NAME, access).map_err(|e| e.to_string())?;
    let result = unsafe {
        match command {
            "uninstall" => DeleteService(handle.0),
            "start" => StartServiceW(handle.0, 0, null()),
            "stop" => ControlService(
                handle.0,
                SERVICE_CONTROL_STOP,
                &mut SERVICE_STATUS::default(),
            ),
            _ => unreachable!(),
        }
    };
    if result == 0 {
        Err(io::Error::last_os_error().to_string())
    } else {
        Ok(())
    }
}

fn install(exe: &Path) -> io::Result<()> {
    let manager = manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let name = platform::wide(NAME);
    if let Ok(old) =
        ServiceHandle::new(unsafe { OpenServiceW(manager.0, name.as_ptr(), SERVICE_QUERY_STATUS) })
    {
        drop(old);
        return Err(io::Error::other(format!("service {NAME:?} already exists")));
    }
    let display = platform::wide(DISPLAY);
    let path = platform::wide(format!(
        "{} service",
        platform::quote_arg(&exe.to_string_lossy())
    ));
    let service = ServiceHandle::new(unsafe {
        CreateServiceW(
            manager.0,
            name.as_ptr(),
            display.as_ptr(),
            SERVICE_CHANGE_CONFIG,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            path.as_ptr(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
        )
    })?;
    let mut description = platform::wide(DESCRIPTION);
    let value = SERVICE_DESCRIPTIONW {
        lpDescription: description.as_mut_ptr(),
    };
    if unsafe {
        ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_DESCRIPTION,
            (&value as *const SERVICE_DESCRIPTIONW).cast(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn state(name: &str) -> io::Result<SERVICE_STATUS_PROCESS> {
    let service = open(name, SERVICE_QUERY_STATUS)?;
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut used = 0;
    if unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            std::mem::size_of_val(&status) as u32,
            &mut used,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(status)
}

pub fn binary_command(name: &str) -> io::Result<String> {
    let service = open(name, SERVICE_QUERY_CONFIG)?;
    let mut length = 0;
    unsafe {
        QueryServiceConfigW(service.0, null_mut(), 0, &mut length);
    }
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    let mut buffer = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
    let config = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    if unsafe { QueryServiceConfigW(service.0, config, length, &mut length) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let ptr = unsafe { (*config).lpBinaryPathName };
    let base = buffer.as_ptr() as usize;
    let end = base + buffer.len() * std::mem::size_of::<usize>();
    if ptr.is_null() || (ptr as usize) < base || (ptr as usize) >= end {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let data = unsafe { std::slice::from_raw_parts(ptr, (end - ptr as usize) / 2) };
    let n = data
        .iter()
        .position(|b| *b == 0)
        .ok_or(io::ErrorKind::InvalidData)?;
    Ok(String::from_utf16_lossy(&data[..n]))
}
