use crate::flow::{Direction, Flow, FlowTable};
use crate::monitor::{action_name, Monitor};
use crate::packet::Packet;
use crate::platform::{self, TcpOwner};
use crate::routing::{request, ExeCache, SharedRoutes, Stop};
use crate::rules::Action;
use std::collections::HashSet;
use std::ffi::CString;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{FreeLibrary, HANDLE, HMODULE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

const CLASSIFIER: &str =
    "outbound and tcp and !loopback and !impostor and tcp.Syn and !tcp.Ack and !tcp.Rst";
const CLEANUP: Duration = Duration::from_secs(30);
const SHUTDOWN_RECV: u32 = 1;

#[repr(C, align(8))]
#[derive(Clone, Copy)]
struct Address([u8; 80]);

type Open = unsafe extern "system" fn(*const i8, u32, i16, u64) -> HANDLE;
type Close = unsafe extern "system" fn(HANDLE) -> i32;
type Shutdown = unsafe extern "system" fn(HANDLE, u32) -> i32;
type Recv = unsafe extern "system" fn(HANDLE, *mut u8, u32, *mut u32, *mut Address) -> i32;
type Send = unsafe extern "system" fn(HANDLE, *const u8, u32, *mut u32, *const Address) -> i32;
type Checksum = unsafe extern "system" fn(*mut u8, u32, *mut Address, u64) -> i32;

struct Library(HMODULE);
unsafe impl std::marker::Send for Library {}
unsafe impl Sync for Library {}
impl Drop for Library {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.0);
        }
    }
}

struct Api {
    _library: Library,
    open: Open,
    close: Close,
    shutdown: Shutdown,
    recv: Recv,
    send: Send,
    checksum: Checksum,
}
impl Api {
    fn load() -> io::Result<Arc<Self>> {
        let executable = std::env::current_exe()?;
        let path = executable.with_file_name("WinDivert.dll");
        let path = platform::wide(path.as_os_str());
        let module = unsafe {
            LoadLibraryExW(
                path.as_ptr(),
                null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
        };
        if module.is_null() {
            return Err(io::Error::last_os_error());
        }
        let library = Library(module);
        macro_rules! symbol {
            ($name:literal, $ty:ty) => {{
                let pointer = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) }
                    .ok_or_else(io::Error::last_os_error)?;
                // Signature and calling convention are from the WinDivert 2.2 header.
                unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(pointer) }
            }};
        }
        Ok(Arc::new(Self {
            _library: library,
            open: symbol!("WinDivertOpen", Open),
            close: symbol!("WinDivertClose", Close),
            shutdown: symbol!("WinDivertShutdown", Shutdown),
            recv: symbol!("WinDivertRecv", Recv),
            send: symbol!("WinDivertSend", Send),
            checksum: symbol!("WinDivertHelperCalcChecksums", Checksum),
        }))
    }

    fn open(self: &Arc<Self>, filter: &str, priority: i16) -> io::Result<Arc<Device>> {
        let filter = CString::new(filter).map_err(io::Error::other)?;
        let handle = unsafe { (self.open)(filter.as_ptr(), 0, priority, 0) };
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::other(format!(
                "WinDivertOpen: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(Arc::new(Device {
            api: self.clone(),
            handle,
            stopped: AtomicBool::new(false),
        }))
    }
}

struct Device {
    api: Arc<Api>,
    handle: HANDLE,
    stopped: AtomicBool,
}
unsafe impl std::marker::Send for Device {}
unsafe impl Sync for Device {}
impl Device {
    fn stop(&self) {
        if !self.stopped.swap(true, Ordering::AcqRel) {
            unsafe {
                (self.api.shutdown)(self.handle, SHUTDOWN_RECV);
            }
        }
    }
    fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }
    fn recv(&self, data: &mut [u8], address: &mut Address) -> io::Result<usize> {
        let mut size = 0;
        if unsafe {
            (self.api.recv)(
                self.handle,
                data.as_mut_ptr(),
                data.len() as u32,
                &mut size,
                address,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if size as usize > data.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(size as usize)
    }
    fn send(&self, data: &[u8], address: &Address) -> io::Result<()> {
        let mut size = 0;
        if unsafe {
            (self.api.send)(
                self.handle,
                data.as_ptr(),
                data.len() as u32,
                &mut size,
                address,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if size as usize != data.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(())
    }
    fn checksum(&self, data: &mut [u8], address: &mut Address) -> io::Result<()> {
        if unsafe { (self.api.checksum)(data.as_mut_ptr(), data.len() as u32, address, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
impl Drop for Device {
    fn drop(&mut self) {
        unsafe {
            (self.api.close)(self.handle);
        }
    }
}

struct Worker {
    device: Arc<Device>,
    task: Option<JoinHandle<()>>,
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.device.stop();
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

struct Shared {
    flows: Arc<FlowTable>,
    monitor: Arc<Monitor>,
    routes: SharedRoutes,
    stop: Arc<Stop>,
    port: u16,
    local: HashSet<IpAddr>,
    wake: SyncSender<()>,
    redirector: Mutex<Option<Worker>>,
    last_error: Mutex<(Option<Instant>, u64)>,
}

pub struct Capture {
    classifier: Option<Worker>,
    cleanup: Option<JoinHandle<()>>,
    shared: Arc<Shared>,
}

impl Capture {
    pub fn start(
        port: u16,
        routes: SharedRoutes,
        flows: Arc<FlowTable>,
        monitor: Arc<Monitor>,
        stop: Arc<Stop>,
    ) -> io::Result<Self> {
        let local = platform::local_ips()?;
        let device = Api::load()?.open(CLASSIFIER, 200)?;
        let (wake, events) = mpsc::sync_channel(1);
        let callback = wake.clone();
        let shared = Arc::new(Shared {
            flows,
            monitor,
            routes,
            stop,
            port,
            local,
            wake,
            redirector: Mutex::new(None),
            last_error: Mutex::new((None, 0)),
        });
        let mut capture = Self {
            classifier: None,
            cleanup: None,
            shared: shared.clone(),
        };
        shared.flows.set_on_empty(Some(Arc::new(move || {
            let _ = callback.try_send(());
        })));
        capture.cleanup = Some(
            thread::Builder::new()
                .name("pitchprox-flow-cleanup".into())
                .spawn({
                    let shared = shared.clone();
                    move || {
                        while !shared.stop.stopped() {
                            if shared.flows.is_empty() {
                                let mut redirector = shared.redirector.lock().unwrap();
                                if shared.flows.is_empty() {
                                    redirector.take();
                                }
                                drop(redirector);
                                if events.recv().is_err() {
                                    break;
                                }
                            } else if events.recv_timeout(CLEANUP).is_err() {
                                shared.flows.cleanup(CLEANUP);
                            }
                        }
                    }
                })?,
        );
        let task = thread::Builder::new()
            .name("pitchprox-syn-classifier".into())
            .spawn({
                let (shared, device) = (shared.clone(), device.clone());
                move || classifier(&shared, &device)
            })?;
        capture.classifier = Some(Worker {
            device,
            task: Some(task),
        });
        shared.monitor.log(
            "info",
            "WinDivert started with selective SYN classifier and lazy shared redirector",
            None,
        );
        Ok(capture)
    }
}

impl Drop for Capture {
    fn drop(&mut self) {
        self.shared.stop.signal();
        self.shared.flows.set_on_empty(None);
        let _ = self.shared.wake.try_send(());
        self.classifier.take();
        if let Some(task) = self.cleanup.take() {
            let _ = task.join();
        }
        self.shared.redirector.lock().unwrap().take();
    }
}

impl Shared {
    fn redirector(self: &Arc<Self>, api: &Arc<Api>) -> io::Result<()> {
        let mut state = self.redirector.lock().unwrap();
        if self.stop.stopped() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if state.is_some() {
            return Ok(());
        }
        let port = self.port;
        let filter = format!("outbound and tcp and !impostor and (!loopback or tcp.SrcPort == {port} or tcp.DstPort == {port})");
        let device = api.open(&filter, 100)?;
        let thread_device = device.clone();
        let shared = self.clone();
        let task = thread::Builder::new()
            .name("pitchprox-divert-redirector".into())
            .spawn(move || redirect(&shared, &thread_device))?;
        *state = Some(Worker {
            device,
            task: Some(task),
        });
        Ok(())
    }

    fn packet_error(&self, operation: &str, err: io::Error) {
        let mut state = self.last_error.lock().unwrap();
        if state
            .0
            .is_some_and(|time| time.elapsed() < Duration::from_secs(5))
        {
            state.1 += 1;
            return;
        }
        let suppressed = state.1;
        *state = (Some(Instant::now()), 0);
        drop(state);
        self.monitor.log(
            "error",
            format!("WinDivert {operation}: {err} (suppressed {suppressed})"),
            None,
        );
    }

    fn reinject(&self, device: &Device, raw: &[u8], address: &Address, operation: &str) -> bool {
        match device.send(raw, address) {
            Ok(()) => true,
            Err(err) => {
                self.packet_error(operation, err);
                false
            }
        }
    }
}

fn classifier(shared: &Arc<Shared>, device: &Device) {
    let mut owners = OwnerCache::new();
    let mut raw = vec![0; 0xffff];
    let mut backup = Vec::new();
    while !device.stopped() {
        let mut address = Address([0; 80]);
        let n = match device.recv(&mut raw, &mut address) {
            Ok(size) => size,
            Err(_) if device.stopped() || shared.stop.stopped() => break,
            Err(err) => {
                shared
                    .monitor
                    .log("error", format!("WinDivert classifier recv: {err}"), None);
                shared.stop.wait(Duration::from_millis(200));
                continue;
            }
        };
        let buf = &mut raw[..n];
        if device.stopped() || shared.stop.stopped() {
            shared.reinject(device, buf, &address, "classifier stopping passthrough");
            continue;
        }
        let Ok(mut packet) = Packet::parse(buf) else {
            shared.reinject(device, buf, &address, "classifier parse fallback");
            continue;
        };
        let local = SocketAddr::new(packet.src, packet.src_port);
        let remote = SocketAddr::new(packet.dst, packet.dst_port);
        if packet.dst.is_loopback() || shared.local.contains(&packet.dst.to_canonical()) {
            shared.reinject(
                device,
                packet.bytes(),
                &address,
                "classifier local passthrough",
            );
            continue;
        }
        let Some((pid, exe, tries)) = owners.lookup(local, remote, &shared.stop) else {
            shared.monitor.log(
                "warn",
                format!("owner lookup failed for {local} -> {remote}, passing direct"),
                None,
            );
            shared.reinject(
                device,
                packet.bytes(),
                &address,
                "classifier unknown-owner passthrough",
            );
            continue;
        };
        if pid == std::process::id() {
            shared.reinject(
                device,
                packet.bytes(),
                &address,
                "classifier self passthrough",
            );
            continue;
        }
        let flow = Flow {
            pid,
            exe_path: exe,
            client: local,
            original: remote,
            ipv6: packet.ipv6,
        };
        let routes = shared.routes.read().unwrap().clone();
        let pre = routes.engine.preflight(request(&flow, ""));
        if pre.definitive && pre.decision.action() == Action::Direct {
            shared.reinject(
                device,
                packet.bytes(),
                &address,
                "classifier direct passthrough",
            );
            continue;
        }
        shared.flows.register(flow.clone());
        let _ = shared.wake.try_send(());
        if let Err(err) = shared.redirector(&device.api) {
            shared.flows.delete(flow.client);
            shared.monitor.log(
                "error",
                format!("shared redirector start failed for {local} -> {remote}: {err}"),
                None,
            );
            shared.reinject(
                device,
                packet.bytes(),
                &address,
                "classifier redirector fallback",
            );
            continue;
        }
        if shared.monitor.ui_active() {
            shared.monitor.log("debug", format!("intercepted pid={pid} exe={} {local} -> {remote} after {tries} owner tries action={} rule={}",
                flow.exe_path, action_name(pre.decision.action()), pre.decision.rule.map_or("", |rule| &rule.name)), None);
        }
        backup.clear();
        backup.extend_from_slice(packet.bytes());
        let original_address = address;
        if let Err(err) = packet
            .set_destination(flow.client.ip(), shared.port)
            .map_err(io::Error::other)
            .and_then(|_| device.checksum(buf, &mut address))
        {
            shared.flows.delete(flow.client);
            shared.packet_error("classifier checksum", err);
            shared.reinject(
                device,
                &backup,
                &original_address,
                "classifier checksum fallback",
            );
        } else if !shared.reinject(device, buf, &address, "classifier redirect") {
            shared.flows.delete(flow.client);
            shared.reinject(
                device,
                &backup,
                &original_address,
                "classifier redirect fallback",
            );
        }
    }
}

fn redirect(shared: &Shared, device: &Device) {
    let mut raw = vec![0; 0xffff];
    while !device.stopped() {
        let mut address = Address([0; 80]);
        let n = match device.recv(&mut raw, &mut address) {
            Ok(size) => size,
            Err(_) if device.stopped() || shared.stop.stopped() => break,
            Err(err) => {
                shared
                    .monitor
                    .log("warn", format!("WinDivert redirector recv: {err}"), None);
                shared.stop.wait(Duration::from_millis(100));
                continue;
            }
        };
        let buf = &mut raw[..n];
        if let Ok(mut packet) = Packet::parse(buf) {
            let source = SocketAddr::new(packet.src, packet.src_port);
            let destination = SocketAddr::new(packet.dst, packet.dst_port);
            if let Some((flow, direction)) = shared.flows.redirect(source, destination, shared.port)
            {
                let changed = match direction {
                    Direction::ListenerToApp => {
                        packet.set_source(flow.original.ip(), flow.original.port())
                    }
                    Direction::AppToListener => {
                        packet.set_destination(flow.client.ip(), shared.port)
                    }
                };
                if let Err(err) = changed
                    .map_err(io::Error::other)
                    .and_then(|_| device.checksum(buf, &mut address))
                {
                    shared.packet_error("redirector checksum", err);
                    continue;
                }
            }
        }
        shared.reinject(device, buf, &address, "redirector send");
    }
}

struct OwnerCache {
    rows: Vec<TcpOwner>,
    refreshed: Instant,
    paths: ExeCache,
}
impl OwnerCache {
    fn new() -> Self {
        Self {
            rows: platform::tcp_owners(),
            refreshed: Instant::now(),
            paths: ExeCache::default(),
        }
    }
    fn refresh(&mut self) {
        self.rows = platform::tcp_owners();
        self.refreshed = Instant::now();
        self.paths.prune();
    }
    fn lookup(
        &mut self,
        local: SocketAddr,
        remote: SocketAddr,
        stop: &Stop,
    ) -> Option<(u32, Arc<str>, usize)> {
        let local = SocketAddr::new(local.ip().to_canonical(), local.port());
        let remote = SocketAddr::new(remote.ip().to_canonical(), remote.port());
        for (i, delay) in [0, 0, 10, 30, 80].into_iter().enumerate() {
            if stop.wait(Duration::from_millis(delay)) {
                return None;
            }
            if i > 0 || self.refreshed.elapsed() >= Duration::from_secs(2) {
                self.refresh();
            }
            let found = self
                .rows
                .iter()
                .find(|r| r.local == local && r.remote == remote && r.pid != 0);
            let found = found.or_else(|| {
                self.rows
                    .iter()
                    .find(|r| r.local == local && r.pid != 0 && r.state != 2)
            });
            if let Some(row) = found {
                return Some((row.pid, self.paths.path(row.pid), i + 1));
            }
        }
        None
    }
}
