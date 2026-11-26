use crate::app::App;
use crate::{localhttp, platform};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::cell::{Cell, RefCell};
use std::io;
use std::ptr::{null, null_mut};
use std::sync::Arc;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Graphics::Gdi::{
    GetMonitorInfoW, MonitorFromPoint, MONITORINFO, MONITOR_DEFAULTTONEAREST,
};
use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::Shell::*;
use windows_sys::Win32::UI::WindowsAndMessaging::*;

const TRAY_EVENT: u32 = WM_APP + 1;
const NIN_KEYSELECT: u32 = NIN_SELECT | 1;
const MANAGE: usize = 1001;
const EXIT: usize = 1002;
const DISABLE_UI: usize = 1003;
const PAUSE: usize = 1004;
const RESUME: usize = 1005;
const ENABLE_UI: usize = 1006;
type Frame = [[u8; 4]; 256];
type Pixel = [u8; 4];

pub enum Provider {
    App(Arc<App>),
    Remote(String),
}
impl Provider {
    fn url(&self) -> String {
        match self {
            Self::App(app) => app.url(),
            Self::Remote(url) => url.trim_end_matches('/').into(),
        }
    }
    fn remote(&self, method: &str, path: &str) -> Result<Value, String> {
        let body = if method == "POST" { &b"{}"[..] } else { &[] };
        let (code, data) = localhttp::request(
            &self.url(),
            method,
            path,
            body,
            false,
            Duration::from_secs(2),
        )
        .map_err(|e| e.to_string())?;
        if !(200..300).contains(&code) {
            return Err(format!("tray status: {code}"));
        }
        serde_json::from_slice(&data).map_err(|e| e.to_string())
    }
    fn status(&self) -> Value {
        match self {
            Self::App(app) => app.service_status(),
            Self::Remote(_) => self
                .remote("GET", "/api/control/service/status")
                .unwrap_or(Value::Null),
        }
    }
    fn enable(&self, enabled: bool) -> Result<Value, String> {
        match self {
            Self::App(app) => app.webui(enabled),
            Self::Remote(_) => self.remote(
                "POST",
                if enabled {
                    "/api/control/webui/enable"
                } else {
                    "/api/control/webui/disable"
                },
            ),
        }
    }
    fn pause(&self, pause: bool) -> Result<Value, String> {
        match self {
            Self::App(app) => app.pause(pause),
            Self::Remote(_) => self.remote(
                "POST",
                if pause {
                    "/api/control/service/pause"
                } else {
                    "/api/control/service/resume"
                },
            ),
        }
    }
    fn traffic(&self) -> Result<Value, String> {
        match self {
            Self::App(app) => Ok(app.monitor.tray(12)),
            Self::Remote(_) => self.remote("GET", "/api/tray"),
        }
    }
}

struct Icon {
    handle: HICON,
    tooltip: String,
    signature: Signature,
}
#[derive(PartialEq, Eq)]
enum Signature {
    Offline,
    Paused,
    Traffic([(u64, u64); 12]),
}
struct Tray {
    provider: Provider,
    hwnd: Cell<HWND>,
    icon: RefCell<Option<Icon>>,
    taskbar: u32,
    refresh: Cell<bool>,
    busy: Cell<bool>,
    offline_since: Cell<Option<Instant>>,
    exit_deadline: Cell<Option<Instant>>,
}

pub fn run(provider: Provider) -> Result<(), String> {
    let name = platform::wide(r"Local\pitchProxTrayHelper");
    let mutex = unsafe { CreateMutexW(null(), 0, name.as_ptr()) };
    let already = unsafe { GetLastError() } == ERROR_ALREADY_EXISTS;
    let _mutex = platform::Handle::new(mutex).map_err(|e| e.to_string())?;
    if already {
        return Ok(());
    }
    let class = platform::wide("pitchProxTrayHelperWindow");
    let notification = platform::wide("TaskbarCreated");
    let instance = unsafe { GetModuleHandleW(null()) };
    let wc = WNDCLASSEXW {
        cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
        lpfnWndProc: Some(window_proc),
        hInstance: instance,
        lpszClassName: class.as_ptr(),
        ..WNDCLASSEXW::default()
    };
    unsafe {
        RegisterClassExW(&wc);
    }
    let mut tray = Box::new(Tray {
        provider,
        hwnd: Cell::new(null_mut()),
        icon: RefCell::new(None),
        taskbar: unsafe { RegisterWindowMessageW(notification.as_ptr()) },
        refresh: Cell::new(false),
        busy: Cell::new(false),
        offline_since: Cell::new(None),
        exit_deadline: Cell::new(None),
    });
    let window = unsafe {
        CreateWindowExW(
            0,
            class.as_ptr(),
            class.as_ptr(),
            0,
            0,
            0,
            0,
            0,
            null_mut(),
            null_mut(),
            instance,
            (&mut *tray as *mut Tray).cast(),
        )
    };
    if window.is_null() {
        return Err(io::Error::last_os_error().to_string());
    }
    unsafe {
        if tray.taskbar != 0 {
            ChangeWindowMessageFilterEx(window, tray.taskbar, MSGFLT_ALLOW, null_mut());
        }
        SetTimer(window, 1, 2000, None);
    }
    tray.update(Signature::Offline);
    let mut message = MSG::default();
    let outcome = loop {
        match unsafe { GetMessageW(&mut message, null_mut(), 0, 0) } {
            -1 => break Err(io::Error::last_os_error().to_string()),
            0 => break Ok(()),
            _ => unsafe {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            },
        }
    };
    if !tray.hwnd.get().is_null() {
        unsafe {
            DestroyWindow(tray.hwnd.get());
        }
    }
    outcome
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    event: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    unsafe {
        if event == WM_NCCREATE {
            let create = &*(lparam as *const CREATESTRUCTW);
            let pointer = create.lpCreateParams.cast::<Tray>();
            (*pointer).hwnd.set(hwnd);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, pointer as isize);
        }
        let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *const Tray;
        let Some(tray) = ptr.as_ref() else {
            return DefWindowProcW(hwnd, event, wparam, lparam);
        };
        if tray.taskbar != 0 && event == tray.taskbar {
            tray.refresh.set(true);
            return 0;
        }
        match event {
            TRAY_EVENT => {
                match (lparam as u32) & 0xffff {
                    WM_LBUTTONDBLCLK | NIN_KEYSELECT => tray.open(true),
                    WM_RBUTTONUP | WM_CONTEXTMENU => tray.menu(),
                    _ => {}
                }
                0
            }
            WM_COMMAND => {
                tray.command(wparam & 0xffff);
                0
            }
            WM_TIMER => {
                tray.tick();
                0
            }
            WM_CLOSE => {
                DestroyWindow(hwnd);
                0
            }
            WM_DESTROY => {
                KillTimer(hwnd, 1);
                tray.cleanup();
                tray.hwnd.set(null_mut());
                PostQuitMessage(0);
                0
            }
            WM_NCDESTROY => {
                SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                DefWindowProcW(hwnd, event, wparam, lparam)
            }
            _ => DefWindowProcW(hwnd, event, wparam, lparam),
        }
    }
}

impl Tray {
    fn open(&self, monitor: bool) {
        if self.provider.status()["paused"] == true && self.provider.pause(false).is_err() {
            return;
        }
        if self.provider.enable(true).is_err() {
            return;
        }
        let mut url = self.provider.url();
        if monitor {
            url.push_str("/#/monitor?filter=all");
        }
        let _ = platform::open_browser(&url);
    }
    fn command(&self, id: usize) {
        match id {
            MANAGE | RESUME => self.open(false),
            PAUSE => {
                let _ = self.provider.pause(true);
                self.tick();
            }
            ENABLE_UI => {
                let _ = self.provider.enable(true);
            }
            DISABLE_UI => {
                let _ = self.provider.enable(false);
            }
            EXIT => match &self.provider {
                Provider::App(app) => {
                    app.stop.signal();
                    self.close();
                }
                Provider::Remote(_) => {
                    if self.provider.remote("POST", "/api/control/stop").is_ok() {
                        self.exit_deadline
                            .set(Some(Instant::now() + Duration::from_secs(8)));
                        self.tick();
                    }
                }
            },
            _ => {}
        }
    }
    fn menu(&self) {
        if self.busy.replace(true) {
            return;
        }
        let hwnd = self.hwnd.get();
        unsafe {
            let menu = CreatePopupMenu();
            if !menu.is_null() {
                let status = self.provider.status();
                let items = if status["paused"] == true {
                    vec![(RESUME, "Запустить"), (EXIT, "Выйти")]
                } else {
                    let ui = if status["webui_enabled"] == true {
                        (DISABLE_UI, "Отключить WebUI")
                    } else {
                        (ENABLE_UI, "Включить WebUI")
                    };
                    vec![
                        (MANAGE, "Управление"),
                        (PAUSE, "Приостановить работу"),
                        ui,
                        (EXIT, "Выйти"),
                    ]
                };
                for (id, label) in items {
                    let text = platform::wide(label);
                    AppendMenuW(menu, MF_STRING, id, text.as_ptr());
                }
                let (point, align) = menu_position();
                SetWindowPos(
                    hwnd,
                    HWND_TOPMOST,
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
                );
                SetForegroundWindow(hwnd);
                let choice = TrackPopupMenu(
                    menu,
                    align | TPM_RIGHTBUTTON | TPM_RETURNCMD | TPM_NONOTIFY,
                    point.x,
                    point.y,
                    0,
                    hwnd,
                    null(),
                );
                PostMessageW(hwnd, WM_NULL, 0, 0);
                SetWindowPos(
                    hwnd,
                    HWND_NOTOPMOST,
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
                );
                DestroyMenu(menu);
                self.command(choice as usize);
                if let Some(icon) = self.icon.borrow().as_ref() {
                    Shell_NotifyIconW(NIM_SETFOCUS, &self.notification(icon.handle, ""));
                }
            }
        }
        self.busy.set(false);
    }
    fn close(&self) {
        unsafe {
            PostMessageW(self.hwnd.get(), WM_CLOSE, 0, 0);
        }
    }
    fn tick(&self) {
        if self.busy.get() {
            return;
        }
        if let Provider::App(app) = &self.provider {
            if app.stop.stopped() {
                self.close();
                return;
            }
        }
        if self.provider.status()["paused"] == true {
            self.offline_since.set(None);
            self.update(Signature::Paused);
            return;
        }
        match self.provider.traffic() {
            Ok(value) => {
                self.offline_since.set(None);
                if self
                    .exit_deadline
                    .get()
                    .is_some_and(|t| Instant::now() >= t)
                {
                    self.close();
                    return;
                }
                self.update(Signature::Traffic(traffic(value)));
            }
            Err(_) => {
                self.update(Signature::Offline);
                if matches!(&self.provider, Provider::Remote(_)) {
                    if self.exit_deadline.get().is_some()
                        || self
                            .offline_since
                            .get()
                            .is_some_and(|t| t.elapsed() >= Duration::from_secs(15))
                    {
                        self.close();
                    } else if self.offline_since.get().is_none() {
                        self.offline_since.set(Some(Instant::now()));
                    }
                }
            }
        }
    }
    fn update(&self, signature: Signature) {
        let mut current = self.icon.borrow_mut();
        if let Some(icon) = current.as_ref().filter(|icon| icon.signature == signature) {
            if self.refresh.replace(false) && !self.publish(icon.handle, &icon.tooltip, true) {
                self.refresh.set(true);
            }
            return;
        }
        let (frame, tooltip) = render(&signature);
        let dib = dib(frame);
        let handle = unsafe {
            CreateIconFromResourceEx(dib.as_ptr(), dib.len() as u32, 1, 0x00030000, 16, 16, 0)
        };
        if handle.is_null() {
            return;
        }
        if self.publish(
            handle,
            &tooltip,
            self.refresh.replace(false) || current.is_none(),
        ) {
            if let Some(previous) = current.replace(Icon {
                handle,
                tooltip,
                signature,
            }) {
                unsafe {
                    DestroyIcon(previous.handle);
                }
            }
        } else {
            unsafe {
                DestroyIcon(handle);
            }
            self.refresh.set(true);
        }
    }
    fn publish(&self, handle: HICON, tooltip: &str, add_first: bool) -> bool {
        let mut note = self.notification(handle, tooltip);
        unsafe {
            if !add_first && Shell_NotifyIconW(NIM_MODIFY, &note) != 0 {
                return true;
            }
            if Shell_NotifyIconW(NIM_ADD, &note) != 0 {
                note.Anonymous.uVersion = NOTIFYICON_VERSION_4;
                Shell_NotifyIconW(NIM_SETVERSION, &note);
                true
            } else {
                add_first && Shell_NotifyIconW(NIM_MODIFY, &note) != 0
            }
        }
    }
    fn notification(&self, icon: HICON, tooltip: &str) -> NOTIFYICONDATAW {
        let mut note = NOTIFYICONDATAW {
            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: self.hwnd.get(),
            uID: 1,
            uFlags: NIF_MESSAGE | NIF_TIP | NIF_ICON,
            uCallbackMessage: TRAY_EVENT,
            hIcon: icon,
            ..NOTIFYICONDATAW::default()
        };
        for (slot, unit) in note.szTip[..127].iter_mut().zip(tooltip.encode_utf16()) {
            *slot = unit;
        }
        note
    }
    fn cleanup(&self) {
        if let Some(icon) = self.icon.borrow_mut().take() {
            unsafe {
                Shell_NotifyIconW(NIM_DELETE, &self.notification(icon.handle, ""));
                DestroyIcon(icon.handle);
            }
        }
    }
}

unsafe fn menu_position() -> (POINT, u32) {
    let mut point = POINT::default();
    unsafe {
        GetCursorPos(&mut point);
    }
    let monitor = unsafe { MonitorFromPoint(point, MONITOR_DEFAULTTONEAREST) };
    let mut info = MONITORINFO {
        cbSize: std::mem::size_of::<MONITORINFO>() as u32,
        ..MONITORINFO::default()
    };
    let mut flags = TPM_LEFTALIGN | TPM_TOPALIGN;
    if !monitor.is_null() && unsafe { GetMonitorInfoW(monitor, &mut info) } != 0 {
        if point.x >= info.rcWork.right - 6 {
            point.x = info.rcWork.right - 2;
            flags |= TPM_RIGHTALIGN;
        } else if point.x <= info.rcWork.left + 6 {
            point.x = info.rcWork.left + 2;
        }
        if point.y >= info.rcWork.bottom - 6 {
            point.y = info.rcWork.bottom - 2;
            flags |= TPM_BOTTOMALIGN;
        } else if point.y <= info.rcWork.top + 6 {
            point.y = info.rcWork.top + 2;
        }
    }
    (point, flags)
}
fn traffic(value: Value) -> [(u64, u64); 12] {
    let mut out = [(0, 0); 12];
    let start = Utc::now().timestamp() - 11;
    if let Some(samples) = value["traffic"].as_array() {
        for sample in samples {
            if let Some(stamp) = sample["time"]
                .as_str()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            {
                let ix = stamp.timestamp() - start;
                if (0..12).contains(&ix) {
                    out[ix as usize].0 += sample["down_bytes"].as_u64().unwrap_or_default();
                    out[ix as usize].1 += sample["up_bytes"].as_u64().unwrap_or_default();
                }
            }
        }
    }
    out
}
fn render(signature: &Signature) -> (Frame, String) {
    let mut img = [[0; 4]; 256];
    match signature {
        Signature::Offline => {
            let gray = [107, 114, 128, 255];
            for x in 2..14 {
                point(&mut img, x, 13, gray);
            }
            for y in 3..13 {
                point(&mut img, 2, y, gray);
            }
            for i in 0..10 {
                point(&mut img, 3 + i, 12 - i, gray);
            }
            (img, "pitchProx: сервис недоступен".into())
        }
        Signature::Paused => {
            let muted = [156, 163, 175, 255];
            for y in 0..16 {
                for x in 0..16 {
                    point(
                        &mut img,
                        x,
                        y,
                        if matches!(x, 0 | 15) || matches!(y, 0 | 15) {
                            [248, 113, 113, 255]
                        } else {
                            [17, 24, 39, 255]
                        },
                    );
                }
            }
            for x in 5..=10 {
                point(&mut img, x, 4, muted);
                point(&mut img, x, 11, muted);
            }
            for y in 5..=10 {
                point(&mut img, 5, y, muted);
                point(&mut img, 10, y, muted);
            }
            for i in 2..=13 {
                point(&mut img, i, i, [220, 38, 38, 255]);
                point(&mut img, i + 1, i, [220, 38, 38, 255]);
            }
            (img, "pitchProx: сервис приостановлен".into())
        }
        Signature::Traffic(history) => {
            let axis = [226, 232, 240, 255];
            for y in 0..16 {
                for x in 0..16 {
                    let px = if matches!(x, 0 | 15) || matches!(y, 0 | 15) {
                        [248, 250, 252, 240]
                    } else if x == 1 || y == 14 {
                        [2, 6, 23, 255]
                    } else {
                        [15, 23, 42, 245]
                    };
                    point(&mut img, x, y, px);
                }
            }
            for x in 1..15 {
                point(&mut img, x, 14, axis);
            }
            for y in 1..15 {
                point(&mut img, 1, y, axis);
            }
            let rx = history.map(|p| p.0);
            let tx = history.map(|p| p.1);
            let peak_rx = rx.into_iter().max().unwrap_or_default();
            let peak_tx = tx.into_iter().max().unwrap_or_default();
            let receive = (rx, [20, 83, 45, 255], [74, 222, 128, 255]);
            let transmit = (tx, [30, 64, 175, 255], [147, 197, 253, 255]);
            for (values, fill, color) in if (rx[11], peak_rx) >= (tx[11], peak_tx) {
                [receive, transmit]
            } else {
                [transmit, receive]
            } {
                series(&mut img, values, fill, color);
            }
            let tooltip = format!(
                "pitchProx · ↓ {}/s (peak {}/s) · ↑ {}/s (peak {}/s)",
                bytes(rx[11]),
                bytes(peak_rx),
                bytes(tx[11]),
                bytes(peak_tx)
            );
            (img, tooltip)
        }
    }
}
fn point(frame: &mut Frame, x: i32, y: i32, color: Pixel) {
    frame[(y * 16 + x) as usize] = color;
}
fn series(frame: &mut Frame, series: [u64; 12], fill: Pixel, color: Pixel) {
    let scale = series.into_iter().max().unwrap_or_default().max(5 * 1024) as f64;
    let mut prev = None;
    for (i, value) in series.into_iter().enumerate() {
        let x = i as i32 + 2;
        let y = (13 - (value as f64 / scale * 10.0) as i32).clamp(2, 13);
        for row in y..=13 {
            point(frame, x, row, fill);
        }
        if let Some((px, py)) = prev {
            draw_line(frame, px, py, x, y, color);
        }
        point(frame, x, y, color);
        prev = Some((x, y));
    }
}
fn draw_line(frame: &mut Frame, mut x: i32, mut y: i32, end_x: i32, end_y: i32, color: Pixel) {
    let dx = (end_x - x).abs();
    let dy = -(end_y - y).abs();
    let sx = if x < end_x { 1 } else { -1 };
    let sy = if y < end_y { 1 } else { -1 };
    let mut err = dx + dy;
    loop {
        point(frame, x, y, color);
        if x == end_x && y == end_y {
            break;
        }
        let twice = 2 * err;
        if twice >= dy {
            err += dy;
            x += sx;
        }
        if twice <= dx {
            err += dx;
            y += sy;
        }
    }
}
fn dib(frame: Frame) -> Vec<u8> {
    let mut dib = Vec::with_capacity(1128);
    for value in [40u32, 16, 32, 0x00200001, 0, 1088, 0, 0, 0, 0] {
        dib.extend(value.to_le_bytes());
    }
    for row in frame.chunks_exact(16).rev() {
        for &[r, g, b, a] in row {
            dib.extend([b, g, r, a]);
        }
    }
    dib.resize(1128, 0);
    dib
}
fn bytes(value: u64) -> String {
    if value < 1024 {
        return format!("{value} B");
    }
    let mut value = value as f64;
    let mut unit = "";
    for suffix in ["KB", "MB", "GB"] {
        value /= 1024.0;
        unit = suffix;
        if value < 1024.0 {
            break;
        }
    }
    if value >= 100.0 {
        format!("{value:.0} {unit}")
    } else {
        format!("{value:.1} {unit}")
    }
}
