use std::io;
use std::net::SocketAddr;

#[derive(Clone, Copy, Debug)]
pub struct TcpOwner {
    pub pid: u32,
    pub local: SocketAddr,
    pub remote: SocketAddr,
    pub state: u32,
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::collections::HashSet;
    use std::ffi::OsStr;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        FreeMibTable, GetExtendedTcpTable, GetUnicastIpAddressTable, MIB_UNICASTIPADDRESS_ROW,
        TCP_TABLE_OWNER_PID_ALL,
    };
    use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, AF_UNSPEC};
    use windows_sys::Win32::Storage::FileSystem::GetFileType;
    use windows_sys::Win32::System::Console::{
        AttachConsole, GetConsoleProcessList, GetConsoleWindow, GetStdHandle, SetStdHandle,
        ATTACH_PARENT_PROCESS, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
    };
    use windows_sys::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
    use windows_sys::Win32::UI::WindowsAndMessaging::{ShowWindow, SW_HIDE, SW_SHOWNORMAL};

    pub fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
        s.as_ref().encode_wide().chain([0]).collect()
    }

    pub struct Handle(HANDLE);
    // Win32 kernel handles can be closed and used by a different thread.
    unsafe impl Send for Handle {}
    unsafe impl Sync for Handle {}

    impl Handle {
        pub fn new(raw: HANDLE) -> io::Result<Self> {
            if raw.is_null() || raw == INVALID_HANDLE_VALUE {
                Err(io::Error::last_os_error())
            } else {
                Ok(Self(raw))
            }
        }
        pub fn raw(&self) -> HANDLE {
            self.0
        }
        pub fn creation_time(&self) -> io::Result<u64> {
            creation_time(self.0)
        }
    }
    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    fn read_tcp_table(ipv6: bool) -> io::Result<Vec<TcpOwner>> {
        let af = if ipv6 { AF_INET6 } else { AF_INET };
        let mut size = 0;
        let mut buffer = Vec::<u32>::new();
        for _ in 0..4 {
            size = (buffer.len() * 4) as u32;
            let ptr = if size == 0 {
                null_mut()
            } else {
                buffer.as_mut_ptr().cast()
            };
            let status = unsafe {
                GetExtendedTcpTable(ptr, &mut size, 0, af as u32, TCP_TABLE_OWNER_PID_ALL, 0)
            };
            if status == 0 {
                break;
            }
            if status != ERROR_INSUFFICIENT_BUFFER {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            buffer.resize((size as usize).div_ceil(4), 0_u32);
        }
        if buffer.is_empty() || buffer.len() * 4 < size as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GetExtendedTcpTable table kept growing",
            ));
        }
        let data =
            unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), size as usize) };
        let n = data
            .get(..4)
            .and_then(|head| head.try_into().ok())
            .map(u32::from_le_bytes)
            .unwrap_or(0) as usize;
        let stride = if ipv6 { 56 } else { 24 };
        if data.len() < 4 + n * stride {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "truncated TCP owner table",
            ));
        }
        Ok(data[4..4 + n * stride]
            .chunks_exact(stride)
            .map(|row| {
                let port = |position| u16::from_be_bytes([row[position], row[position + 1]]);
                let int =
                    |position| u32::from_le_bytes(row[position..position + 4].try_into().unwrap());
                if ipv6 {
                    let ip = |position| {
                        IpAddr::from(<[u8; 16]>::try_from(&row[position..position + 16]).unwrap())
                            .to_canonical()
                    };
                    TcpOwner {
                        pid: int(52),
                        local: SocketAddr::new(ip(0), port(20)),
                        remote: SocketAddr::new(ip(24), port(44)),
                        state: int(48),
                    }
                } else {
                    let ip = |position| {
                        IpAddr::V4(Ipv4Addr::from(
                            <[u8; 4]>::try_from(&row[position..position + 4]).unwrap(),
                        ))
                    };
                    TcpOwner {
                        pid: int(20),
                        local: SocketAddr::new(ip(4), port(8)),
                        remote: SocketAddr::new(ip(12), port(16)),
                        state: int(0),
                    }
                }
            })
            .collect())
    }

    pub fn tcp_owners() -> Vec<TcpOwner> {
        let mut rows = read_tcp_table(false).unwrap_or_default();
        rows.extend(read_tcp_table(true).unwrap_or_default());
        rows
    }

    pub fn local_ips() -> io::Result<HashSet<IpAddr>> {
        let mut table = null_mut();
        let status = unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let mut result = HashSet::new();
        if !table.is_null() {
            // MIB_UNICASTIPADDRESS_TABLE contains NumEntries initialized rows.
            unsafe {
                let rows = std::slice::from_raw_parts(
                    std::ptr::addr_of!((*table).Table).cast::<MIB_UNICASTIPADDRESS_ROW>(),
                    (*table).NumEntries as usize,
                );
                for row in rows {
                    let ip = match row.Address.si_family {
                        AF_INET => {
                            IpAddr::from(row.Address.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes())
                        }
                        AF_INET6 => IpAddr::from(row.Address.Ipv6.sin6_addr.u.Byte).to_canonical(),
                        _ => continue,
                    };
                    result.insert(ip);
                }
                FreeMibTable(table.cast());
            }
        }
        result.insert(Ipv4Addr::LOCALHOST.into());
        result.insert(Ipv6Addr::LOCALHOST.into());
        Ok(result)
    }

    pub fn current_creation_time() -> io::Result<u64> {
        creation_time(unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() })
    }

    fn creation_time(handle: HANDLE) -> io::Result<u64> {
        let (mut creation, mut exit, mut kernel, mut user) = (
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
            FILETIME::default(),
        );
        if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
    }

    pub fn process_info(pid: u32, known_creation: u64) -> io::Result<(u64, Option<String>)> {
        let process =
            Handle::new(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })?;
        let creation = process.creation_time()?;
        if creation == known_creation {
            return Ok((creation, None));
        }
        let mut name = vec![0_u16; 32768];
        let mut size = name.len() as u32;
        if unsafe { QueryFullProcessImageNameW(process.raw(), 0, name.as_mut_ptr(), &mut size) }
            == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok((
            creation,
            Some(String::from_utf16_lossy(&name[..size as usize])),
        ))
    }

    pub fn elevated() -> bool {
        unsafe { IsUserAnAdmin() != 0 }
    }

    pub fn hide_own_console() {
        let mut processes = [0_u32; 2];
        unsafe {
            let window = GetConsoleWindow();
            if !window.is_null() && GetConsoleProcessList(processes.as_mut_ptr(), 2) == 1 {
                ShowWindow(window, SW_HIDE);
            }
        }
    }

    pub fn prepare_console() {
        let slots = [STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE];
        let preserved = slots.map(|slot| unsafe {
            let handle = GetStdHandle(slot);
            if handle.is_null() || handle == INVALID_HANDLE_VALUE || GetFileType(handle) == 0 {
                null_mut()
            } else {
                handle
            }
        });
        if preserved.iter().all(|p| !p.is_null()) {
            return;
        }
        unsafe {
            AttachConsole(ATTACH_PARENT_PROCESS);
            for (slot, handle) in slots.into_iter().zip(preserved) {
                if !handle.is_null() {
                    SetStdHandle(slot, handle);
                }
            }
        }
    }

    pub fn open_browser(url: &str) -> io::Result<()> {
        shell("open", OsStr::new(url), None, None)
    }

    pub fn relaunch_elevated(args: &[String]) -> io::Result<()> {
        let path = std::env::current_exe()?;
        let params = args
            .iter()
            .map(|arg| quote_arg(arg))
            .collect::<Vec<_>>()
            .join(" ");
        shell("runas", path.as_os_str(), Some(&params), path.parent())
    }

    fn shell(verb: &str, path: &OsStr, params: Option<&str>, dir: Option<&Path>) -> io::Result<()> {
        let verb = wide(verb);
        let path = wide(path);
        let params = params.map(wide);
        let dir = dir.map(|dir| wide(dir.as_os_str()));
        let value = unsafe {
            ShellExecuteW(
                null_mut(),
                verb.as_ptr(),
                path.as_ptr(),
                params.as_ref().map_or(null(), |p| p.as_ptr()),
                dir.as_ref().map_or(null(), |p| p.as_ptr()),
                SW_SHOWNORMAL,
            )
        } as usize;
        if value > 32 {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "ShellExecuteW failed with code {value}"
            )))
        }
    }

    pub fn quote_arg(arg: &str) -> String {
        if !arg.is_empty() && !arg.contains([' ', '\t', '"']) {
            return arg.to_owned();
        }
        let mut output = String::from("\"");
        let mut backslashes = 0;
        for ch in arg.chars() {
            if ch == '\\' {
                backslashes += 1;
                continue;
            }
            output.extend(std::iter::repeat_n(
                '\\',
                if ch == '"' {
                    2 * backslashes + 1
                } else {
                    backslashes
                },
            ));
            output.push(ch);
            backslashes = 0;
        }
        output.extend(std::iter::repeat_n('\\', backslashes * 2));
        output.push('"');
        output
    }
}

#[cfg(windows)]
pub use windows::*;

#[cfg(not(windows))]
pub fn tcp_owners() -> Vec<TcpOwner> {
    Vec::new()
}
#[cfg(not(windows))]
pub fn process_info(_: u32, _: u64) -> io::Result<(u64, Option<String>)> {
    Err(io::ErrorKind::Unsupported.into())
}
#[cfg(not(windows))]
pub fn hide_own_console() {}
#[cfg(not(windows))]
pub fn prepare_console() {}
#[cfg(not(windows))]
pub fn elevated() -> bool {
    true
}
#[cfg(not(windows))]
pub fn relaunch_elevated(_: &[String]) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}
#[cfg(not(windows))]
pub fn open_browser(_: &str) -> io::Result<()> {
    Err(io::ErrorKind::Unsupported.into())
}
