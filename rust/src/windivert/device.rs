//! The subset of the WinDivert 2.2 device ABI used by pitchProx.
//! Layout and command reference: https://github.com/basil00/WinDivert/blob/v2.2.2/include/windivert_device.h

use super::runtime;
use crate::platform::{self, Handle};
use crate::service::{self, ServiceHandle};
use std::cell::RefCell;
use std::ffi::c_void;
use std::io;
use std::mem::{size_of, size_of_val};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_IO_PENDING, ERROR_PATH_NOT_FOUND, ERROR_SERVICE_ALREADY_RUNNING,
    ERROR_SERVICE_DOES_NOT_EXIST, ERROR_SERVICE_EXISTS, GENERIC_READ, GENERIC_WRITE,
    WAIT_ABANDONED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
};
use windows_sys::Win32::System::Services::{
    CreateServiceW, DeleteService, OpenServiceW, StartServiceW, SC_MANAGER_CONNECT,
    SC_MANAGER_CREATE_SERVICE, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, SERVICE_KERNEL_DRIVER,
    SERVICE_START,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, CreateMutexW, ReleaseMutex, WaitForSingleObject,
};
use windows_sys::Win32::System::IO::{
    CancelIoEx, DeviceIoControl, GetOverlappedResult, OVERLAPPED,
};

const KERNEL_SERVICE: &str = "WinDivert";
const CLIENT_MAGIC: u64 = 0x4C4C_4476_6964_5724;
const DRIVER_MAGIC: u64 = 0x5359_5376_6964_5723;
const PRIORITY_BIAS: u64 = 30_000;

const ACCESS_READ: u32 = 1;
const ACCESS_READ_WRITE: u32 = 3;
const IN_DIRECT: u32 = 1;
const OUT_DIRECT: u32 = 2;

const fn network_ioctl(function: u32, method: u32, access: u32) -> u32 {
    (0x12 << 16) | (access << 14) | (function << 2) | method
}

const INITIALIZE: u32 = network_ioctl(0x921, OUT_DIRECT, ACCESS_READ_WRITE);
const START: u32 = network_ioctl(0x922, IN_DIRECT, ACCESS_READ_WRITE);
const RECEIVE: u32 = network_ioctl(0x923, OUT_DIRECT, ACCESS_READ);
const SEND: u32 = network_ioctl(0x924, IN_DIRECT, ACCESS_READ_WRITE);
const SHUTDOWN: u32 = network_ioctl(0x927, IN_DIRECT, ACCESS_READ_WRITE);
const SHUTDOWN_RECEIVE: u64 = 1;

thread_local! {
    static IO_EVENT: RefCell<Option<Handle>> = const { RefCell::new(None) };
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct Address {
    timestamp: i64,
    flags: u32,
    reserved: u32,
    data: [u8; 64],
}

impl Address {
    pub(super) const EMPTY: Self = Self {
        timestamp: 0,
        flags: 0,
        reserved: 0,
        data: [0; 64],
    };

    pub(super) fn mark_checksums(&mut self, ipv6: bool) {
        self.flags |= 1 << 22;
        if !ipv6 {
            self.flags |= 1 << 21;
        }
    }
}

#[repr(C)]
struct Version {
    magic: u64,
    major: u32,
    minor: u32,
    bits: u32,
    reserved: [u32; 11],
}

#[repr(C)]
struct Command {
    first: u64,
    second: u64,
}

#[repr(C)]
struct Predicate {
    // The low 11 bits select the field. The upper five bits are zero for equality.
    field: u16,
    yes: u16,
    no: u16,
    flags: u16,
    operand: [u32; 4],
}

const _: () = {
    assert!(size_of::<Address>() == 80 && std::mem::offset_of!(Address, data) == 16);
    assert!(size_of::<Version>() == 64);
    assert!(size_of::<Command>() == 16);
    assert!(size_of::<Predicate>() == 24);
};

const OUTBOUND: u16 = 2;
const TCP: u16 = 8;
const SOURCE_PORT: u16 = 38;
const DESTINATION_PORT: u16 = 39;
const ACK: u16 = 44;
const RST: u16 = 46;
const SYN: u16 = 47;
const LOOPBACK: u16 = 58;
const IMPOSTOR: u16 = 59;
const ACCEPT: u16 = 0x7ffe;
const REJECT: u16 = 0x7fff;
const OUTBOUND_IPV4_AND_IPV6: u64 = 0x20 | 0x40 | 0x80;

const fn equal(field: u16, value: u32, yes: u16, no: u16) -> Predicate {
    Predicate {
        field,
        yes,
        no,
        flags: 0,
        operand: [value, 0, 0, 0],
    }
}

const CLASSIFIER: [Predicate; 7] = [
    equal(OUTBOUND, 1, 1, REJECT),
    equal(TCP, 1, 2, REJECT),
    equal(LOOPBACK, 0, 3, REJECT),
    equal(IMPOSTOR, 0, 4, REJECT),
    equal(SYN, 1, 5, REJECT),
    equal(ACK, 0, 6, REJECT),
    equal(RST, 0, ACCEPT, REJECT),
];

fn redirector(port: u16) -> [Predicate; 6] {
    let port = u32::from(port);
    [
        equal(OUTBOUND, 1, 1, REJECT),
        equal(TCP, 1, 2, REJECT),
        equal(IMPOSTOR, 0, 3, REJECT),
        equal(LOOPBACK, 0, ACCEPT, 4),
        equal(SOURCE_PORT, port, ACCEPT, 5),
        equal(DESTINATION_PORT, port, ACCEPT, REJECT),
    ]
}

pub(super) struct Device {
    handle: Handle,
    stopped: AtomicBool,
}

impl Device {
    pub(super) fn classifier() -> io::Result<Arc<Self>> {
        let driver = runtime::driver_path()?;
        runtime::extract_if_missing(&driver)?;
        Self::open(&CLASSIFIER, 200, &driver)
    }

    pub(super) fn redirector(port: u16) -> io::Result<Arc<Self>> {
        Self::open(&redirector(port), 100, &runtime::driver_path()?)
    }

    fn open(filter: &[Predicate], priority: u16, driver: &Path) -> io::Result<Arc<Self>> {
        let handle = match open_device() {
            Ok(handle) => handle,
            Err(error) if device_missing(&error) => install_and_open(driver)?,
            Err(error) => return Err(error),
        };
        let device = Self {
            handle,
            stopped: AtomicBool::new(false),
        };
        let mut version = Version {
            magic: CLIENT_MAGIC,
            major: 2,
            minor: 2,
            bits: usize::BITS,
            reserved: [0; 11],
        };
        // The network layer is zero. Priority is a u32 at offset four.
        device.control(
            INITIALIZE,
            (u64::from(priority) + PRIORITY_BIAS) << 32,
            0,
            (&mut version as *mut Version).cast(),
            size_of::<Version>(),
        )?;
        if (version.magic, version.major, version.minor, version.bits) != (DRIVER_MAGIC, 2, 2, 64) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "the active WinDivert driver does not implement the 2.2 x64 interface",
            ));
        }
        // The driver's METHOD_IN_DIRECT command reads the filter buffer.
        device.control(
            START,
            OUTBOUND_IPV4_AND_IPV6,
            0,
            filter.as_ptr().cast_mut().cast(),
            size_of_val(filter),
        )?;
        Ok(Arc::new(device))
    }

    pub(super) fn stopped(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    pub(super) fn stop(&self) {
        if !self.stopped.swap(true, Ordering::AcqRel)
            && self
                .control(SHUTDOWN, SHUTDOWN_RECEIVE, 0, null_mut(), 0)
                .is_err()
        {
            // If the device is no longer responding to shutdown, wake pending I/O.
            unsafe { CancelIoEx(self.handle.raw(), null()) };
        }
    }

    pub(super) fn recv(&self, packet: &mut [u8], address: &mut Address) -> io::Result<usize> {
        if self.stopped() {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let received = self.control(
            RECEIVE,
            address as *mut Address as usize as u64,
            0,
            packet.as_mut_ptr().cast(),
            packet.len(),
        )?;
        if received > packet.len() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(received)
    }

    pub(super) fn send(&self, packet: &[u8], address: &Address) -> io::Result<()> {
        // SEND reads the packet and associated address metadata.
        let sent = self.control(
            SEND,
            address as *const Address as usize as u64,
            size_of::<Address>() as u64,
            packet.as_ptr().cast_mut().cast(),
            packet.len(),
        )?;
        if sent != packet.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(())
    }

    fn control(
        &self,
        code: u32,
        first: u64,
        second: u64,
        buffer: *mut c_void,
        length: usize,
    ) -> io::Result<usize> {
        let length = u32::try_from(length).map_err(|_| io::ErrorKind::InvalidInput)?;
        let command = Command { first, second };
        IO_EVENT.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_none() {
                *slot = Some(Handle::new(unsafe { CreateEventW(null(), 0, 0, null()) })?);
            }
            let mut operation = OVERLAPPED {
                hEvent: slot.as_ref().unwrap().raw(),
                ..Default::default()
            };
            let mut bytes = 0;
            let handle = self.handle.raw();
            // The command, data buffer and any packet metadata stay live until completion.
            if unsafe {
                DeviceIoControl(
                    handle,
                    code,
                    (&command as *const Command).cast(),
                    size_of::<Command>() as u32,
                    buffer,
                    length,
                    &mut bytes,
                    &mut operation,
                )
            } == 0
            {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                    return Err(error);
                }
                if code == RECEIVE && self.stopped() {
                    unsafe { CancelIoEx(handle, &operation) };
                }
                if unsafe { GetOverlappedResult(handle, &operation, &mut bytes, 1) } == 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(bytes as usize)
        })
    }
}

fn open_device() -> io::Result<Handle> {
    let path = platform::wide(r"\\.\WinDivert");
    Handle::new(unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            null_mut(),
        )
    })
}

fn device_missing(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error().map(|e| e as u32),
        Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND)
    )
}

struct InstallLock(Handle);

impl InstallLock {
    fn acquire() -> io::Result<Self> {
        // Share WinDivert's installation mutex with processes that still use its DLL.
        let name = platform::wide("WinDivertDriverInstallMutex");
        let mutex = Handle::new(unsafe { CreateMutexW(null(), 0, name.as_ptr()) })?;
        match unsafe { WaitForSingleObject(mutex.raw(), 15_000) } {
            WAIT_OBJECT_0 | WAIT_ABANDONED => Ok(Self(mutex)),
            WAIT_TIMEOUT => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "waiting for WinDivert driver installation",
            )),
            _ => Err(io::Error::last_os_error()),
        }
    }
}

impl Drop for InstallLock {
    fn drop(&mut self) {
        unsafe { ReleaseMutex(self.0.raw()) };
    }
}

fn install_and_open(path: &Path) -> io::Result<Handle> {
    let _lock = InstallLock::acquire()?;
    match open_device() {
        Ok(handle) => return Ok(handle),
        Err(error) if device_missing(&error) => (),
        Err(error) => return Err(error),
    }

    let _image = runtime::open_verified(path)?;

    let manager = service::manager(SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)?;
    let name = platform::wide(KERNEL_SERVICE);
    let path = platform::wide(path.as_os_str());
    let (driver, created) = open_or_create_service(manager.raw(), &name, &path)?;
    let started = unsafe { StartServiceW(driver.raw(), 0, null()) };
    let error = io::Error::last_os_error();
    // Keep the image locked through StartService. Remove only the entry we created.
    if created {
        unsafe { DeleteService(driver.raw()) };
    }
    if started == 0 && error.raw_os_error() != Some(ERROR_SERVICE_ALREADY_RUNNING as i32) {
        return Err(error);
    }
    open_device()
}

fn open_or_create_service(
    manager: windows_sys::Win32::System::Services::SC_HANDLE,
    name: &[u16],
    path: &[u16],
) -> io::Result<(ServiceHandle, bool)> {
    let existing =
        || ServiceHandle::new(unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_START) });
    match existing() {
        Ok(handle) => return Ok((handle, false)),
        Err(error) if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) => (),
        Err(error) => return Err(error),
    }
    let created = ServiceHandle::new(unsafe {
        CreateServiceW(
            manager,
            name.as_ptr(),
            name.as_ptr(),
            SERVICE_START | DELETE,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            path.as_ptr(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
        )
    });
    match created {
        Ok(handle) => Ok((handle, true)),
        Err(error) if error.raw_os_error() == Some(ERROR_SERVICE_EXISTS as i32) => {
            existing().map(|handle| (handle, false))
        }
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepts(filter: &[Predicate], properties: &[u32; 60]) -> bool {
        let mut decision = 0;
        while decision < ACCEPT {
            let test = &filter[usize::from(decision)];
            assert_eq!(test.flags, 0);
            let next = if properties[usize::from(test.field)] == test.operand[0] {
                test.yes
            } else {
                test.no
            };
            assert!(next > decision);
            decision = next;
        }
        decision == ACCEPT
    }

    #[test]
    fn filter_programs_preserve_the_classifier_and_redirector_match_conditions() {
        let port = 26001;
        let redirector = redirector(port);
        let fields = [OUTBOUND, TCP, LOOPBACK, IMPOSTOR, SYN, ACK, RST];
        let mut props = [0; 60];
        for bits in 0..1 << fields.len() {
            for (bit, field) in fields.into_iter().enumerate() {
                props[usize::from(field)] = (bits >> bit) & 1;
            }
            assert_eq!(accepts(&CLASSIFIER, &props), bits == 0b001_0011);
            let outbound_tcp = bits & 0b1011 == 0b0011;
            let loopback = bits & 0b0100 != 0;
            for (src, dst) in [(80, 81), (80, port), (port, 81), (port, port)] {
                props[usize::from(SOURCE_PORT)] = u32::from(src);
                props[usize::from(DESTINATION_PORT)] = u32::from(dst);
                assert_eq!(
                    accepts(&redirector, &props),
                    outbound_tcp && (!loopback || src == port || dst == port)
                );
            }
        }
    }
}
