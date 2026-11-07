//! HID packet transports.
//!
//! - [`UhidTransport`]: real hardware via /dev/uhid (Linux UHID, written
//!   directly against the kernel ABI — no uhid crate).
//! - [`MockTransport`]: in-memory queue, for tests and `selftest`.
//! - [`StdioTransport`]: raw 64-byte packets over stdin/stdout, for
//!   development without UHID (selected with `--transport stdio`).

use std::collections::VecDeque;
#[cfg(unix)]
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};

use crate::ctaphid::PACKET_SIZE;

pub trait Transport {
    /// Receive one 64-byte HID packet (blocking).
    fn recv_packet(&mut self) -> io::Result<[u8; PACKET_SIZE]>;
    /// Send one 64-byte HID packet.
    fn send_packet(&mut self, packet: &[u8; PACKET_SIZE]) -> io::Result<()>;
    /// Receive one packet, waiting at most `timeout`; Ok(None) when the
    /// wait expires with nothing received. The daemon's serve loop uses
    /// the timeout ticks for phone-session upkeep (see Phone::maintain),
    /// which is what makes the connection self-establishing. The default
    /// implementation just blocks; transports that can poll override it.
    fn recv_packet_timeout(
        &mut self,
        _timeout: std::time::Duration,
    ) -> io::Result<Option<[u8; PACKET_SIZE]>> {
        self.recv_packet().map(Some)
    }
}

// ------------------------------------------------------------- MockTransport

/// In-memory transport. Inbound packets are queued by the test/client
/// side; outbound packets accumulate in `sent`.
#[derive(Default)]
pub struct MockTransport {
    pub incoming: VecDeque<[u8; PACKET_SIZE]>,
    pub sent: Vec<[u8; PACKET_SIZE]>,
}

impl MockTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn queue_incoming(&mut self, packet: [u8; PACKET_SIZE]) {
        self.incoming.push_back(packet);
    }

    pub fn take_sent(&mut self) -> Vec<[u8; PACKET_SIZE]> {
        std::mem::take(&mut self.sent)
    }
}

impl Transport for MockTransport {
    fn recv_packet(&mut self) -> io::Result<[u8; PACKET_SIZE]> {
        self.incoming.pop_front().ok_or_else(|| {
            io::Error::new(io::ErrorKind::WouldBlock, "mock transport: no packet queued")
        })
    }

    fn send_packet(&mut self, packet: &[u8; PACKET_SIZE]) -> io::Result<()> {
        self.sent.push(*packet);
        Ok(())
    }
}

// ------------------------------------------------------------ StdioTransport

/// Development transport: binary 64-byte packets on stdin/stdout.
pub struct StdioTransport {
    stdin: io::Stdin,
    stdout: io::Stdout,
}

impl StdioTransport {
    pub fn new() -> Self {
        Self {
            stdin: io::stdin(),
            stdout: io::stdout(),
        }
    }
}

impl Default for StdioTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl Transport for StdioTransport {
    fn recv_packet(&mut self) -> io::Result<[u8; PACKET_SIZE]> {
        let mut buf = [0u8; PACKET_SIZE];
        self.stdin.lock().read_exact(&mut buf)?;
        Ok(buf)
    }

    fn send_packet(&mut self, packet: &[u8; PACKET_SIZE]) -> io::Result<()> {
        let mut lock = self.stdout.lock();
        lock.write_all(packet)?;
        lock.flush()
    }
}

/// FIDO HID report descriptor: usage page 0xF1D0, 64-byte in/out
/// reports (the standard 34-byte un-numbered descriptor). Shared by
/// the Linux UHID and macOS IOHIDUserDevice device definitions.
pub(crate) const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01, // Usage (U2F/Authenticator)
    0xA1, 0x01, // Collection (Application)
    0x09, 0x20, //   Usage (Input Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, // Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x81, 0x02, //   Input (Data, Var, Abs)
    0x09, 0x21, //   Usage (Output Report Data)
    0x15, 0x00, //   Logical Minimum (0)
    0x26, 0xFF, 0x00, // Logical Maximum (255)
    0x75, 0x08, //   Report Size (8)
    0x95, 0x40, //   Report Count (64)
    0x91, 0x02, //   Output (Data, Var, Abs)
    0xC0, // End Collection
];

// ------------------------------------------------------------- UhidTransport

// The UHID transport is Linux-only (kernel UHID ABI, poll(2)); the
// whole section is compiled out on other platforms so the library
// builds for the Windows plugin host, which needs neither UHID nor
// CTAPHID device plumbing (the broker talks CTAP2 CBOR directly).

// The UHID transport is Linux-only (kernel UHID ABI, poll(2));
// it is compiled out on other platforms so the library builds
// for the Windows plugin host, which needs neither UHID nor
// CTAPHID device plumbing (the broker talks CTAP2 CBOR directly).
#[cfg(unix)]
mod uhid_impl {
    use super::*;

// Linux UHID ABI (include/uapi/linux/uhid.h). Event integers are native
// (little-endian on all Fedora targets). The full uhid_event is
// 4 (type) + 4372 (largest union member, uhid_create2_req) = 4376 bytes.
const UHID_EVENT_SIZE: usize = 4376;
const UHID_CREATE2: u32 = 11;
const UHID_INPUT2: u32 = 12;
const UHID_OUTPUT: u32 = 6; // legacy UHID_OUTPUT: host -> device report
const UHID_GET_REPORT: u32 = 9;
const UHID_GET_REPORT_REPLY: u32 = 10;
const UHID_SET_REPORT: u32 = 13;
const UHID_SET_REPORT_REPLY: u32 = 14;

const BUS_USB: u16 = 0x03;

/// Real UHID transport. Opening fails with an explicit error when
/// /dev/uhid is unavailable (this development VM has none).
pub struct UhidTransport {
    file: File,
    verbose: bool,
}

impl UhidTransport {
    pub fn new() -> io::Result<Self> {
        Self::open_path("/dev/uhid")
    }

    pub fn open_path(path: &str) -> io::Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "cannot open UHID device {path}: {e}. \
                         UHID is required for the real transport; check that the \
                         kernel uhid module is loaded and you have permission \
                         (see packaging/99-iphone-fido-uhid.rules for a udev rule \
                         that grants the input group access without running as root)."
                    ),
                )
            })?;
        Self::send_create2(&mut file)?;
        Ok(Self {
            file,
            verbose: false,
        })
    }

    /// When enabled, every UHID kernel event type is logged to stderr.
    /// Host processes block on some of these (notably GET_REPORT), so
    /// seeing the exact event sequence matters when a browser stalls.
    pub fn set_verbose(&mut self, verbose: bool) {
        self.verbose = verbose;
    }

    fn send_create2(file: &mut File) -> io::Result<()> {
        let mut ev = vec![0u8; UHID_EVENT_SIZE];
        ev[0..4].copy_from_slice(&UHID_CREATE2.to_ne_bytes());
        // struct uhid_create2_req layout:
        //   name[128] @4, phys[64] @132, uniq[64] @196,
        //   rd_size u16 @260, bus u16 @262, vendor u32 @264,
        //   product u32 @268, version u32 @272, country u32 @276,
        //   rd_data[] @280
        let name = b"iphone-fido (iPhone FIDO2 authenticator)";
        ev[4..4 + name.len()].copy_from_slice(name);
        let phys = b"usb-iphone-fido";
        ev[132..132 + phys.len()].copy_from_slice(phys);
        let uniq = b"iphone-fido-0000001";
        ev[196..196 + uniq.len()].copy_from_slice(uniq);
        ev[260..262].copy_from_slice(&(FIDO_REPORT_DESCRIPTOR.len() as u16).to_ne_bytes());
        ev[262..264].copy_from_slice(&BUS_USB.to_ne_bytes());
        ev[264..268].copy_from_slice(&0x1209u32.to_ne_bytes()); // generic PID.codes VID
        ev[268..272].copy_from_slice(&0xF1D0u32.to_ne_bytes());
        ev[272..276].copy_from_slice(&1u32.to_ne_bytes()); // version
        // country @276 stays 0
        ev[280..280 + FIDO_REPORT_DESCRIPTOR.len()].copy_from_slice(FIDO_REPORT_DESCRIPTOR);
        file.write_all(&ev)
    }

    fn send_input2(&mut self, packet: &[u8; PACKET_SIZE]) -> io::Result<()> {
        let mut ev = vec![0u8; UHID_EVENT_SIZE];
        ev[0..4].copy_from_slice(&UHID_INPUT2.to_ne_bytes());
        // struct uhid_input2_req: size u16 @4, data[] @6
        ev[4..6].copy_from_slice(&(PACKET_SIZE as u16).to_ne_bytes());
        ev[6..6 + PACKET_SIZE].copy_from_slice(packet);
        self.file.write_all(&ev)
    }

    /// Write a GET_REPORT / SET_REPORT reply. The kernel forwards these
    /// requests from host processes (e.g. a browser's HID stack issuing
    /// ioctls while enumerating the device) and BLOCKS the requester
    /// until the daemon replies -- silently dropping them, as an earlier
    /// version of this code did, leaves the host process waiting and the
    /// device never gets probed. This authenticator's descriptor declares
    /// no feature reports, so an empty success reply is the honest answer.
    fn send_report_reply(&mut self, reply_ty: u32, id: u32) -> io::Result<()> {
        let mut ev = vec![0u8; UHID_EVENT_SIZE];
        ev[0..4].copy_from_slice(&reply_ty.to_ne_bytes());
        // reply payload @4: id u32, err u16 = 0 (success), then for
        // GET_REPORT_REPLY a size u16 = 0 (no data).
        ev[4..8].copy_from_slice(&id.to_ne_bytes());
        self.file.write_all(&ev)
    }

    /// Read events until a host->device OUTPUT report arrives.
    /// GET_REPORT and SET_REPORT are answered (see send_report_reply);
    /// START/STOP/OPEN/CLOSE need no reply.
    ///
    /// With a deadline, EVERY read is poll-gated against the remaining
    /// budget and Ok(None) is returned when it expires. Gating only the
    /// first read is a wedge: a stray OPEN event would let the loop
    /// consume it and then block forever on the next read, and the
    /// daemon's upkeep tick would never run again (observed 2026-11-06:
    /// the daemon sat in read() on /dev/uhid while the phone waited).
    fn read_output_packet_deadline(
        &mut self,
        deadline: Option<std::time::Instant>,
    ) -> io::Result<Option<[u8; PACKET_SIZE]>> {
        use std::os::unix::io::AsRawFd;
        let mut ev = vec![0u8; UHID_EVENT_SIZE];
        loop {
            if let Some(d) = deadline {
                let remaining = d.saturating_duration_since(std::time::Instant::now());
                if remaining.is_zero() {
                    return Ok(None);
                }
                let mut pfd = libc::pollfd {
                    fd: self.file.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ms = remaining.as_millis().min(i32::MAX as u128) as i32;
                let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
                if rc == 0 {
                    return Ok(None);
                }
                if rc < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            let n = self.file.read(&mut ev)?;
            if n < 4 {
                continue;
            }
            let ty = u32::from_ne_bytes(ev[0..4].try_into().unwrap());
            if self.verbose {
                let name = match ty {
                    2 => "START",
                    3 => "STOP",
                    4 => "OPEN",
                    5 => "CLOSE",
                    UHID_OUTPUT => "OUTPUT",
                    UHID_GET_REPORT => "GET_REPORT",
                    UHID_SET_REPORT => "SET_REPORT",
                    _ => "other",
                };
                eprintln!("uhid: event {name} (type {ty}, {n} bytes)");
            }
            if ty == UHID_GET_REPORT || ty == UHID_SET_REPORT {
                // request payload @4: id u32 first in both structs.
                let id = u32::from_ne_bytes(ev[4..8].try_into().unwrap());
                let reply_ty = if ty == UHID_GET_REPORT {
                    UHID_GET_REPORT_REPLY
                } else {
                    UHID_SET_REPORT_REPLY
                };
                self.send_report_reply(reply_ty, id)?;
                continue;
            }
            if ty == UHID_OUTPUT {
                // struct uhid_output_req: data[4096] @4, size u16 @4100,
                // type u8 @4102. Data begins with the report.
                let size = if n >= 4102 {
                    u16::from_ne_bytes(ev[4100..4102].try_into().unwrap()) as usize
                } else {
                    0
                };
                // Host stacks built on hidapi (Firefox's authenticator-rs,
                // Chromium's Linux HID service) write reports WITH a
                // leading report-ID byte -- 0x00 for devices like this one
                // whose descriptor declares no numbered reports -- which
                // makes the report 65 bytes and shifts the CTAPHID packet
                // by one. Raw 64-byte writes (no prefix) also occur.
                // Accept both shapes; without this, browsers' INIT packets
                // parse as garbage and the device looks dead to them
                // (observed on real hardware 2026-11-05).
                let mut start = 4usize;
                let mut avail = size.min(n.saturating_sub(4));
                if avail == PACKET_SIZE + 1 && ev[start] == 0 {
                    start += 1;
                    avail -= 1;
                }
                let take = avail.min(PACKET_SIZE);
                if self.verbose {
                    let head = &ev[start..start + take.min(16)];
                    eprintln!("uhid: OUTPUT report size field {size}, take {take}, head {head:02x?}");
                }
                if take == 0 {
                    continue;
                }
                let mut packet = [0u8; PACKET_SIZE];
                packet[..take].copy_from_slice(&ev[start..start + take]);
                return Ok(Some(packet));
            }
            // Remaining events (START/STOP/OPEN/CLOSE, ...) need no reply.
        }
    }
}

impl Transport for UhidTransport {
    fn recv_packet(&mut self) -> io::Result<[u8; PACKET_SIZE]> {
        // No deadline: the deadline loop only returns None on timeout,
        // so this always yields a packet (or an I/O error).
        match self.read_output_packet_deadline(None)? {
            Some(packet) => Ok(packet),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "uhid: deadline loop returned no packet without a deadline",
            )),
        }
    }

    fn recv_packet_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> io::Result<Option<[u8; PACKET_SIZE]>> {
        let deadline = std::time::Instant::now() + timeout;
        self.read_output_packet_deadline(Some(deadline))
    }

    fn send_packet(&mut self, packet: &[u8; PACKET_SIZE]) -> io::Result<()> {
        self.send_input2(packet)
    }
}

}

#[cfg(unix)]
pub use uhid_impl::UhidTransport;

// ------------------------------------------------------------ MacHidTransport

/// macOS transport: a virtual FIDO HID device created with IOKit's
/// IOHIDUserDevice, so IOHIDManager clients (Chrome, libfido2 via
/// hidapi) enumerate it exactly like a USB security key. Compiled
/// only on macOS; see docs/MACOS.md for the entitlement / packaging
/// constraints and the (hardware-pending) verification status.
#[cfg(target_os = "macos")]
pub use mac_hid::MacHidTransport;

#[cfg(target_os = "macos")]
mod mac_hid {
    use super::*;
    use std::collections::VecDeque;
    use std::ffi::{c_void, CString};
    use std::sync::{Arc, Condvar, Mutex};

    // ---- CoreFoundation / IOKit FFI (hand-declared; no crates) ----
    // All CF types are opaque pointers here. Ownership follows the
    // Create Rule: values returned by *Create* functions are +1 and
    // released with CFRelease.

    type CfAllocatorRef = *const c_void;
    type CfTypeRef = *const c_void;
    type CfMutableDictionaryRef = *mut c_void;
    type CfStringRef = *const c_void;
    type CfRunLoopRef = *mut c_void;
    type IoReturn = i32;

    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    const K_CF_NUMBER_SINT32_TYPE: isize = 3;

    extern "C" {
        static kCFAllocatorDefault: CfAllocatorRef;
        static kCFTypeDictionaryKeyCallBacks: c_void;
        static kCFTypeDictionaryValueCallBacks: c_void;
        static kCFRunLoopDefaultMode: CfStringRef;

        // IOHID property keys (CFStringRef globals from IOKit).
        static kIOHIDReportDescriptorKey: CfStringRef;
        static kIOHIDVendorIDKey: CfStringRef;
        static kIOHIDProductIDKey: CfStringRef;
        static kIOHIDVersionNumberKey: CfStringRef;
        static kIOHIDManufacturerKey: CfStringRef;
        static kIOHIDProductKey: CfStringRef;
        static kIOHIDSerialNumberKey: CfStringRef;
        static kIOHIDTransportKey: CfStringRef;
        static kIOHIDPrimaryUsagePageKey: CfStringRef;
        static kIOHIDPrimaryUsageKey: CfStringRef;

        fn CFDictionaryCreateMutable(
            allocator: CfAllocatorRef,
            capacity: isize,
            key_callbacks: *const c_void,
            value_callbacks: *const c_void,
        ) -> CfMutableDictionaryRef;
        fn CFDictionarySetValue(dict: CfMutableDictionaryRef, key: CfTypeRef, value: CfTypeRef);
        fn CFStringCreateWithCString(
            allocator: CfAllocatorRef,
            cstr: *const std::ffi::c_char,
            encoding: u32,
        ) -> CfStringRef;
        fn CFNumberCreate(
            allocator: CfAllocatorRef,
            the_type: isize,
            value_ptr: *const c_void,
        ) -> CfTypeRef;
        fn CFDataCreate(
            allocator: CfAllocatorRef,
            bytes: *const u8,
            length: isize,
        ) -> CfTypeRef;
        fn CFRelease(cf: CfTypeRef);
        fn CFRunLoopGetCurrent() -> CfRunLoopRef;
        fn CFRunLoopRun();
        fn CFRunLoopStop(runloop: CfRunLoopRef);

        fn IOHIDUserDeviceCreate(
            allocator: CfAllocatorRef,
            properties: CfTypeRef,
        ) -> *mut c_void;
        fn IOHIDUserDeviceRegisterSetReportCallback(
            device: *mut c_void,
            callback: SetReportCallback,
            context: *mut c_void,
        );
        fn IOHIDUserDeviceRegisterGetReportCallback(
            device: *mut c_void,
            callback: GetReportCallback,
            context: *mut c_void,
        );
        fn IOHIDUserDeviceScheduleWithRunLoop(
            device: *mut c_void,
            runloop: CfRunLoopRef,
            mode: CfStringRef,
        );
        fn IOHIDUserDeviceUnscheduleFromRunLoop(
            device: *mut c_void,
            runloop: CfRunLoopRef,
            mode: CfStringRef,
        );
        fn IOHIDUserDeviceHandleReport(device: *mut c_void, report: CfTypeRef) -> IoReturn;
    }

    type SetReportCallback = extern "C" fn(
        context: *mut c_void,
        result: IoReturn,
        sender: *mut c_void,
        report_type: u32,
        report_id: u32,
        report: *const u8,
        report_length: isize,
    );

    type GetReportCallback = extern "C" fn(
        context: *mut c_void,
        sender: *mut c_void,
        report_type: u32,
        report_id: u32,
        report: *mut u8,
        report_length: *mut isize,
    ) -> IoReturn;

    /// Inbound packet queue shared between the IOKit runloop thread
    /// (producer, via the set-report callback) and the daemon thread
    /// (consumer, via Transport::recv_packet).
    type PacketQueue = Arc<(Mutex<VecDeque<[u8; PACKET_SIZE]>>, Condvar)>;

    extern "C" fn on_set_report(
        context: *mut c_void,
        _result: IoReturn,
        _sender: *mut c_void,
        _report_type: u32,
        _report_id: u32,
        report: *const u8,
        report_length: isize,
    ) {
        if context.is_null() || report.is_null() || report_length <= 0 {
            return;
        }
        let queue = unsafe { &*(context as *const (Mutex<VecDeque<[u8; PACKET_SIZE]>>, Condvar)) };
        let mut packet = [0u8; PACKET_SIZE];
        let n = (report_length as usize).min(PACKET_SIZE);
        unsafe {
            std::ptr::copy_nonoverlapping(report, packet.as_mut_ptr(), n);
        }
        let (lock, cvar) = &*queue;
        if let Ok(mut q) = lock.lock() {
            // Depth cap mirrors a host that stopped reading: drop the
            // oldest rather than growing without bound.
            if q.len() >= 64 {
                q.pop_front();
            }
            q.push_back(packet);
            cvar.notify_one();
        }
    }

    extern "C" fn on_get_report(
        _context: *mut c_void,
        _sender: *mut c_void,
        _report_type: u32,
        _report_id: u32,
        report: *mut u8,
        report_length: *mut isize,
    ) -> IoReturn {
        // Same as the UHID GET_REPORT reply: 64 zero bytes.
        if !report.is_null() && !report_length.is_null() {
            unsafe {
                std::ptr::write_bytes(report, 0, PACKET_SIZE);
                *report_length = PACKET_SIZE as isize;
            }
        }
        0 // kIOReturnSuccess
    }

    /// Create a CF string, run `f` with it, then release it.
    unsafe fn with_cf_string<R>(s: &str, f: impl FnOnce(CfStringRef) -> R) -> R {
        let cstr = CString::new(s).expect("no interior NUL");
        let cf = CFStringCreateWithCString(
            kCFAllocatorDefault,
            cstr.as_ptr(),
            K_CF_STRING_ENCODING_UTF8,
        );
        let r = f(cf);
        CFRelease(cf);
        r
    }

    unsafe fn dict_set_number(dict: CfMutableDictionaryRef, key: CfStringRef, value: i32) {
        let num = CFNumberCreate(
            kCFAllocatorDefault,
            K_CF_NUMBER_SINT32_TYPE,
            &value as *const i32 as *const c_void,
        );
        CFDictionarySetValue(dict, key, num);
        CFRelease(num);
    }

    unsafe fn dict_set_string(dict: CfMutableDictionaryRef, key: CfStringRef, value: &str) {
        with_cf_string(value, |cf| {
            CFDictionarySetValue(dict, key, cf);
        });
    }

    /// Virtual FIDO HID device on macOS (IOHIDUserDevice).
    pub struct MacHidTransport {
        device: *mut c_void,
        queue: PacketQueue,
        runloop: CfRunLoopRef,
        verbose: bool,
    }

    // The device handle is only used from the daemon thread after
    // creation (HandleReport is thread-safe); inbound reports reach
    // us exclusively through the Arc queue. The runloop thread owns
    // the scheduled callbacks.
    unsafe impl Send for MacHidTransport {}

    impl MacHidTransport {
        pub fn new() -> io::Result<Self> {
            let queue: PacketQueue = Arc::new((Mutex::new(VecDeque::new()), Condvar::new()));
            let device = unsafe { Self::create_device()? };
            // Hand the queue to the C callbacks (daemon-lifetime leak,
            // like the pairing state: the process serves until killed).
            let context = Arc::into_raw(queue.clone()) as *mut c_void;
            unsafe {
                IOHIDUserDeviceRegisterSetReportCallback(device, on_set_report, context);
                IOHIDUserDeviceRegisterGetReportCallback(device, on_get_report, context);
            }
            // A dedicated thread runs the runloop the device is
            // scheduled on; callbacks must never run on the daemon
            // thread (which blocks in recv and calls HandleReport).
            // The runloop handle crosses threads as a usize: raw CF
            // pointers are not Send, and this one is only ever used
            // to unschedule/stop the loop the owning thread created.
            let (tx, rx) = std::sync::mpsc::channel::<usize>();
            let device_addr = device as usize;
            std::thread::Builder::new()
                .name("machid-runloop".into())
                .spawn(move || {
                    let runloop = unsafe { CFRunLoopGetCurrent() };
                    unsafe {
                        IOHIDUserDeviceScheduleWithRunLoop(
                            device_addr as *mut c_void,
                            runloop,
                            kCFRunLoopDefaultMode,
                        );
                    }
                    let _ = tx.send(runloop as usize);
                    unsafe { CFRunLoopRun() };
                })
                .map_err(|e| io::Error::new(e.kind(), format!("spawn runloop thread: {e}")))?;
            let runloop = rx
                .recv()
                .map(|addr| addr as CfRunLoopRef)
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::Other, "runloop thread died during setup")
                })?;
            Ok(Self {
                device,
                queue,
                runloop,
                verbose: false,
            })
        }

        unsafe fn create_device() -> io::Result<*mut c_void> {
            let props = CFDictionaryCreateMutable(
                kCFAllocatorDefault,
                0,
                &kCFTypeDictionaryKeyCallBacks as *const c_void,
                &kCFTypeDictionaryValueCallBacks as *const c_void,
            );
            if props.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    "CFDictionaryCreateMutable failed",
                ));
            }
            // Report descriptor (+1 from CFDataCreate; the dictionary
            // retains its own reference via the value callbacks).
            let desc = CFDataCreate(
                kCFAllocatorDefault,
                FIDO_REPORT_DESCRIPTOR.as_ptr(),
                FIDO_REPORT_DESCRIPTOR.len() as isize,
            );
            CFDictionarySetValue(props, kIOHIDReportDescriptorKey, desc);
            CFRelease(desc);
            dict_set_number(props, kIOHIDVendorIDKey, 0x1209);
            dict_set_number(props, kIOHIDProductIDKey, 0xF1D0);
            dict_set_number(props, kIOHIDVersionNumberKey, 0x0001);
            dict_set_number(props, kIOHIDPrimaryUsagePageKey, 0xF1D0);
            dict_set_number(props, kIOHIDPrimaryUsageKey, 0x01);
            dict_set_string(props, kIOHIDManufacturerKey, "Phone as a security key");
            dict_set_string(
                props,
                kIOHIDProductKey,
                "iphone-fido (Phone FIDO2 authenticator)",
            );
            dict_set_string(props, kIOHIDSerialNumberKey, "phone-fido-1");
            dict_set_string(props, kIOHIDTransportKey, "USB");
            let device = IOHIDUserDeviceCreate(kCFAllocatorDefault, props);
            CFRelease(props);
            if device.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "IOHIDUserDeviceCreate failed (returned NULL). On modern macOS, \
                     creating a virtual HID device requires either root (run the \
                     daemon via the launchd daemon plist, see docs/MACOS.md) or the \
                     restricted entitlement com.apple.developer.hid.virtual.device \
                     in a binary signed with a paid-team provisioning profile.",
                ));
            }
            Ok(device)
        }

        pub fn set_verbose(&mut self, verbose: bool) {
            self.verbose = verbose;
        }
    }

    impl Drop for MacHidTransport {
        fn drop(&mut self) {
            unsafe {
                IOHIDUserDeviceUnscheduleFromRunLoop(
                    self.device,
                    self.runloop,
                    kCFRunLoopDefaultMode,
                );
                CFRunLoopStop(self.runloop);
                CFRelease(self.device);
            }
        }
    }

    impl Transport for MacHidTransport {
        fn recv_packet(&mut self) -> io::Result<[u8; PACKET_SIZE]> {
            let (lock, cvar) = &*self.queue;
            let mut q = lock
                .lock()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "packet queue poisoned"))?;
            loop {
                if let Some(p) = q.pop_front() {
                    return Ok(p);
                }
                q = cvar
                    .wait(q)
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "packet queue poisoned"))?;
            }
        }

        fn recv_packet_timeout(
            &mut self,
            timeout: std::time::Duration,
        ) -> io::Result<Option<[u8; PACKET_SIZE]>> {
            let (lock, cvar) = &*self.queue;
            let q = lock
                .lock()
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "packet queue poisoned"))?;
            let (mut q, _timeout_result) = cvar
                .wait_timeout_while(q, timeout, |q| q.is_empty())
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "packet queue poisoned"))?;
            Ok(q.pop_front())
        }

        fn send_packet(&mut self, packet: &[u8; PACKET_SIZE]) -> io::Result<()> {
            let data = unsafe {
                CFDataCreate(kCFAllocatorDefault, packet.as_ptr(), PACKET_SIZE as isize)
            };
            if data.is_null() {
                return Err(io::Error::new(io::ErrorKind::Other, "CFDataCreate failed"));
            }
            let rc = unsafe { IOHIDUserDeviceHandleReport(self.device, data) };
            unsafe { CFRelease(data) };
            if rc != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("IOHIDUserDeviceHandleReport failed: IOReturn {rc:#x}"),
                ));
            }
            if self.verbose {
                eprintln!("machid: sent 64-byte input report");
            }
            Ok(())
        }
    }
}
