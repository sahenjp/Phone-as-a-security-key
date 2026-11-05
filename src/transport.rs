//! HID packet transports.
//!
//! - [`UhidTransport`]: real hardware via /dev/uhid (Linux UHID, written
//!   directly against the kernel ABI — no uhid crate).
//! - [`MockTransport`]: in-memory queue, for tests and `selftest`.
//! - [`StdioTransport`]: raw 64-byte packets over stdin/stdout, for
//!   development without UHID (selected with `--transport stdio`).

use std::collections::VecDeque;
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

// ------------------------------------------------------------- UhidTransport

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

/// FIDO HID report descriptor: usage page 0xF1D0, 64-byte in/out reports.
const FIDO_REPORT_DESCRIPTOR: &[u8] = &[
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
    fn read_output_packet(&mut self) -> io::Result<[u8; PACKET_SIZE]> {
        let mut ev = vec![0u8; UHID_EVENT_SIZE];
        loop {
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
                return Ok(packet);
            }
            // Remaining events (START/STOP/OPEN/CLOSE, ...) need no reply.
        }
    }
}

impl Transport for UhidTransport {
    fn recv_packet(&mut self) -> io::Result<[u8; PACKET_SIZE]> {
        self.read_output_packet()
    }

    fn recv_packet_timeout(
        &mut self,
        timeout: std::time::Duration,
    ) -> io::Result<Option<[u8; PACKET_SIZE]>> {
        use std::os::unix::io::AsRawFd;
        let mut pfd = libc::pollfd {
            fd: self.file.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc == 0 {
            return Ok(None);
        }
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        // Something arrived. read_output_packet consumes events until an
        // OUTPUT report shows up; the non-OUTPUT events need no waiting
        // beyond this in practice, and an idle host (the case the timeout
        // exists for) never reaches here.
        self.read_output_packet().map(Some)
    }

    fn send_packet(&mut self, packet: &[u8; PACKET_SIZE]) -> io::Result<()> {
        self.send_input2(packet)
    }
}
