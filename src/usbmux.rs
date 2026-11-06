//! Minimal usbmuxd client.
//!
//! usbmuxd multiplexes TCP-style connections to services on USB (or
//! Wi-Fi) iDevices. On Windows it is provided by Apple Mobile Device
//! Service (installed with Apple's "Apple Devices" app / iTunes) and
//! listens on 127.0.0.1:27015; on Linux the standalone usbmuxd speaks
//! the same protocol. This client is just enough of that protocol to
//! reach the phone app's bridge port without depending on third-party
//! iproxy binaries (docs/WINDOWS.md):
//!
//! 1. `ListDevices` on a fresh connection -> pick the first USB device.
//! 2. `Connect` for the bridge port on another fresh connection ->
//!    usbmuxd answers with a Result message and the connection then
//!    becomes a transparent pipe to the on-device service, over which
//!    the existing bridge protocol (crate::bridge) runs unchanged.
//!
//! Wire format: a 16-byte little-endian header
//! (total_length, version, message_type, tag) followed by a plist
//! payload. Version 1 payloads are XML plists (accepted by both real
//! usbmuxd and AMDS); version 0 payloads are binary plists. Requests
//! are sent as XML; responses are sniffed and parsed either way, so no
//! plist dependency is needed -- the parsers below cover exactly the
//! shapes usbmuxd emits (dict / array / string / integer / data /
//! bool / real).

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

/// Where AMDS / usbmuxd listens by default.
pub const DEFAULT_USBMUX_ADDR: &str = "127.0.0.1:27015";
/// TCP port the phone app's bridge listener accepts on (iproxy and adb
/// forward to the same port; see BRIDGE-PROTOCOL.md).
pub const PHONE_BRIDGE_PORT: u16 = 18765;
/// Environment variable overriding the usbmuxd address ("host:port").
pub const ADDR_ENV_VAR: &str = "IPHONE_FIDO_USBMUX_ADDR";

const HEADER_LEN: usize = 16;
const VERSION_XML: u32 = 1;
const MESSAGE_PLIST: u32 = 8;
/// Refuse absurd mux payloads (device lists are a few hundred bytes).
const MAX_PAYLOAD: usize = 4 * 1024 * 1024;

/// The usbmuxd address to use: `$IPHONE_FIDO_USBMUX_ADDR` when set,
/// otherwise [`DEFAULT_USBMUX_ADDR`].
pub fn usbmux_addr() -> String {
    match std::env::var(ADDR_ENV_VAR) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => DEFAULT_USBMUX_ADDR.to_string(),
    }
}

// ------------------------------------------------------------------ plist

/// The subset of plist values usbmuxd messages use.
#[derive(Debug, Clone, PartialEq)]
enum Plist {
    Dict(Vec<(String, Plist)>),
    Array(Vec<Plist>),
    Str(String),
    Int(i64),
    Data(Vec<u8>),
    Bool(bool),
    Real(f64),
}

impl Plist {
    fn get(&self, key: &str) -> Option<&Plist> {
        match self {
            Plist::Dict(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    fn as_str(&self) -> Option<&str> {
        match self {
            Plist::Str(s) => Some(s),
            _ => None,
        }
    }
    fn as_int(&self) -> Option<i64> {
        match self {
            Plist::Int(n) => Some(*n),
            _ => None,
        }
    }
    fn as_array(&self) -> Option<&[Plist]> {
        match self {
            Plist::Array(items) => Some(items),
            _ => None,
        }
    }
}

/// Parse a plist payload, sniffing binary ("bplist00") vs XML.
fn parse_plist(data: &[u8]) -> io::Result<Plist> {
    if data.starts_with(b"bplist00") {
        parse_binary_plist(data)
    } else {
        parse_xml_plist(data)
    }
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("usbmux plist: {}", msg.into()),
    )
}

// ------------------------------------------------------------- XML writer

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            _ => out.push(c),
        }
    }
    out
}

fn request_xml(entries: &[(&str, Plist)]) -> Vec<u8> {
    fn write_value(out: &mut String, v: &Plist) {
        match v {
            Plist::Str(s) => {
                out.push_str("<string>");
                out.push_str(&xml_escape(s));
                out.push_str("</string>");
            }
            Plist::Int(n) => out.push_str(&format!("<integer>{n}</integer>")),
            Plist::Bool(b) => out.push_str(if *b { "<true/>" } else { "<false/>" }),
            _ => out.push_str("<string></string>"), // not used by our requests
        }
    }
    let mut s = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n",
    );
    for (k, v) in entries {
        s.push_str("<key>");
        s.push_str(&xml_escape(k));
        s.push_str("</key>");
        write_value(&mut s, v);
        s.push('\n');
    }
    s.push_str("</dict>\n</plist>\n");
    s.into_bytes()
}

// ------------------------------------------------------------- XML parser
// Minimal recursive parser for the plist XML dialect: elements
// plist/dict/array/key/string/integer/real/data/true/false, character
// data with the five named entities plus numeric references. Comments,
// the XML prolog and the DOCTYPE are skipped.

struct XmlParser<'a> {
    text: &'a str,
    pos: usize,
}

impl<'a> XmlParser<'a> {
    fn new(data: &'a [u8]) -> io::Result<Self> {
        let text = std::str::from_utf8(data).map_err(|_| invalid("XML plist is not valid UTF-8"))?;
        Ok(Self { text, pos: 0 })
    }

    fn rest(&self) -> &'a str {
        &self.text[self.pos..]
    }

    fn bump(&mut self, n: usize) {
        self.pos += n;
    }

    fn skip_misc(&mut self) -> io::Result<()> {
        loop {
            let rest = self.rest().trim_start();
            self.pos = self.text.len() - rest.len();
            if rest.starts_with("<?") {
                match rest.find("?>") {
                    Some(i) => self.bump(i + 2),
                    None => return Err(invalid("unterminated processing instruction")),
                }
            } else if rest.starts_with("<!--") {
                match rest.find("-->") {
                    Some(i) => self.bump(i + 3),
                    None => return Err(invalid("unterminated comment")),
                }
            } else if rest.starts_with("<!") {
                match rest.find('>') {
                    Some(i) => self.bump(i + 1),
                    None => return Err(invalid("unterminated declaration")),
                }
            } else {
                return Ok(());
            }
        }
    }

    /// Consume `<tag ...>` (or `<tag/>`), returning (tag, self_closing).
    fn open_tag(&mut self) -> io::Result<(String, bool)> {
        self.skip_misc()?;
        let rest = self.rest();
        if !rest.starts_with('<') || rest.starts_with("</") {
            return Err(invalid("expected an opening tag"));
        }
        let end = rest.find('>').ok_or_else(|| invalid("unterminated tag"))?;
        let inside = rest[1..end].trim();
        let (name, self_closing) = match inside.strip_suffix('/') {
            Some(n) => (n.trim(), true),
            None => (inside, false),
        };
        let name = name.split_whitespace().next().unwrap_or("").to_string();
        if name.is_empty() {
            return Err(invalid("empty tag name"));
        }
        self.bump(end + 1);
        Ok((name, self_closing))
    }

    /// Consume character data up to the next '<', decoding entities.
    fn char_data(&mut self) -> String {
        let rest = self.rest();
        let end = rest.find('<').unwrap_or(rest.len());
        let raw = &rest[..end];
        self.bump(end);
        decode_entities(raw)
    }

    fn close_tag(&mut self, expected: &str) -> io::Result<()> {
        let rest = self.rest().trim_start();
        self.pos = self.text.len() - rest.len();
        let rest = self.rest();
        let want = format!("</{expected}>");
        if rest.starts_with(&want) {
            self.bump(want.len());
            Ok(())
        } else {
            Err(invalid(format!("expected {want}")))
        }
    }

    fn value(&mut self) -> io::Result<Plist> {
        let (tag, self_closing) = self.open_tag()?;
        match tag.as_str() {
            "dict" => {
                let mut pairs = Vec::new();
                if !self_closing {
                    loop {
                        self.skip_misc()?;
                        if self.rest().starts_with("</") {
                            break;
                        }
                        let (ktag, kself) = self.open_tag()?;
                        if ktag != "key" {
                            return Err(invalid("dict entry does not start with <key>"));
                        }
                        let key = if kself {
                            String::new()
                        } else {
                            let k = self.char_data();
                            self.close_tag("key")?;
                            k
                        };
                        let val = self.value()?;
                        pairs.push((key, val));
                    }
                    self.close_tag("dict")?;
                }
                Ok(Plist::Dict(pairs))
            }
            "array" => {
                let mut items = Vec::new();
                if !self_closing {
                    loop {
                        self.skip_misc()?;
                        if self.rest().starts_with("</") {
                            break;
                        }
                        items.push(self.value()?);
                    }
                    self.close_tag("array")?;
                }
                Ok(Plist::Array(items))
            }
            "string" => {
                if self_closing {
                    return Ok(Plist::Str(String::new()));
                }
                let s = self.char_data();
                self.close_tag("string")?;
                Ok(Plist::Str(s))
            }
            "integer" => {
                let s = self.char_data();
                self.close_tag("integer")?;
                s.trim()
                    .parse::<i64>()
                    .map(Plist::Int)
                    .map_err(|_| invalid("bad <integer>"))
            }
            "real" => {
                let s = self.char_data();
                self.close_tag("real")?;
                s.trim()
                    .parse::<f64>()
                    .map(Plist::Real)
                    .map_err(|_| invalid("bad <real>"))
            }
            "data" => {
                let s: String = self
                    .char_data()
                    .chars()
                    .filter(|c| !c.is_whitespace())
                    .collect();
                self.close_tag("data")?;
                B64.decode(s)
                    .map(Plist::Data)
                    .map_err(|_| invalid("bad <data> base64"))
            }
            "true" => {
                if !self_closing {
                    self.close_tag("true")?;
                }
                Ok(Plist::Bool(true))
            }
            "false" => {
                if !self_closing {
                    self.close_tag("false")?;
                }
                Ok(Plist::Bool(false))
            }
            other => Err(invalid(format!("unsupported plist element <{other}>"))),
        }
    }
}

fn decode_entities(raw: &str) -> String {
    if !raw.contains('&') {
        return raw.to_string();
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let Some(end) = after.find(';') else {
            out.push('&');
            rest = after;
            continue;
        };
        let entity = &after[..end];
        let decoded = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .and_then(|h| u32::from_str_radix(h, 16).ok())
                .or_else(|| entity.strip_prefix('#').and_then(|d| d.parse::<u32>().ok()))
                .and_then(char::from_u32),
        };
        match decoded {
            Some(c) => out.push(c),
            None => {
                out.push('&');
                out.push_str(entity);
                out.push(';');
            }
        }
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    out
}

fn parse_xml_plist(data: &[u8]) -> io::Result<Plist> {
    let mut p = XmlParser::new(data)?;
    let (tag, self_closing) = p.open_tag()?;
    if tag != "plist" || self_closing {
        return Err(invalid("document is not a <plist>"));
    }
    let v = p.value()?;
    p.close_tag("plist")?;
    Ok(v)
}

// ---------------------------------------------------------- binary parser
// bplist00: objects addressed by index through an offset table, with a
// 32-byte trailer at the end. Only the object types usbmuxd emits are
// supported (plus UID, folded to Int).

fn parse_binary_plist(data: &[u8]) -> io::Result<Plist> {
    if data.len() < 8 + 32 || !data.starts_with(b"bplist00") {
        return Err(invalid("bad binary plist header"));
    }
    let trailer = &data[data.len() - 32..];
    let offset_size = trailer[6] as usize;
    let ref_size = trailer[7] as usize;
    let num_objects = be_u64(&trailer[8..16]) as usize;
    let top_object = be_u64(&trailer[16..24]) as usize;
    let offset_table_at = be_u64(&trailer[24..32]) as usize;
    if offset_size == 0 || offset_size > 8 || ref_size == 0 || ref_size > 8 || num_objects == 0 {
        return Err(invalid("implausible binary plist trailer"));
    }
    let mut offsets = Vec::with_capacity(num_objects);
    for i in 0..num_objects {
        let at = offset_table_at + i * offset_size;
        let raw = data
            .get(at..at + offset_size)
            .ok_or_else(|| invalid("offset table out of bounds"))?;
        offsets.push(be_uint(raw) as usize);
    }
    let mut bp = Bplist {
        data,
        offsets,
        ref_size,
    };
    bp.object(top_object, 0)
}

fn be_u64(b: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&b[..8]);
    u64::from_be_bytes(buf)
}

fn be_uint(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |acc, &x| (acc << 8) | x as u64)
}

struct Bplist<'a> {
    data: &'a [u8],
    offsets: Vec<usize>,
    ref_size: usize,
}

impl<'a> Bplist<'a> {
    fn object(&mut self, index: usize, depth: usize) -> io::Result<Plist> {
        if depth > 64 {
            return Err(invalid("binary plist nesting too deep"));
        }
        let offset = *self
            .offsets
            .get(index)
            .ok_or_else(|| invalid("binary plist object index out of range"))?;
        let marker = *self
            .data
            .get(offset)
            .ok_or_else(|| invalid("binary plist object out of bounds"))?;
        let kind = marker >> 4;
        let info = (marker & 0x0F) as usize;
        let body = offset + 1;
        match kind {
            0x0 => match info {
                0x0 => Ok(Plist::Str(String::new())), // null; unused in mux traffic
                0x8 => Ok(Plist::Bool(false)),
                0x9 => Ok(Plist::Bool(true)),
                _ => Err(invalid("unsupported simple plist object")),
            },
            0x1 => {
                let size = 1usize << info;
                let raw = self
                    .data
                    .get(body..body + size)
                    .ok_or_else(|| invalid("int object out of bounds"))?;
                Ok(Plist::Int(be_uint(raw) as i64))
            }
            0x2 => {
                let size = 1usize << info;
                let raw = self
                    .data
                    .get(body..body + size)
                    .ok_or_else(|| invalid("real object out of bounds"))?;
                let v = match size {
                    4 => f32::from_be_bytes(raw.try_into().unwrap()) as f64,
                    8 => f64::from_be_bytes(raw.try_into().unwrap()),
                    _ => return Err(invalid("odd real size in binary plist")),
                };
                Ok(Plist::Real(v))
            }
            0x4 => {
                let (len, at) = self.length(info, body)?;
                let raw = self
                    .data
                    .get(at..at + len)
                    .ok_or_else(|| invalid("data object out of bounds"))?;
                Ok(Plist::Data(raw.to_vec()))
            }
            0x5 => {
                let (len, at) = self.length(info, body)?;
                let raw = self
                    .data
                    .get(at..at + len)
                    .ok_or_else(|| invalid("string object out of bounds"))?;
                String::from_utf8(raw.to_vec())
                    .map(Plist::Str)
                    .map_err(|_| invalid("non-UTF-8 ASCII string in binary plist"))
            }
            0x6 => {
                let (len, at) = self.length(info, body)?;
                let raw = self
                    .data
                    .get(at..at + len * 2)
                    .ok_or_else(|| invalid("UTF-16 string out of bounds"))?;
                let units: Vec<u16> = raw
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
                String::from_utf16(&units)
                    .map(Plist::Str)
                    .map_err(|_| invalid("invalid UTF-16 in binary plist"))
            }
            0x8 => {
                let size = info + 1;
                let raw = self
                    .data
                    .get(body..body + size)
                    .ok_or_else(|| invalid("UID object out of bounds"))?;
                Ok(Plist::Int(be_uint(raw) as i64))
            }
            0xA => {
                let (len, at) = self.length(info, body)?;
                let mut items = Vec::with_capacity(len);
                for i in 0..len {
                    let r = self.read_ref(at + i * self.ref_size)?;
                    items.push(self.object(r, depth + 1)?);
                }
                Ok(Plist::Array(items))
            }
            0xD => {
                let (len, at) = self.length(info, body)?;
                let mut keys = Vec::with_capacity(len);
                for i in 0..len {
                    let r = self.read_ref(at + i * self.ref_size)?;
                    match self.object(r, depth + 1)? {
                        Plist::Str(s) => keys.push(s),
                        _ => return Err(invalid("binary plist dict key is not a string")),
                    }
                }
                let vat = at + len * self.ref_size;
                let mut pairs = Vec::with_capacity(len);
                for (i, key) in keys.into_iter().enumerate() {
                    let r = self.read_ref(vat + i * self.ref_size)?;
                    let v = self.object(r, depth + 1)?;
                    pairs.push((key, v));
                }
                Ok(Plist::Dict(pairs))
            }
            _ => Err(invalid(format!(
                "unsupported binary plist object type {kind:#x}"
            ))),
        }
    }

    /// Length for sized objects: `info` is the length unless it is
    /// 0xF, in which case an int object follows giving the length.
    /// Returns (length, offset of the payload / ref array).
    fn length(&self, info: usize, body: usize) -> io::Result<(usize, usize)> {
        if info != 0xF {
            return Ok((info, body));
        }
        let marker = *self
            .data
            .get(body)
            .ok_or_else(|| invalid("missing length int in binary plist"))?;
        if marker >> 4 != 0x1 {
            return Err(invalid("length is not an int object in binary plist"));
        }
        let size = 1usize << (marker & 0x0F);
        let raw = self
            .data
            .get(body + 1..body + 1 + size)
            .ok_or_else(|| invalid("length int out of bounds"))?;
        Ok((be_uint(raw) as usize, body + 1 + size))
    }

    fn read_ref(&self, at: usize) -> io::Result<usize> {
        let raw = self
            .data
            .get(at..at + self.ref_size)
            .ok_or_else(|| invalid("object ref out of bounds"))?;
        Ok(be_uint(raw) as usize)
    }
}

// ---------------------------------------------------------------- protocol

/// One device as reported by usbmuxd's ListDevices.
#[derive(Debug, Clone, PartialEq)]
pub struct UsbMuxDevice {
    pub device_id: u32,
    /// "USB" / "Network" / "WiFi" when reported.
    pub connection_type: Option<String>,
    pub serial_number: Option<String>,
    pub product_id: Option<u16>,
}

fn write_message(stream: &mut TcpStream, tag: u32, payload: &[u8]) -> io::Result<()> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&((HEADER_LEN + payload.len()) as u32).to_le_bytes());
    header.extend_from_slice(&VERSION_XML.to_le_bytes());
    header.extend_from_slice(&MESSAGE_PLIST.to_le_bytes());
    header.extend_from_slice(&tag.to_le_bytes());
    stream.write_all(&header)?;
    stream.write_all(payload)?;
    stream.flush()
}

fn read_message(stream: &mut TcpStream) -> io::Result<Plist> {
    let mut header = [0u8; HEADER_LEN];
    stream.read_exact(&mut header)?;
    let total = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
    if total < HEADER_LEN || total - HEADER_LEN > MAX_PAYLOAD {
        return Err(invalid(format!("implausible usbmux message length {total}")));
    }
    let mut payload = vec![0u8; total - HEADER_LEN];
    stream.read_exact(&mut payload)?;
    parse_plist(&payload)
}

fn mux_connect(addr: &str) -> io::Result<TcpStream> {
    let stream = match addr.parse::<std::net::SocketAddr>() {
        Ok(sock) => TcpStream::connect_timeout(&sock, Duration::from_secs(3))?,
        Err(_) => TcpStream::connect(addr)?,
    };
    stream.set_nodelay(true).ok();
    // The mux handshakes must be time-bounded; callers that keep the
    // stream (Connect) re-tune the timeouts for their own protocol.
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
    Ok(stream)
}

fn base_request(message_type: &str) -> Vec<(&'static str, Plist)> {
    vec![
        ("MessageType", Plist::Str(message_type.to_string())),
        ("ProgName", Plist::Str("iphone-fido".to_string())),
        ("ClientVersionString", Plist::Str("iphone-fido".to_string())),
    ]
}

/// Query usbmuxd for the currently attached devices.
pub fn list_devices(addr: &str) -> io::Result<Vec<UsbMuxDevice>> {
    let mut stream = mux_connect(addr)?;
    let mut entries = base_request("ListDevices");
    entries.push(("kLibUSBMuxVersion", Plist::Int(3)));
    write_message(&mut stream, 1, &request_xml(&entries))?;
    let response = read_message(&mut stream)?;
    parse_device_list(&response)
}

fn parse_device_list(response: &Plist) -> io::Result<Vec<UsbMuxDevice>> {
    let list = response
        .get("DeviceList")
        .and_then(Plist::as_array)
        .ok_or_else(|| invalid("ListDevices response has no DeviceList"))?;
    let mut out = Vec::new();
    for item in list {
        let props = item.get("Properties");
        let device_id = item
            .get("DeviceID")
            .and_then(Plist::as_int)
            .or_else(|| props.and_then(|p| p.get("DeviceID")).and_then(Plist::as_int))
            .ok_or_else(|| invalid("device entry has no DeviceID"))?;
        let get_prop = |key: &str| props.and_then(|p| p.get(key));
        out.push(UsbMuxDevice {
            device_id: device_id as u32,
            connection_type: get_prop("ConnectionType")
                .and_then(Plist::as_str)
                .map(str::to_string),
            serial_number: get_prop("SerialNumber")
                .and_then(Plist::as_str)
                .map(str::to_string)
                .or_else(|| {
                    get_prop("UniqueDeviceID")
                        .and_then(Plist::as_str)
                        .map(str::to_string)
                }),
            product_id: get_prop("ProductID").and_then(Plist::as_int).map(|n| n as u16),
        });
    }
    Ok(out)
}

/// Pick the device the bridge should use: the first USB-connected
/// device. Devices whose ConnectionType is absent are accepted after
/// explicitly-USB ones (some usbmuxd builds omit the field);
/// network-only listings are never picked -- this project is USB-only
/// by design.
pub fn pick_usb_device(devices: &[UsbMuxDevice]) -> Option<&UsbMuxDevice> {
    devices
        .iter()
        .find(|d| d.connection_type.as_deref() == Some("USB"))
        .or_else(|| devices.iter().find(|d| d.connection_type.is_none()))
}

/// The port as usbmuxd wants it in a Connect request: byte-swapped
/// (the field carries htons(port) as an integer).
fn swapped_port(port: u16) -> i64 {
    port.swap_bytes() as i64
}

/// Open a connection through usbmuxd to `port` on `device_id`. After a
/// successful Result the returned stream is a transparent pipe to the
/// on-device service.
pub fn connect_to_device(addr: &str, device_id: u32, port: u16) -> io::Result<TcpStream> {
    let mut stream = mux_connect(addr)?;
    let mut entries = base_request("Connect");
    entries.push(("DeviceID", Plist::Int(device_id as i64)));
    entries.push(("PortNumber", Plist::Int(swapped_port(port))));
    write_message(&mut stream, 1, &request_xml(&entries))?;
    let response = read_message(&mut stream)?;
    let number = response
        .get("Number")
        .and_then(Plist::as_int)
        .ok_or_else(|| invalid("Connect response has no result Number"))?;
    if number != 0 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("usbmuxd Connect to device {device_id} port {port} refused (result {number})"),
        ));
    }
    Ok(stream)
}

/// List devices, pick the first USB one, and connect to the phone
/// app's bridge port on it.
pub fn open_phone_stream(addr: &str) -> io::Result<TcpStream> {
    let devices = list_devices(addr)?;
    let device = pick_usb_device(&devices).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            "usbmuxd reports no USB-connected iDevice",
        )
    })?;
    connect_to_device(addr, device.device_id, PHONE_BRIDGE_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    // plistlib (FMT_BINARY / FMT_XML) dumps of one ListDevices response
    // with a Network device (id 3) listed ahead of a USB device (id 7).
    // The XML form lives in usbmux_fixture_list.xml (same directory).
    const LIST_XML: &str = include_str!("usbmux_fixture_list.xml");
    const LIST_BIN_B64: &str = "YnBsaXN0MDDRAQJaRGV2aWNlTGlzdKIDENMEBQYHCAlYRGV2aWNlSURbTWVzc2FnZVR5cGVaUHJvcGVydGllcxADWEF0dGFjaGVk1AoECwwNBw4PXkNvbm5lY3Rpb25UeXBlXFNlcmlhbE51bWJlcl5VbmlxdWVEZXZpY2VJRFdOZXR3b3JrVk5FVDEyM1huZXQtdWRpZNMEBQYRCBIQB9UKBBMLDBQRFRYXWVByb2R1Y3RJRFNVU0IREpdeMDAwMDgxMDFBQkNERUZfEBkwMDAwODEwMS0wMDExMjIzMzQ0NTU2Njc3CAsWGSApNUBCS1RjcH+HjpeeoKu1ubzLAAAAAAAAAQEAAAAAAAAAGAAAAAAAAAAAAAAAAAAAAOc=";
    const RESULT_BIN_B64: &str = "YnBsaXN0MDDSAQIDBFtNZXNzYWdlVHlwZVZOdW1iZXJWUmVzdWx0EAAIDRkgJwAAAAAAAAEBAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAAp";

    fn expected_devices() -> Vec<UsbMuxDevice> {
        vec![
            UsbMuxDevice {
                device_id: 3,
                connection_type: Some("Network".into()),
                serial_number: Some("NET123".into()),
                product_id: None,
            },
            UsbMuxDevice {
                device_id: 7,
                connection_type: Some("USB".into()),
                serial_number: Some("00008101ABCDEF".into()),
                product_id: Some(4759),
            },
        ]
    }

    #[test]
    fn xml_plist_device_list_parses() {
        let parsed = parse_xml_plist(LIST_XML.as_bytes()).unwrap();
        assert_eq!(parse_device_list(&parsed).unwrap(), expected_devices());
    }

    #[test]
    fn binary_plist_device_list_parses() {
        let bin = B64.decode(LIST_BIN_B64).unwrap();
        let parsed = parse_plist(&bin).unwrap();
        assert_eq!(parse_device_list(&parsed).unwrap(), expected_devices());
    }

    #[test]
    fn binary_plist_result_parses() {
        let bin = B64.decode(RESULT_BIN_B64).unwrap();
        let parsed = parse_plist(&bin).unwrap();
        assert_eq!(
            parsed.get("MessageType").and_then(Plist::as_str),
            Some("Result")
        );
        assert_eq!(parsed.get("Number").and_then(Plist::as_int), Some(0));
    }

    #[test]
    fn pick_prefers_usb_over_network() {
        let devices = expected_devices();
        assert_eq!(pick_usb_device(&devices).unwrap().device_id, 7);
        let network_only = &devices[..1];
        assert!(pick_usb_device(network_only).is_none());
    }

    #[test]
    fn port_is_byte_swapped_for_connect() {
        // 18765 = 0x494D -> 0x4D49 = 19785 on the wire.
        assert_eq!(swapped_port(18765), 19785);
        assert_eq!(swapped_port(0x01BB), 0xBB01);
    }

    #[test]
    fn request_xml_roundtrips_through_own_parser() {
        let mut entries = base_request("Connect");
        entries.push(("DeviceID", Plist::Int(7)));
        entries.push(("PortNumber", Plist::Int(swapped_port(PHONE_BRIDGE_PORT))));
        let xml = request_xml(&entries);
        let parsed = parse_xml_plist(&xml).unwrap();
        assert_eq!(
            parsed.get("MessageType").and_then(Plist::as_str),
            Some("Connect")
        );
        assert_eq!(parsed.get("DeviceID").and_then(Plist::as_int), Some(7));
        assert_eq!(parsed.get("PortNumber").and_then(Plist::as_int), Some(19785));
    }

    // ------------------------------------------------------------ fake mux

    fn framed(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&((HEADER_LEN + payload.len()) as u32).to_le_bytes());
        out.extend_from_slice(&VERSION_XML.to_le_bytes());
        out.extend_from_slice(&MESSAGE_PLIST.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    fn read_client_message(stream: &mut TcpStream) -> Plist {
        let mut header = [0u8; HEADER_LEN];
        stream.read_exact(&mut header).unwrap();
        let total = u32::from_le_bytes(header[0..4].try_into().unwrap()) as usize;
        let mut payload = vec![0u8; total - HEADER_LEN];
        stream.read_exact(&mut payload).unwrap();
        parse_plist(&payload).unwrap()
    }

    /// A fake usbmuxd: answers ListDevices (XML response) and then a
    /// Connect with a *binary* plist Result (real AMDS answers binary),
    /// after which the connection is a transparent pipe to the phone.
    #[test]
    fn client_connects_through_fake_usbmuxd() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = thread::spawn(move || {
            // Connection 1: ListDevices (from the list_devices call).
            let (mut s1, _) = listener.accept().unwrap();
            let req = read_client_message(&mut s1);
            assert_eq!(
                req.get("MessageType").and_then(Plist::as_str),
                Some("ListDevices")
            );
            s1.write_all(&framed(LIST_XML.as_bytes())).unwrap();
            drop(s1);
            // Connection 2: ListDevices again (open_phone_stream lists
            // first), connection 3: Connect for USB device + bridge port.
            let (mut s2, _) = listener.accept().unwrap();
            let req = read_client_message(&mut s2);
            assert_eq!(
                req.get("MessageType").and_then(Plist::as_str),
                Some("ListDevices")
            );
            s2.write_all(&framed(LIST_XML.as_bytes())).unwrap();
            drop(s2);
            let (mut s3, _) = listener.accept().unwrap();
            let req = read_client_message(&mut s3);
            assert_eq!(req.get("MessageType").and_then(Plist::as_str), Some("Connect"));
            assert_eq!(req.get("DeviceID").and_then(Plist::as_int), Some(7));
            assert_eq!(req.get("PortNumber").and_then(Plist::as_int), Some(19785));
            let result_bin = B64.decode(RESULT_BIN_B64).unwrap();
            s3.write_all(&framed(&result_bin)).unwrap();
            // The connection is now a transparent pipe to the device.
            s3.write_all(b"PHONE-PIPE-HELLO").unwrap();
            let mut echo = [0u8; 4];
            s3.read_exact(&mut echo).unwrap();
            assert_eq!(&echo, b"PING");
        });

        let devices = list_devices(&addr).unwrap();
        assert_eq!(devices, expected_devices());

        let mut stream = open_phone_stream(&addr).unwrap();
        let mut greeting = [0u8; 16];
        stream.read_exact(&mut greeting).unwrap();
        assert_eq!(&greeting, b"PHONE-PIPE-HELLO");
        stream.write_all(b"PING").unwrap();
        server.join().unwrap();
    }
}
