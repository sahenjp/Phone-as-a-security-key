//! The virtual authenticator: CTAPHID channel management on the outside,
//! CTAP2 dispatch on the inside, phone operations delegated to a `Phone`.

use std::collections::HashMap;
use std::io;

use crate::ctap2;
use crate::ctaphid::{
    self, Assembler, RawPacket, BROADCAST_CID, PACKET_SIZE,
};
use crate::phone::Phone;
use crate::transport::Transport;

pub struct Authenticator<P: Phone> {
    phone: P,
    assemblers: HashMap<u32, Assembler>,
    next_cid: u32,
    verbose: bool,
}

impl<P: Phone> Authenticator<P> {
    pub fn new(phone: P) -> Self {
        Self {
            phone,
            assemblers: HashMap::new(),
            next_cid: 1,
            verbose: false,
        }
    }

    /// When enabled, each CTAPHID message and CTAP2 command/status is
    /// logged to stderr (metadata only: no key material, no payloads).
    pub fn set_verbose(&mut self, verbose: bool) {
        self.verbose = verbose;
    }

    pub fn phone(&self) -> &P {
        &self.phone
    }

    pub fn phone_mut(&mut self) -> &mut P {
        &mut self.phone
    }

    fn allocate_cid(&mut self) -> u32 {
        loop {
            let cid = self.next_cid;
            self.next_cid = self.next_cid.wrapping_add(1).max(1);
            if cid != BROADCAST_CID && cid != 0 && !self.assemblers.contains_key(&cid) {
                return cid;
            }
        }
    }

    fn err(&self, cid: u32, code: u8) -> Vec<[u8; PACKET_SIZE]> {
        if self.verbose {
            let name = match code {
                ctaphid::ERR_INVALID_CMD => "INVALID_CMD",
                ctaphid::ERR_INVALID_PARAMETER => "INVALID_PARAMETER",
                ctaphid::ERR_INVALID_LEN => "INVALID_LEN",
                ctaphid::ERR_INVALID_SEQ => "INVALID_SEQ",
                ctaphid::ERR_CHANNEL_BUSY => "CHANNEL_BUSY",
                ctaphid::ERR_INVALID_CHANNEL => "INVALID_CHANNEL",
                _ => "other",
            };
            eprintln!("ctaphid: -> ERROR {name} ({code:#04x}) on cid {cid:#010x}");
        }
        vec![Self::error_packet(cid, code)]
    }

    fn error_packet(cid: u32, code: u8) -> [u8; PACKET_SIZE] {
        ctaphid::fragment(cid, ctaphid::CMD_ERROR, &[code])
            .into_iter()
            .next()
            .unwrap()
    }

    /// Handle one inbound 64-byte packet; returns zero or more response
    /// packets to send back.
    pub fn handle_packet(&mut self, packet: &[u8; PACKET_SIZE]) -> Vec<[u8; PACKET_SIZE]> {
        let parsed = ctaphid::parse_packet(packet);
        let cid = parsed.cid();
        if self.verbose {
            match &parsed {
                RawPacket::Initialization { cmd, bcnt, .. } => {
                    eprintln!("ctaphid: packet INIT-frame cid {cid:#010x} cmd {cmd:#04x} bcnt {bcnt}");
                }
                RawPacket::Continuation { seq, .. } => {
                    eprintln!("ctaphid: packet CONT cid {cid:#010x} seq {seq}");
                }
            }
        }

        match &parsed {
            RawPacket::Initialization { cmd, bcnt, data, .. } => {
                if *cmd == ctaphid::CMD_INIT {
                    return self.handle_init(cid, *bcnt, data);
                }
                if cid == BROADCAST_CID {
                    return self.err(cid, ctaphid::ERR_INVALID_CHANNEL);
                }
                if !self.assemblers.contains_key(&cid) {
                    return self.err(cid, ctaphid::ERR_INVALID_CHANNEL);
                }
                // CANCEL targets the channel's pending transaction.
                if *cmd == ctaphid::CMD_CANCEL {
                    if let Some(a) = self.assemblers.get_mut(&cid) {
                        a.reset();
                    }
                    return Vec::new();
                }
                match self.feed(cid, &parsed) {
                    Ok(Some((mcmd, payload))) => self.dispatch(cid, mcmd, &payload),
                    Ok(None) => Vec::new(),
                    Err(code) => self.err(cid, code),
                }
            }
            RawPacket::Continuation { .. } => {
                if !self.assemblers.contains_key(&cid) {
                    return self.err(cid, ctaphid::ERR_INVALID_CHANNEL);
                }
                match self.feed(cid, &parsed) {
                    Ok(Some((mcmd, payload))) => self.dispatch(cid, mcmd, &payload),
                    Ok(None) => Vec::new(),
                    Err(code) => self.err(cid, code),
                }
            }
        }
    }

    fn feed(
        &mut self,
        cid: u32,
        packet: &RawPacket,
    ) -> Result<Option<(u8, Vec<u8>)>, u8> {
        let asm = self.assemblers.entry(cid).or_insert_with(Assembler::new);
        asm.feed(packet)
    }

    /// CTAPHID INIT: nonce echo + channel allocation.
    /// On the broadcast channel a fresh CID is allocated; on an existing
    /// channel this is a synchronisation and the CID is echoed unchanged.
    fn handle_init(&mut self, cid: u32, bcnt: u16, data: &[u8]) -> Vec<[u8; PACKET_SIZE]> {
        if bcnt != 8 || data.len() < 8 {
            if self.verbose {
                eprintln!("ctaphid: INIT rejected: bcnt {bcnt}, data {} bytes", data.len());
            }
            return self.err(cid, ctaphid::ERR_INVALID_LEN);
        }
        let nonce = &data[..8];
        let response_cid;
        let assigned_cid;
        if cid == BROADCAST_CID {
            assigned_cid = self.allocate_cid();
            self.assemblers.insert(assigned_cid, Assembler::new());
            response_cid = BROADCAST_CID;
        } else {
            assigned_cid = cid;
            self.assemblers.entry(cid).or_insert_with(Assembler::new);
            if let Some(a) = self.assemblers.get_mut(&cid) {
                a.reset();
            }
            response_cid = cid;
        }
        if self.verbose {
            eprintln!("ctaphid: INIT on cid {cid:#010x} -> assigned cid {assigned_cid}");
        }
        let mut payload = Vec::with_capacity(17);
        payload.extend_from_slice(nonce); // nonce echo
        payload.extend_from_slice(&assigned_cid.to_be_bytes());
        payload.push(2); // CTAPHID protocol version
        payload.push(1); // device major version
        payload.push(0); // device minor version
        payload.push(1); // build version
        payload.push(ctaphid::CAPABILITIES);
        ctaphid::fragment(response_cid, ctaphid::CMD_INIT, &payload)
    }

    /// Dispatch one fully reassembled HID message.
    fn dispatch(&mut self, cid: u32, cmd: u8, payload: &[u8]) -> Vec<[u8; PACKET_SIZE]> {
        match cmd {
            ctaphid::CMD_PING => ctaphid::fragment(cid, ctaphid::CMD_PING, payload),
            ctaphid::CMD_CBOR => {
                let ctap_cmd = payload.first().copied().unwrap_or(0);
                let response = ctap2::process(&mut self.phone, payload);
                if self.verbose {
                    let name = match ctap_cmd {
                        ctap2::CMD_MAKE_CREDENTIAL => "makeCredential",
                        ctap2::CMD_GET_ASSERTION => "getAssertion",
                        ctap2::CMD_GET_INFO => "getInfo",
                        _ => "unknown",
                    };
                    eprintln!(
                        "ctap2: {name} (cmd {ctap_cmd:#04x}, req {} bytes) -> status {:#04x}, resp {} bytes",
                        payload.len(),
                        response.first().copied().unwrap_or(0),
                        response.len()
                    );
                    // TEMP DEBUG (interop investigation): dump the full
                    // request of any failed CTAP2 call so the rejecting
                    // parameter can be identified from the raw CBOR.
                    if response.first().copied().unwrap_or(0) != 0 {
                        let hex: String = payload.iter().map(|b| format!("{b:02x}")).collect();
                        eprintln!("ctap2-debug: failed request payload hex: {hex}");
                    }
                }
                ctaphid::fragment(cid, ctaphid::CMD_CBOR, &response)
            }
            ctaphid::CMD_MSG => {
                // U2F (CTAP1) operations are not implemented (INIT declares
                // NMSG), but answer in-band with an ISO 7816 status word
                // like a real key's CTAP1 applet would, instead of a
                // transport-level CTAPHID ERROR: some clients (Chromium)
                // send MSG probes during discovery/requests and treat a
                // transport error as a malfunctioning device. The VERSION
                // query gets the standard capability answer; every actual
                // U2F operation gets 0x6D00 (INS not supported), so a
                // client that proceeds anyway fails cleanly in-band.
                if self.verbose {
                    let hex: String =
                        payload.iter().map(|b| format!("{b:02x}")).collect();
                    eprintln!("ctaphid: MSG probe payload hex: {hex}");
                }
                let resp: Vec<u8> = match (payload.first(), payload.get(1)) {
                    (Some(0x00), Some(0x03)) => {
                        let mut v = b"U2F_V2".to_vec();
                        v.extend_from_slice(&[0x90, 0x00]);
                        v
                    }
                    (Some(_), Some(_)) => vec![0x6D, 0x00],
                    _ => vec![0x67, 0x00],
                };
                ctaphid::fragment(cid, ctaphid::CMD_MSG, &resp)
            }
            ctaphid::CMD_CANCEL => Vec::new(),
            ctaphid::CMD_KEEPALIVE | ctaphid::CMD_ERROR => Vec::new(),
            other => {
                if self.verbose {
                    eprintln!("ctaphid: unsupported HID cmd {other:#04x} on cid {cid:#010x}");
                }
                self.err(cid, ctaphid::ERR_INVALID_CMD)
            }
        }
    }

    /// Pump a transport until it would block (MockTransport) or errors.
    /// Returns the number of packets processed. Blocking transports use
    /// the run loop in `main` instead.
    pub fn pump<T: Transport>(&mut self, transport: &mut T) -> io::Result<usize> {
        let mut processed = 0;
        loop {
            match transport.recv_packet() {
                Ok(packet) => {
                    processed += 1;
                    for out in self.handle_packet(&packet) {
                        transport.send_packet(&out)?;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        Ok(processed)
    }
}
