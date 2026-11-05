//! CTAPHID framing layer (FIDO CTAP spec, HID transport).
//!
//! Packets are exactly 64 bytes. An initialization packet carries
//! `CID(4) || CMD(1, high bit set) || BCNT(2 BE) || payload[..57]`;
//! continuation packets carry `CID(4) || SEQ(1, 0..=127) || payload[..59]`.

pub const PACKET_SIZE: usize = 64;
pub const INIT_PACKET_PAYLOAD: usize = 57;
pub const CONT_PACKET_PAYLOAD: usize = 59;
pub const BROADCAST_CID: u32 = 0xFFFF_FFFF;
/// Upper bound accepted for one reassembled HID message.
pub const MAX_MESSAGE_SIZE: usize = 8192;

// Commands (without the 0x80 transport bit; stored here in wire form).
pub const CMD_PING: u8 = 0x81;
pub const CMD_MSG: u8 = 0x83;
pub const CMD_LOCK: u8 = 0x84;
pub const CMD_INIT: u8 = 0x86;
pub const CMD_WINK: u8 = 0x88;
pub const CMD_CBOR: u8 = 0x90;
pub const CMD_CANCEL: u8 = 0x91;
pub const CMD_ERROR: u8 = 0xBF;
pub const CMD_KEEPALIVE: u8 = 0xBB;

// CTAPHID error codes (payload of CMD_ERROR is a single byte).
pub const ERR_INVALID_CMD: u8 = 0x01;
pub const ERR_INVALID_PARAMETER: u8 = 0x02;
pub const ERR_INVALID_LEN: u8 = 0x03;
pub const ERR_INVALID_SEQ: u8 = 0x04;
pub const ERR_MSG_TIMEOUT: u8 = 0x05;
pub const ERR_CHANNEL_BUSY: u8 = 0x06;
pub const ERR_LOCK_REQUIRED: u8 = 0x0A;
pub const ERR_INVALID_CHANNEL: u8 = 0x0B;
pub const ERR_OTHER: u8 = 0x7F;

// Capability bits for the INIT response.
pub const CAPABILITY_WINK: u8 = 0x01;
pub const CAPABILITY_CBOR: u8 = 0x04;
pub const CAPABILITY_NMSG: u8 = 0x08;
/// We support CBOR (CTAP2) only. We do not implement CTAPHID_MSG (U2F /
/// CTAP1 requests are rejected with INVALID_CMD), so NMSG MUST be set:
/// NMSG is the authenticator's declaration that MSG is not supported.
/// Leaving it clear makes hosts treat the device as CTAP1-capable — e.g.
/// Mozilla's authenticator-rs (Firefox) checks `!NMSG` for CTAP1 support
/// and, for requests flagged `use_ctap1_fallback`, downgrades to a U2F
/// register attempt before ever trying CTAP2 (observed on the real
/// device 2026-11-05). With NMSG set the downgrade fails and the host
/// proceeds with CTAP2.
pub const CAPABILITIES: u8 = CAPABILITY_CBOR | CAPABILITY_NMSG;

/// A parsed HID packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawPacket {
    Initialization {
        cid: u32,
        cmd: u8,
        bcnt: u16,
        data: Vec<u8>,
    },
    Continuation {
        cid: u32,
        seq: u8,
        data: Vec<u8>,
    },
}

impl RawPacket {
    pub fn cid(&self) -> u32 {
        match self {
            RawPacket::Initialization { cid, .. } => *cid,
            RawPacket::Continuation { cid, .. } => *cid,
        }
    }
}

/// Parse one 64-byte packet. Never fails: the second header byte decides
/// initialization vs. continuation.
pub fn parse_packet(packet: &[u8; PACKET_SIZE]) -> RawPacket {
    let cid = u32::from_be_bytes([packet[0], packet[1], packet[2], packet[3]]);
    let tag = packet[4];
    if tag & 0x80 != 0 {
        let bcnt = u16::from_be_bytes([packet[5], packet[6]]);
        RawPacket::Initialization {
            cid,
            cmd: tag,
            bcnt,
            data: packet[7..].to_vec(),
        }
    } else {
        RawPacket::Continuation {
            cid,
            seq: tag & 0x7F,
            data: packet[5..].to_vec(),
        }
    }
}

/// Split one HID message into 64-byte packets.
pub fn fragment(cid: u32, cmd: u8, payload: &[u8]) -> Vec<[u8; PACKET_SIZE]> {
    assert!(payload.len() <= u16::MAX as usize, "HID message too large");
    let mut packets = Vec::new();
    let mut first = [0u8; PACKET_SIZE];
    first[0..4].copy_from_slice(&cid.to_be_bytes());
    first[4] = cmd | 0x80;
    first[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let n = payload.len().min(INIT_PACKET_PAYLOAD);
    first[7..7 + n].copy_from_slice(&payload[..n]);
    packets.push(first);

    let mut offset = n;
    let mut seq: u8 = 0;
    while offset < payload.len() {
        let mut pkt = [0u8; PACKET_SIZE];
        pkt[0..4].copy_from_slice(&cid.to_be_bytes());
        pkt[4] = seq;
        let n = (payload.len() - offset).min(CONT_PACKET_PAYLOAD);
        pkt[5..5 + n].copy_from_slice(&payload[offset..offset + n]);
        packets.push(pkt);
        offset += n;
        seq += 1;
    }
    packets
}

/// Reassembles a fragmented HID message for one channel.
/// Used by the authenticator (per channel) and by test clients.
#[derive(Debug, Default)]
pub struct Assembler {
    pending: Option<Pending>,
}

#[derive(Debug)]
struct Pending {
    cmd: u8,
    total: usize,
    buf: Vec<u8>,
    next_seq: u8,
}

impl Assembler {
    pub fn new() -> Self {
        Self { pending: None }
    }

    pub fn reset(&mut self) {
        self.pending = None;
    }

    pub fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// Feed one packet. On completion returns `Some((cmd, payload))`.
    /// On protocol error returns `Err(ctaphid_error_code)`.
    pub fn feed(&mut self, packet: &RawPacket) -> Result<Option<(u8, Vec<u8>)>, u8> {
        match packet {
            RawPacket::Initialization { cmd, bcnt, data, .. } => {
                let total = *bcnt as usize;
                if total > MAX_MESSAGE_SIZE {
                    self.pending = None;
                    return Err(ERR_INVALID_LEN);
                }
                let take = total.min(data.len());
                let buf = data[..take].to_vec();
                if buf.len() >= total {
                    self.pending = None;
                    Ok(Some((*cmd, buf)))
                } else {
                    self.pending = Some(Pending {
                        cmd: *cmd,
                        total,
                        buf,
                        next_seq: 0,
                    });
                    Ok(None)
                }
            }
            RawPacket::Continuation { seq, data, .. } => {
                let pending = match self.pending.as_mut() {
                    Some(p) => p,
                    None => return Err(ERR_INVALID_SEQ),
                };
                if *seq != pending.next_seq {
                    self.pending = None;
                    return Err(ERR_INVALID_SEQ);
                }
                pending.next_seq += 1;
                let remaining = pending.total - pending.buf.len();
                let take = remaining.min(data.len());
                pending.buf.extend_from_slice(&data[..take]);
                if pending.buf.len() >= pending.total {
                    let p = self.pending.take().unwrap();
                    Ok(Some((p.cmd, p.buf)))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(payload_len: usize) {
        let payload: Vec<u8> = (0..payload_len).map(|i| (i % 251) as u8).collect();
        let packets = fragment(0x11223344, CMD_CBOR, &payload);
        let mut asm = Assembler::new();
        let mut result = None;
        for raw in &packets {
            let pkt = parse_packet(raw);
            assert_eq!(pkt.cid(), 0x11223344);
            if let Some(done) = asm.feed(&pkt).expect("feed ok") {
                result = Some(done);
            }
        }
        let (cmd, data) = result.expect("message completed");
        assert_eq!(cmd, CMD_CBOR);
        assert_eq!(data, payload);
    }

    #[test]
    fn fragment_reassemble_small() {
        roundtrip(0);
        roundtrip(1);
        roundtrip(10);
    }

    #[test]
    fn fragment_reassemble_exact_boundaries() {
        roundtrip(INIT_PACKET_PAYLOAD);
        roundtrip(INIT_PACKET_PAYLOAD + 1);
        roundtrip(INIT_PACKET_PAYLOAD + CONT_PACKET_PAYLOAD);
    }

    #[test]
    fn fragment_reassemble_large() {
        roundtrip(1200);
        roundtrip(4096);
    }

    #[test]
    fn continuation_seq_error() {
        let payload = vec![7u8; 200];
        let packets = fragment(9, CMD_PING, &payload);
        let mut asm = Assembler::new();
        asm.feed(&parse_packet(&packets[0])).unwrap();
        // Skip the first continuation packet: sequence mismatch.
        let err = asm.feed(&parse_packet(&packets[2])).unwrap_err();
        assert_eq!(err, ERR_INVALID_SEQ);
    }

    #[test]
    fn packet_layout() {
        let packets = fragment(BROADCAST_CID, CMD_INIT, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(packets.len(), 1);
        let p = &packets[0];
        assert_eq!(&p[0..4], &BROADCAST_CID.to_be_bytes());
        assert_eq!(p[4], CMD_INIT);
        assert_eq!(u16::from_be_bytes([p[5], p[6]]), 8);
        assert_eq!(&p[7..15], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }
}
