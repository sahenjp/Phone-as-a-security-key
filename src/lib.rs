//! iphone-fido: Fedora-side virtual FIDO2 authenticator.
//!
//! CTAPHID/CTAP2 are terminated on the PC; the actual P-256 private keys
//! live on the iPhone (Secure Enclave) and are reached through the
//! encrypted bridge protocol described in docs/BRIDGE-PROTOCOL.md.
//! A software [`phone::MockPhone`] exists for development only.

pub mod authenticator;
pub mod bridge;
pub mod cbor_util;
pub mod ctap2;
pub mod ctaphid;
pub mod phone;
pub mod selftest;
pub mod transport;

/// Project-fixed AAGUID, hex: 69 70 68 2d 66 69 64 6f 2d 30 30 30 30 30 30 31
/// (decodes to ASCII "iph-fido-0000001", 16 bytes).
pub const AAGUID: [u8; 16] = [
    0x69, 0x70, 0x68, 0x2d, 0x66, 0x69, 0x64, 0x6f, 0x2d, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x31,
];

/// SHA-256 helper.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Fill a buffer with OS randomness.
pub fn fill_random(buf: &mut [u8]) {
    use rand_core::RngCore;
    rand_core::OsRng.fill_bytes(buf);
}

/// Encode an ECDSA P-256 signature (fixed 64-byte r||s) as ASN.1 DER.
pub fn ecdsa_rs_to_der(rs: &[u8; 64]) -> Vec<u8> {
    fn der_integer(x: &[u8]) -> Vec<u8> {
        let mut start = 0;
        while start < x.len() - 1 && x[start] == 0 {
            start += 1;
        }
        let mut v = Vec::new();
        v.push(0x02);
        let need_pad = x[start] & 0x80 != 0;
        v.push((x.len() - start + need_pad as usize) as u8);
        if need_pad {
            v.push(0x00);
        }
        v.extend_from_slice(&x[start..]);
        v
    }
    let r = der_integer(&rs[..32]);
    let s = der_integer(&rs[32..]);
    let mut out = Vec::with_capacity(2 + r.len() + s.len());
    out.push(0x30);
    out.push((r.len() + s.len()) as u8);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    out
}

/// Decode an ASN.1 DER ECDSA signature into fixed 64-byte r||s.
/// Returns `None` on malformed input.
pub fn ecdsa_der_to_rs(der: &[u8]) -> Option<[u8; 64]> {
    fn read_integer(data: &[u8], pos: &mut usize) -> Option<[u8; 32]> {
        if *pos + 2 > data.len() || data[*pos] != 0x02 {
            return None;
        }
        let len = data[*pos + 1] as usize;
        *pos += 2;
        if *pos + len > data.len() || len == 0 || len > 33 {
            return None;
        }
        let raw = &data[*pos..*pos + len];
        *pos += len;
        let raw = if raw.len() == 33 {
            if raw[0] != 0x00 {
                return None;
            }
            &raw[1..]
        } else {
            raw
        };
        let mut out = [0u8; 32];
        out[32 - raw.len()..].copy_from_slice(raw);
        Some(out)
    }
    if der.len() < 2 || der[0] != 0x30 {
        return None;
    }
    let mut pos = 2usize;
    // Long-form length is not expected for P-256 DER signatures, but tolerate
    // the single-byte long form (0x81).
    if der[1] == 0x81 {
        if der.len() < 3 {
            return None;
        }
        pos = 3;
    }
    let r = read_integer(der, &mut pos)?;
    let s = read_integer(der, &mut pos)?;
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r);
    out[32..].copy_from_slice(&s);
    Some(out)
}
