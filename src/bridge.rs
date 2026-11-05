//! Bridge protocol v1 client (and a phone-side handshake helper for tests).
//!
//! Wire format and cryptography follow docs/BRIDGE-PROTOCOL.md exactly:
//! 4-byte BE length framing, PSK pairing, ephemeral P-256 ECDH handshake
//! with HKDF-SHA256 key derivation and HMAC confirmation, then
//! ChaCha20-Poly1305 encrypted frames with per-direction keys and a
//! sequence-number nonce.

use std::fs;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdh::{diffie_hellman, EphemeralSecret};
use p256::PublicKey;
use serde_json::{json, Value};
use sha2::Sha256;

pub const DEFAULT_PHONE_ADDR: &str = "127.0.0.1:18766";
pub const MAX_FRAME_SIZE: usize = 1024 * 1024;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug)]
pub struct BridgeError(pub String);

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "bridge error: {}", self.0)
    }
}
impl std::error::Error for BridgeError {}

impl From<io::Error> for BridgeError {
    fn from(e: io::Error) -> Self {
        BridgeError(e.to_string())
    }
}

pub type BridgeResult<T> = Result<T, BridgeError>;

fn err<T>(msg: impl Into<String>) -> BridgeResult<T> {
    Err(BridgeError(msg.into()))
}

// ---------------------------------------------------------------- pairing

/// Default PSK storage path: `~/.config/iphone-fido/pairing.bin`.
pub fn default_pairing_path() -> PathBuf {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("~"));
    home.join(".config").join("iphone-fido").join("pairing.bin")
}

const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// Decode RFC 4648 Base32 without padding (52 chars -> 32 bytes for a PSK).
/// Accepts lowercase input and surrounding whitespace.
pub fn base32_decode_nopad(input: &str) -> Result<Vec<u8>, String> {
    let mut bits: u32 = 0;
    let mut bits_len: u32 = 0;
    let mut out = Vec::new();
    for ch in input.trim().chars() {
        let up = ch.to_ascii_uppercase();
        let val = B32_ALPHABET
            .iter()
            .position(|&c| c as char == up)
            .ok_or_else(|| format!("invalid Base32 character: {ch:?}"))? as u32;
        bits = (bits << 5) | val;
        bits_len += 5;
        if bits_len >= 8 {
            bits_len -= 8;
            out.push((bits >> bits_len) as u8);
            bits &= (1u32 << bits_len) - 1;
        }
    }
    Ok(out)
}

/// Encode bytes as RFC 4648 Base32 without padding (for tests / display).
pub fn base32_encode_nopad(data: &[u8]) -> String {
    let mut out = String::new();
    let mut bits: u32 = 0;
    let mut bits_len: u32 = 0;
    for &b in data {
        bits = (bits << 8) | b as u32;
        bits_len += 8;
        while bits_len >= 5 {
            bits_len -= 5;
            out.push(B32_ALPHABET[((bits >> bits_len) & 0x1F) as usize] as char);
        }
    }
    if bits_len > 0 {
        out.push(B32_ALPHABET[((bits << (5 - bits_len)) & 0x1F) as usize] as char);
    }
    out
}

/// Short authentication string: first 3 bytes of
/// SHA-256(PSK || "iphone-fido-sas-v1") as an integer mod 1_000_000, %06d.
pub fn sas_for_psk(psk: &[u8]) -> String {
    let mut data = Vec::with_capacity(psk.len() + 16);
    data.extend_from_slice(psk);
    data.extend_from_slice(b"iphone-fido-sas-v1");
    let hash = crate::sha256(&data);
    let n = u32::from_be_bytes([0, hash[0], hash[1], hash[2]]) % 1_000_000;
    format!("{n:06}")
}

/// Save the PSK with mode 0600, creating parent directories.
pub fn save_pairing(path: &Path, psk: &[u8; 32]) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, psk)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

pub fn load_pairing(path: &Path) -> io::Result<[u8; 32]> {
    let data = fs::read(path)?;
    if data.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("pairing file must be 32 bytes, got {}", data.len()),
        ));
    }
    let mut psk = [0u8; 32];
    psk.copy_from_slice(&data);
    Ok(psk)
}

// ---------------------------------------------------------------- framing

pub fn write_frame(w: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_FRAME_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "frame too large"));
    }
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()
}

pub fn read_frame(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "frame too large"));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

// ---------------------------------------------------------------- crypto helpers

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

struct SessionKeys {
    pc_to_phone: [u8; 32],
    phone_to_pc: [u8; 32],
    confirm: [u8; 32],
}

fn derive_keys(
    ecdh_x: &[u8; 32],
    psk: &[u8; 32],
    pc_random: &[u8; 32],
    phone_random: &[u8; 32],
) -> SessionKeys {
    let mut ikm = Vec::with_capacity(64);
    ikm.extend_from_slice(ecdh_x);
    ikm.extend_from_slice(psk);
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(pc_random);
    salt.extend_from_slice(phone_random);
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut pc_to_phone = [0u8; 32];
    let mut phone_to_pc = [0u8; 32];
    let mut confirm = [0u8; 32];
    hk.expand(b"iphone-fido v1 pc-to-phone", &mut pc_to_phone)
        .expect("32-byte HKDF expand");
    hk.expand(b"iphone-fido v1 phone-to-pc", &mut phone_to_pc)
        .expect("32-byte HKDF expand");
    hk.expand(b"iphone-fido v1 confirm", &mut confirm)
        .expect("32-byte HKDF expand");
    SessionKeys {
        pc_to_phone,
        phone_to_pc,
        confirm,
    }
}

fn confirm_mac(confirm_key: &[u8; 32], who: &[u8], pc_random: &[u8; 32], phone_random: &[u8; 32]) -> [u8; 32] {
    let mut data = Vec::with_capacity(who.len() + 64);
    data.extend_from_slice(who);
    data.extend_from_slice(pc_random);
    data.extend_from_slice(phone_random);
    hmac_sha256(confirm_key, &data)
}

fn b64_encode(data: &[u8]) -> String {
    B64.encode(data)
}

fn b64_decode(s: &str) -> BridgeResult<Vec<u8>> {
    B64.decode(s).map_err(|e| BridgeError(format!("base64: {e}")))
}

fn json_str<'a>(v: &'a Value, field: &str) -> BridgeResult<&'a str> {
    v.get(field)
        .and_then(|x| x.as_str())
        .ok_or_else(|| BridgeError(format!("missing string field {field}")))
}

// ---------------------------------------------------------------- session

/// An established, encrypted bridge session over a TCP stream.
pub struct BridgeSession {
    stream: TcpStream,
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_seq: u64,
    recv_seq: u64,
}

impl BridgeSession {
    fn nonce(seq: u64) -> Nonce {
        let mut n = [0u8; 12];
        n[4..].copy_from_slice(&seq.to_be_bytes());
        *Nonce::from_slice(&n)
    }

    /// Encrypt and send one JSON message.
    pub fn send_json(&mut self, msg: &Value) -> BridgeResult<()> {
        let plaintext = serde_json::to_vec(msg).map_err(|e| BridgeError(e.to_string()))?;
        let cipher = ChaCha20Poly1305::new((&self.send_key).into());
        let ciphertext = cipher
            .encrypt(&Self::nonce(self.send_seq), plaintext.as_slice())
            .map_err(|_| BridgeError("encryption failed".into()))?;
        let mut payload = Vec::with_capacity(8 + ciphertext.len());
        payload.extend_from_slice(&self.send_seq.to_be_bytes());
        payload.extend_from_slice(&ciphertext);
        self.send_seq += 1;
        write_frame(&mut self.stream, &payload)?;
        Ok(())
    }

    /// Receive and decrypt one JSON message. Any failure is fatal
    /// (the caller must drop the connection), per spec.
    pub fn recv_json(&mut self) -> BridgeResult<Value> {
        let payload = read_frame(&mut self.stream)?;
        if payload.len() < 8 + 16 {
            return err("encrypted frame too short");
        }
        let seq = u64::from_be_bytes(payload[..8].try_into().unwrap());
        if seq != self.recv_seq {
            return err(format!(
                "sequence mismatch: expected {}, got {seq}",
                self.recv_seq
            ));
        }
        let cipher = ChaCha20Poly1305::new((&self.recv_key).into());
        let plaintext = cipher
            .decrypt(&Self::nonce(seq), &payload[8..])
            .map_err(|_| BridgeError("decryption failed (authentication error)".into()))?;
        self.recv_seq += 1;
        serde_json::from_slice(&plaintext).map_err(|e| BridgeError(format!("JSON: {e}")))
    }
}

/// PC side of the handshake (docs/BRIDGE-PROTOCOL.md section 2).
pub fn client_handshake(mut stream: TcpStream, psk: &[u8; 32]) -> BridgeResult<BridgeSession> {
    let mut pc_random = [0u8; 32];
    crate::fill_random(&mut pc_random);
    let ephemeral = EphemeralSecret::random(&mut rand_core::OsRng);
    let pc_pub = ephemeral.public_key().to_sec1_bytes();

    let hello = json!({
        "type": "hello",
        "version": 1,
        "pc_random": b64_encode(&pc_random),
        "pc_ephemeral_pubkey": b64_encode(&pc_pub),
    });
    write_frame(&mut stream, serde_json::to_vec(&hello).unwrap().as_slice())?;

    let ack_bytes = read_frame(&mut stream)?;
    let ack: Value = serde_json::from_slice(&ack_bytes)
        .map_err(|e| BridgeError(format!("hello_ack JSON: {e}")))?;
    if json_str(&ack, "type")? != "hello_ack" {
        return err("unexpected handshake message (expected hello_ack)");
    }
    let phone_random_bytes = b64_decode(json_str(&ack, "phone_random")?)?;
    let phone_pub_bytes = b64_decode(json_str(&ack, "phone_ephemeral_pubkey")?)?;
    if phone_random_bytes.len() != 32 {
        return err("phone_random must be 32 bytes");
    }
    let mut phone_random = [0u8; 32];
    phone_random.copy_from_slice(&phone_random_bytes);
    let phone_pub = PublicKey::from_sec1_bytes(&phone_pub_bytes)
        .map_err(|e| BridgeError(format!("phone ephemeral pubkey: {e}")))?;

    let shared = ephemeral.diffie_hellman(&phone_pub);
    let ecdh_x: [u8; 32] = shared
        .raw_secret_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| BridgeError("ECDH secret is not 32 bytes".into()))?;

    let keys = derive_keys(&ecdh_x, psk, &pc_random, &phone_random);

    let mac = confirm_mac(&keys.confirm, b"pc", &pc_random, &phone_random);
    let confirm = json!({"type": "confirm", "mac": b64_encode(&mac)});
    write_frame(&mut stream, serde_json::to_vec(&confirm).unwrap().as_slice())?;

    let ack2_bytes = read_frame(&mut stream)?;
    let ack2: Value = serde_json::from_slice(&ack2_bytes)
        .map_err(|e| BridgeError(format!("confirm_ack JSON: {e}")))?;
    if json_str(&ack2, "type")? != "confirm_ack" {
        return err("unexpected handshake message (expected confirm_ack)");
    }
    let their_mac = b64_decode(json_str(&ack2, "mac")?)?;
    let expected = confirm_mac(&keys.confirm, b"phone", &pc_random, &phone_random);
    if their_mac.len() != 32 || !constant_time_eq(&their_mac, &expected) {
        return err("phone confirmation MAC mismatch; aborting");
    }

    Ok(BridgeSession {
        stream,
        send_key: keys.pc_to_phone,
        recv_key: keys.phone_to_pc,
        send_seq: 0,
        recv_seq: 0,
    })
}

/// Phone side of the handshake. Used by tests to stand in for the iPhone
/// app; the real phone side is the Swift implementation.
pub fn server_handshake(mut stream: TcpStream, psk: &[u8; 32]) -> BridgeResult<BridgeSession> {
    let hello_bytes = read_frame(&mut stream)?;
    let hello: Value = serde_json::from_slice(&hello_bytes)
        .map_err(|e| BridgeError(format!("hello JSON: {e}")))?;
    if json_str(&hello, "type")? != "hello" {
        return err("unexpected handshake message (expected hello)");
    }
    let pc_random_bytes = b64_decode(json_str(&hello, "pc_random")?)?;
    let pc_pub_bytes = b64_decode(json_str(&hello, "pc_ephemeral_pubkey")?)?;
    if pc_random_bytes.len() != 32 {
        return err("pc_random must be 32 bytes");
    }
    let mut pc_random = [0u8; 32];
    pc_random.copy_from_slice(&pc_random_bytes);
    let pc_pub = PublicKey::from_sec1_bytes(&pc_pub_bytes)
        .map_err(|e| BridgeError(format!("pc ephemeral pubkey: {e}")))?;

    let mut phone_random = [0u8; 32];
    crate::fill_random(&mut phone_random);
    // ECDH via an explicit secret key so both directions share the helper
    // path (EphemeralSecret is consumed by diffie_hellman on the PC side).
    let secret = p256::SecretKey::random(&mut rand_core::OsRng);
    let phone_pub = secret.public_key().to_sec1_bytes();
    let shared = diffie_hellman(secret.to_nonzero_scalar(), pc_pub.as_affine());
    let ecdh_x: [u8; 32] = shared
        .raw_secret_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| BridgeError("ECDH secret is not 32 bytes".into()))?;

    let ack = json!({
        "type": "hello_ack",
        "version": 1,
        "phone_random": b64_encode(&phone_random),
        "phone_ephemeral_pubkey": b64_encode(&phone_pub),
    });
    write_frame(&mut stream, serde_json::to_vec(&ack).unwrap().as_slice())?;

    let keys = derive_keys(&ecdh_x, psk, &pc_random, &phone_random);

    let confirm_bytes = read_frame(&mut stream)?;
    let confirm_msg: Value = serde_json::from_slice(&confirm_bytes)
        .map_err(|e| BridgeError(format!("confirm JSON: {e}")))?;
    if json_str(&confirm_msg, "type")? != "confirm" {
        return err("unexpected handshake message (expected confirm)");
    }
    let their_mac = b64_decode(json_str(&confirm_msg, "mac")?)?;
    let expected = confirm_mac(&keys.confirm, b"pc", &pc_random, &phone_random);
    if their_mac.len() != 32 || !constant_time_eq(&their_mac, &expected) {
        return err("pc confirmation MAC mismatch; aborting");
    }

    let mac = confirm_mac(&keys.confirm, b"phone", &pc_random, &phone_random);
    let confirm_ack = json!({"type": "confirm_ack", "mac": b64_encode(&mac)});
    write_frame(&mut stream, serde_json::to_vec(&confirm_ack).unwrap().as_slice())?;

    Ok(BridgeSession {
        stream,
        send_key: keys.phone_to_pc,
        recv_key: keys.pc_to_phone,
        send_seq: 0,
        recv_seq: 0,
    })
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Connect to the phone (through iproxy) and complete the handshake.
/// All phases are time-bounded: a half-alive path (iproxy accepting but
/// the app suspended, so nobody ever answers) must fail within seconds —
/// the daemon's serve loop calls this on its upkeep tick and must never
/// stall there.
pub fn connect(addr: &str, psk: &[u8; 32]) -> BridgeResult<BridgeSession> {
    use std::time::Duration;
    let stream = match addr.parse::<std::net::SocketAddr>() {
        Ok(sock) => TcpStream::connect_timeout(&sock, Duration::from_secs(3))
            .map_err(|e| BridgeError(format!("connect to {addr}: {e}")))?,
        Err(_) => TcpStream::connect(addr)
            .map_err(|e| BridgeError(format!("connect to {addr}: {e}")))?,
    };
    stream.set_nodelay(true).ok();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .ok();
    let mut session = client_handshake(stream, psk)?;
    // Established: relax the read timeout to a stall guard comfortably
    // beyond the phone's 60-second user-approval window.
    session
        .stream
        .set_read_timeout(Some(Duration::from_secs(120)))
        .ok();
    session
        .stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .ok();
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base32_rfc4648_vectors() {
        // RFC 4648 test vectors, padding stripped.
        assert_eq!(base32_decode_nopad("").unwrap(), b"");
        assert_eq!(base32_decode_nopad("MY").unwrap(), b"f");
        assert_eq!(base32_decode_nopad("MZXQ").unwrap(), b"fo");
        assert_eq!(base32_decode_nopad("MZXW6").unwrap(), b"foo");
        assert_eq!(base32_decode_nopad("MZXW6YQ").unwrap(), b"foob");
        assert_eq!(base32_decode_nopad("MZXW6YTB").unwrap(), b"fooba");
        assert_eq!(base32_decode_nopad("MZXW6YTBOI").unwrap(), b"foobar");
        assert_eq!(base32_encode_nopad(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn base32_psk_roundtrip_52_chars() {
        let mut psk = [0u8; 32];
        crate::fill_random(&mut psk);
        let encoded = base32_encode_nopad(&psk);
        assert_eq!(encoded.len(), 52);
        let decoded = base32_decode_nopad(&encoded).unwrap();
        assert_eq!(decoded, psk.to_vec());
        // Lowercase is accepted.
        let decoded_lower = base32_decode_nopad(&encoded.to_lowercase()).unwrap();
        assert_eq!(decoded_lower, psk.to_vec());
    }

    #[test]
    fn sas_format() {
        let sas = sas_for_psk(&[0u8; 32]);
        assert_eq!(sas.len(), 6);
        assert!(sas.chars().all(|c| c.is_ascii_digit()));
        assert_eq!(sas, sas_for_psk(&[0u8; 32]), "SAS is deterministic");
        assert_ne!(sas, sas_for_psk(&[1u8; 32]));
    }

    // ---- Cross-implementation known-answer vectors.
    // These inputs/expectations are shared with the Swift implementation
    // (ios/IPhoneFidoKeyTests/BridgeCoreTests.swift) and were computed
    // independently from BRIDGE-PROTOCOL.md. Inputs are consecutive byte
    // sequences starting at 0x00 / 0x20 / 0x40 / 0x60.

    fn seq32(start: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = start.wrapping_add(i as u8);
        }
        out
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn swift_vector_key_derivation() {
        let keys = derive_keys(&seq32(0x20), &seq32(0x00), &seq32(0x40), &seq32(0x60));
        assert_eq!(
            hex(&keys.pc_to_phone),
            "093052a5a2a26a710fb010734f5569ebcd2ec65c8336122feb38ef1917cb5591"
        );
        assert_eq!(
            hex(&keys.phone_to_pc),
            "f0681d919195bba9c5562d6148ca0673ad872ba80b20507c7e26352cc2f32d81"
        );
        assert_eq!(
            hex(&keys.confirm),
            "2f1c882095510a5376a4a94d3bd711d0e8df3d17a0429d94c6cadf6bee2aad61"
        );
    }

    #[test]
    fn swift_vector_confirm_macs() {
        let keys = derive_keys(&seq32(0x20), &seq32(0x00), &seq32(0x40), &seq32(0x60));
        let pc_mac = confirm_mac(&keys.confirm, b"pc", &seq32(0x40), &seq32(0x60));
        assert_eq!(
            b64_encode(&pc_mac),
            "BQIUMQKwysvX3l9RZz70MFccHqYuCKlFc+W+MDSo23Q="
        );
        let phone_mac = confirm_mac(&keys.confirm, b"phone", &seq32(0x40), &seq32(0x60));
        assert_eq!(
            b64_encode(&phone_mac),
            "+KjEbAbdyW+wvCnE5d0wnOhoCjyHcMgc4sEAgElXGcQ="
        );
    }

    #[test]
    fn swift_vector_sas_and_base32() {
        assert_eq!(sas_for_psk(&seq32(0x00)), "212523");
        let encoded = base32_encode_nopad(&seq32(0x00));
        assert_eq!(encoded, "AAAQEAYEAUDAOCAJBIFQYDIOB4IBCEQTCQKRMFYYDENBWHA5DYPQ");
        assert_eq!(encoded.len(), 52);
        assert_eq!(base32_decode_nopad(&encoded).unwrap(), seq32(0x00).to_vec());
    }

    #[test]
    fn frame_roundtrip() {
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, b"hello bridge").unwrap();
        write_frame(&mut buf, b"").unwrap();
        let mut cursor = io::Cursor::new(buf);
        assert_eq!(read_frame(&mut cursor).unwrap(), b"hello bridge");
        assert_eq!(read_frame(&mut cursor).unwrap(), b"");
    }
}
