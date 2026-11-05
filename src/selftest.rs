//! End-to-end self test: MockPhone + MockTransport.
//!
//! Drives the authenticator exactly like a host would (CTAPHID INIT,
//! CBOR getInfo -> makeCredential -> getAssertion), then verifies the
//! assertion signature with the credential public key taken from the
//! attested authData. Returns log lines; the caller prints PASS/FAIL.

use ciborium::value::Value;

use crate::authenticator::Authenticator;
use crate::cbor_util as cu;
use crate::ctaphid::{self, Assembler, BROADCAST_CID, PACKET_SIZE};
use crate::phone::{verifying_key_from_x963, verify_der_signature, MockPhone};
use crate::transport::MockTransport;
use crate::AAGUID;

/// Minimal host-side HID client driving an Authenticator through a
/// MockTransport, reassembling response messages itself.
struct HidClient {
    assembler: Assembler,
}

impl HidClient {
    fn new() -> Self {
        Self {
            assembler: Assembler::new(),
        }
    }

    fn exchange(
        &mut self,
        auth: &mut Authenticator<MockPhone>,
        transport: &mut MockTransport,
        cid: u32,
        cmd: u8,
        payload: &[u8],
    ) -> Result<(u8, Vec<u8>), String> {
        for pkt in ctaphid::fragment(cid, cmd, payload) {
            transport.queue_incoming(pkt);
        }
        auth.pump(transport).map_err(|e| format!("pump: {e}"))?;
        let sent = transport.take_sent();
        if sent.is_empty() {
            return Err("no response packets from authenticator".into());
        }
        let mut completed = None;
        for pkt in &sent {
            let parsed = ctaphid::parse_packet(pkt);
            if let Some(done) = self
                .assembler
                .feed(&parsed)
                .map_err(|c| format!("response reassembly error {c:#x}"))?
            {
                completed = Some(done);
            }
        }
        completed.ok_or_else(|| "response message did not complete".to_string())
    }
}

fn expect_status0(response: &[u8]) -> Result<&[u8], String> {
    match response.first() {
        Some(0x00) => Ok(&response[1..]),
        Some(code) => Err(format!("CTAP error status {code:#04x}")),
        None => Err("empty CTAP response".into()),
    }
}

pub fn run_selftest() -> Result<Vec<String>, String> {
    let mut log: Vec<String> = Vec::new();
    let mut auth = Authenticator::new(MockPhone::new());
    let mut transport = MockTransport::new();
    let mut client = HidClient::new();

    // ---- CTAPHID INIT on the broadcast channel
    let nonce: [u8; 8] = [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE];
    let (_cmd, init_resp) = client.exchange(
        &mut auth,
        &mut transport,
        BROADCAST_CID,
        ctaphid::CMD_INIT,
        &nonce,
    )?;
    if init_resp.len() != 17 {
        return Err(format!("INIT response must be 17 bytes, got {}", init_resp.len()));
    }
    if init_resp[..8] != nonce {
        return Err("INIT nonce was not echoed".into());
    }
    let cid = u32::from_be_bytes(init_resp[8..12].try_into().unwrap());
    if cid == 0 || cid == BROADCAST_CID {
        return Err("INIT assigned an invalid channel id".into());
    }
    let capabilities = init_resp[16];
    if capabilities & ctaphid::CAPABILITY_CBOR == 0 {
        return Err("INIT capabilities do not advertise CBOR".into());
    }
    log.push(format!(
        "INIT ok: channel {cid:#010x}, capabilities {capabilities:#04x}"
    ));

    // ---- PING echo
    let (_cmd, pong) = client.exchange(
        &mut auth,
        &mut transport,
        cid,
        ctaphid::CMD_PING,
        b"selftest-ping",
    )?;
    if pong != b"selftest-ping" {
        return Err("PING payload not echoed".into());
    }
    log.push("PING ok".into());

    // ---- CTAP2 getInfo
    let (_cmd, resp) = client.exchange(
        &mut auth,
        &mut transport,
        cid,
        ctaphid::CMD_CBOR,
        &[crate::ctap2::CMD_GET_INFO],
    )?;
    let info = cu::decode(expect_status0(&resp)?).map_err(|e| e)?;
    let versions = cu::get_int_key(&info, 0x01).ok_or("getInfo: missing versions")?;
    let versions_ok = cu::as_array(versions)
        .map(|a| a.iter().any(|v| cu::as_text(v) == Some("FIDO_2_0")))
        .unwrap_or(false);
    if !versions_ok {
        return Err("getInfo: versions does not contain FIDO_2_0".into());
    }
    let aaguid = cu::get_int_key(&info, 0x03).and_then(cu::as_bytes).ok_or("getInfo: missing aaguid")?;
    if aaguid != AAGUID {
        return Err("getInfo: AAGUID mismatch".into());
    }
    log.push("getInfo ok: versions=[FIDO_2_0], aaguid matches".into());

    // ---- CTAP2 makeCredential (rp example.com)
    let client_data_hash_1 = crate::sha256(b"selftest clientData #1");
    let mc_params = cu::imap(vec![
        (1, cu::vbytes(client_data_hash_1.to_vec())),
        (
            2,
            cu::tmap(vec![
                ("id", cu::vtext("example.com")),
                ("name", cu::vtext("Example")),
            ]),
        ),
        (
            3,
            cu::tmap(vec![
                ("id", cu::vbytes(b"user-123".to_vec())),
                ("name", cu::vtext("sahen")),
                ("displayName", cu::vtext("sahen")),
            ]),
        ),
        (
            4,
            Value::Array(vec![cu::tmap(vec![
                ("type", cu::vtext("public-key")),
                ("alg", cu::vint(-7)),
            ])]),
        ),
        (7, cu::tmap(vec![("rk", cu::vbool(true))])),
    ]);
    let mut mc_msg = vec![crate::ctap2::CMD_MAKE_CREDENTIAL];
    mc_msg.extend_from_slice(&cu::encode(&mc_params));
    let (_cmd, resp) = client.exchange(&mut auth, &mut transport, cid, ctaphid::CMD_CBOR, &mc_msg)?;
    let mc = cu::decode(expect_status0(&resp)?).map_err(|e| e)?;
    let fmt = cu::get_int_key(&mc, 1).and_then(cu::as_text).ok_or("makeCredential: missing fmt")?;
    if fmt != "none" {
        return Err(format!("makeCredential: expected fmt none, got {fmt}"));
    }
    let auth_data = cu::get_int_key(&mc, 2)
        .and_then(cu::as_bytes)
        .ok_or("makeCredential: missing authData")?
        .to_vec();
    // Parse attested credential data out of authData.
    if auth_data.len() < 55 {
        return Err("makeCredential: authData too short".into());
    }
    if auth_data[..32] != crate::sha256(b"example.com") {
        return Err("makeCredential: authData rpIdHash mismatch".into());
    }
    if auth_data[32] != 0x45 {
        return Err(format!(
            "makeCredential: expected flags 0x45, got {:#04x}",
            auth_data[32]
        ));
    }
    if auth_data[37..53] != AAGUID {
        return Err("makeCredential: authData AAGUID mismatch".into());
    }
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let credential_id = auth_data[55..55 + cred_len].to_vec();
    let cose = cu::decode(&auth_data[55 + cred_len..]).map_err(|e| format!("COSE key: {e}"))?;
    let x = cu::get_int_key(&cose, -2).and_then(cu::as_bytes).ok_or("COSE: missing x")?;
    let y = cu::get_int_key(&cose, -3).and_then(cu::as_bytes).ok_or("COSE: missing y")?;
    let mut x963 = vec![0x04u8];
    x963.extend_from_slice(x);
    x963.extend_from_slice(y);
    let verifying_key =
        verifying_key_from_x963(&x963).ok_or("COSE: cannot build verifying key")?;
    log.push(format!(
        "makeCredential ok: fmt=none, credential_id {} bytes, COSE ES256 key parsed",
        credential_id.len()
    ));

    // ---- CTAP2 getAssertion
    let client_data_hash_2 = crate::sha256(b"selftest clientData #2");
    let ga_params = cu::imap(vec![
        (1, cu::vtext("example.com")),
        (2, cu::vbytes(client_data_hash_2.to_vec())),
        (
            3,
            Value::Array(vec![cu::tmap(vec![
                ("type", cu::vtext("public-key")),
                ("id", cu::vbytes(credential_id.clone())),
            ])]),
        ),
        (
            5,
            cu::tmap(vec![("up", cu::vbool(true)), ("uv", cu::vbool(true))]),
        ),
    ]);
    let mut ga_msg = vec![crate::ctap2::CMD_GET_ASSERTION];
    ga_msg.extend_from_slice(&cu::encode(&ga_params));
    let (_cmd, resp) = client.exchange(&mut auth, &mut transport, cid, ctaphid::CMD_CBOR, &ga_msg)?;
    let ga = cu::decode(expect_status0(&resp)?).map_err(|e| e)?;
    let resp_cred = cu::get_int_key(&ga, 1).ok_or("getAssertion: missing credential")?;
    let resp_cred_id = cu::get_text_key(resp_cred, "id")
        .and_then(cu::as_bytes)
        .ok_or("getAssertion: credential has no id")?;
    if resp_cred_id != credential_id.as_slice() {
        return Err("getAssertion: credential id mismatch".into());
    }
    let assert_auth_data = cu::get_int_key(&ga, 2)
        .and_then(cu::as_bytes)
        .ok_or("getAssertion: missing authData")?
        .to_vec();
    let signature = cu::get_int_key(&ga, 3)
        .and_then(cu::as_bytes)
        .ok_or("getAssertion: missing signature")?
        .to_vec();
    if assert_auth_data.len() != 37 {
        return Err("getAssertion: authData must be 37 bytes".into());
    }
    if assert_auth_data[..32] != crate::sha256(b"example.com") {
        return Err("getAssertion: authData rpIdHash mismatch".into());
    }
    if assert_auth_data[32] != 0x05 {
        return Err("getAssertion: expected flags 0x05".into());
    }
    let sign_count = u32::from_be_bytes(assert_auth_data[33..37].try_into().unwrap());
    if sign_count != 1 {
        return Err(format!("getAssertion: expected signCount 1, got {sign_count}"));
    }
    // The actual signature check, with the p256 verifying key.
    let mut signed = assert_auth_data.clone();
    signed.extend_from_slice(&client_data_hash_2);
    if !verify_der_signature(&verifying_key, &signed, &signature) {
        return Err("getAssertion: signature verification FAILED".into());
    }
    log.push("getAssertion ok: signCount=1, DER signature verified with credential public key".into());

    // Keep PACKET_SIZE referenced (packet size sanity).
    debug_assert_eq!(PACKET_SIZE, 64);
    Ok(log)
}
