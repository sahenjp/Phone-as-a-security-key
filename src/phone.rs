//! The `Phone` abstraction: semantic operations from BRIDGE-PROTOCOL.md
//! section 3. The phone never sees CTAP; it builds authData itself and
//! signs only after explicit user approval + Face ID (on the real device).
//!
//! Two implementations:
//! - [`TcpPhone`]: the real bridge client (encrypted session to the iPhone).
//! - [`MockPhone`]: development-only software phone with in-memory P-256
//!   keys. Enabled only via the explicit `--mock-phone` flag.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use serde_json::{json, Value};

use crate::bridge::{self, BridgeSession};
use crate::cbor_util;
use crate::AAGUID;

// ------------------------------------------------------------------ types

#[derive(Debug, Clone)]
pub struct PhoneError {
    /// One of the protocol error codes (user_cancelled, no_credentials,
    /// not_found, internal, bad_request) or a local transport description.
    pub code: String,
    pub message: String,
}

impl PhoneError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new("internal", message)
    }
}

impl std::fmt::Display for PhoneError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "phone error [{}]: {}", self.code, self.message)
    }
}
impl std::error::Error for PhoneError {}

pub type PhoneResult<T> = Result<T, PhoneError>;

#[derive(Debug, Clone)]
pub struct CreateCredentialRequest {
    pub rp_id: String,
    pub rp_name: Option<String>,
    pub user_id: Vec<u8>,
    pub user_name: Option<String>,
    pub user_display_name: Option<String>,
    pub client_data_hash: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct CreateCredentialResponse {
    pub credential_id: Vec<u8>,
    pub public_key_x963: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub fmt: String,
}

#[derive(Debug, Clone)]
pub struct GetAssertionRequest {
    pub rp_id: String,
    pub client_data_hash: [u8; 32],
    pub allow_credential_ids: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct GetAssertionResponse {
    pub credential_id: Vec<u8>,
    pub auth_data: Vec<u8>,
    pub signature: Vec<u8>, // ASN.1 DER
    pub user_handle: Vec<u8>,
    pub user_name: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CredentialInfo {
    pub rp_id: String,
    pub user_name: Option<String>,
    pub credential_id: Vec<u8>,
}

pub trait Phone {
    fn ping(&mut self) -> PhoneResult<Value>;
    fn create_credential(
        &mut self,
        req: &CreateCredentialRequest,
    ) -> PhoneResult<CreateCredentialResponse>;
    fn get_assertion(&mut self, req: &GetAssertionRequest) -> PhoneResult<GetAssertionResponse>;
    fn list_credentials(&mut self) -> PhoneResult<Vec<CredentialInfo>>;
    /// Periodic upkeep while the daemon is idle. TcpPhone uses it to
    /// keep one warm bridge session: connect as soon as the phone
    /// appears and notice when it goes away, so plugging the phone in
    /// is all the user has to do. Default: nothing to maintain.
    fn maintain(&mut self) {}
}

// ------------------------------------------------------- authData helpers
// These mirror exactly what the phone does (BRIDGE-PROTOCOL.md 3.2/3.3).
// The PC never builds authData for real operations; MockPhone uses these
// because it plays the phone's role.

pub fn build_attested_auth_data(
    rp_id: &str,
    credential_id: &[u8],
    public_key_x963: &[u8; 65],
) -> Vec<u8> {
    assert_eq!(public_key_x963[0], 0x04, "x9.63 uncompressed point");
    let mut out = Vec::new();
    out.extend_from_slice(&crate::sha256(rp_id.as_bytes()));
    out.push(0x45); // UP | UV | AT
    out.extend_from_slice(&0u32.to_be_bytes()); // sign_count = 0
    out.extend_from_slice(&AAGUID);
    out.extend_from_slice(&(credential_id.len() as u16).to_be_bytes());
    out.extend_from_slice(credential_id);
    out.extend_from_slice(&cbor_util::cose_key_es256(
        &public_key_x963[1..33],
        &public_key_x963[33..65],
    ));
    out
}

pub fn build_assertion_auth_data(rp_id: &str, sign_count: u32) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&crate::sha256(rp_id.as_bytes()));
    out.push(0x05); // UP | UV
    out.extend_from_slice(&sign_count.to_be_bytes());
    out
}

// ---------------------------------------------------------------- MockPhone

struct MockCredential {
    signing_key: SigningKey,
    rp_id: String,
    user_id: Vec<u8>,
    user_name: Option<String>,
    sign_count: u32,
}

/// Software phone for development. Keys are ordinary in-memory P-256
/// keys — NOT Secure Enclave, NOT biometry-protected. Never ship
/// credentials made by this implementation as if they were real.
pub struct MockPhone {
    credentials: HashMap<Vec<u8>, MockCredential>,
    order: Vec<Vec<u8>>,
}

impl MockPhone {
    pub fn new() -> Self {
        Self {
            credentials: HashMap::new(),
            order: Vec::new(),
        }
    }

    fn x963(key: &VerifyingKey) -> [u8; 65] {
        let point = key.to_encoded_point(false);
        let bytes = point.as_bytes();
        let mut out = [0u8; 65];
        out.copy_from_slice(bytes);
        out
    }
}

impl Default for MockPhone {
    fn default() -> Self {
        Self::new()
    }
}

impl Phone for MockPhone {
    fn ping(&mut self) -> PhoneResult<Value> {
        Ok(json!({"app": "iphone-fido", "version": 1}))
    }

    fn create_credential(
        &mut self,
        req: &CreateCredentialRequest,
    ) -> PhoneResult<CreateCredentialResponse> {
        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let mut credential_id = vec![0u8; 32];
        crate::fill_random(&mut credential_id);
        let public_key_x963 = Self::x963(signing_key.verifying_key());
        let auth_data =
            build_attested_auth_data(&req.rp_id, &credential_id, &public_key_x963);
        self.order.push(credential_id.clone());
        self.credentials.insert(
            credential_id.clone(),
            MockCredential {
                signing_key,
                rp_id: req.rp_id.clone(),
                user_id: req.user_id.clone(),
                user_name: req.user_name.clone(),
                sign_count: 0,
            },
        );
        Ok(CreateCredentialResponse {
            credential_id,
            public_key_x963: public_key_x963.to_vec(),
            auth_data,
            fmt: "none".to_string(),
        })
    }

    fn get_assertion(&mut self, req: &GetAssertionRequest) -> PhoneResult<GetAssertionResponse> {
        // Find a credential for this rp_id, honoring the allow list.
        let mut chosen: Option<Vec<u8>> = None;
        if req.allow_credential_ids.is_empty() {
            for id in &self.order {
                if self.credentials.get(id).map(|c| &c.rp_id) == Some(&req.rp_id) {
                    chosen = Some(id.clone());
                    break;
                }
            }
        } else {
            for id in &req.allow_credential_ids {
                if let Some(c) = self.credentials.get(id) {
                    if c.rp_id == req.rp_id {
                        chosen = Some(id.clone());
                        break;
                    }
                }
            }
        }
        let credential_id = chosen.ok_or_else(|| {
            PhoneError::new("no_credentials", "no credential matches this rp_id / allow list")
        })?;
        let cred = self.credentials.get_mut(&credential_id).unwrap();
        cred.sign_count += 1;
        let auth_data = build_assertion_auth_data(&req.rp_id, cred.sign_count);
        let mut to_sign = auth_data.clone();
        to_sign.extend_from_slice(&req.client_data_hash);
        let signature: Signature = cred.signing_key.sign(&to_sign);
        let der = crate::ecdsa_rs_to_der(&signature.to_bytes().into());
        Ok(GetAssertionResponse {
            credential_id,
            auth_data,
            signature: der,
            user_handle: cred.user_id.clone(),
            user_name: cred.user_name.clone(),
        })
    }

    fn list_credentials(&mut self) -> PhoneResult<Vec<CredentialInfo>> {
        Ok(self
            .order
            .iter()
            .filter_map(|id| {
                self.credentials.get(id).map(|c| CredentialInfo {
                    rp_id: c.rp_id.clone(),
                    user_name: c.user_name.clone(),
                    credential_id: id.clone(),
                })
            })
            .collect())
    }
}

// ---------------------------------------------------------------- TcpPhone

/// The real phone, reached through an encrypted bridge session
/// (iproxy on 127.0.0.1:18766 by default).
pub struct TcpPhone {
    addr: String,
    psk: [u8; 32],
    session: Option<BridgeSession>,
    next_id: u64,
    last_activity: std::time::Instant,
}

impl TcpPhone {
    /// Create a phone handle without connecting. The bridge session is
    /// established lazily on the first request and re-established when it
    /// breaks: the iPhone app suspends whenever it is backgrounded or the
    /// phone locks, which kills the TCP session, so a session must never be
    /// treated as a permanent resource.
    pub fn new(addr: &str, psk: &[u8; 32]) -> Self {
        Self {
            addr: addr.to_string(),
            psk: *psk,
            session: None,
            next_id: 1,
            last_activity: std::time::Instant::now(),
        }
    }

    fn ensure_session(&mut self) -> PhoneResult<()> {
        if self.session.is_none() {
            let session = bridge::connect(&self.addr, &self.psk).map_err(|e| {
                PhoneError::internal(format!("bridge connect/handshake: {e}"))
            })?;
            self.session = Some(session);
        }
        Ok(())
    }

    fn request(&mut self, op: &str, mut params: Value) -> PhoneResult<Value> {
        let id = self.next_id;
        self.next_id += 1;
        if let Some(obj) = params.as_object_mut() {
            obj.insert("op".to_string(), json!(op));
            obj.insert("id".to_string(), json!(id));
        }
        self.ensure_session()?;
        let send_result = self
            .session
            .as_mut()
            .expect("session ensured")
            .send_json(&params);
        if let Err(e) = send_result {
            // The session is dead (the app was backgrounded or the phone
            // locked). The request did not complete sending, so reconnect
            // and retry exactly once on a fresh session.
            self.session = None;
            self.ensure_session().map_err(|_| {
                PhoneError::internal(format!("bridge send: {e}"))
            })?;
            self.session
                .as_mut()
                .expect("session ensured")
                .send_json(&params)
                .map_err(|e2| PhoneError::internal(format!("bridge send: {e2}")))?;
        }
        let res = match self.session.as_mut().expect("session ensured").recv_json() {
            Ok(v) => v,
            Err(e) => {
                // Drop the broken session and reconnect so the NEXT
                // request starts fresh; this request's outcome on the
                // phone is unknown, so surface the error instead of
                // retrying (a retry could duplicate a credential).
                self.session = None;
                let _ = self.ensure_session();
                return Err(PhoneError::internal(format!("bridge receive: {e}")));
            }
        };
        self.last_activity = std::time::Instant::now();
        if res.get("id").and_then(|v| v.as_u64()) != Some(id) {
            return Err(PhoneError::internal("bridge response id mismatch"));
        }
        match res.get("ok").and_then(|v| v.as_bool()) {
            Some(true) => Ok(res
                .get("result")
                .cloned()
                .unwrap_or(Value::Null)),
            Some(false) => {
                let code = res
                    .get("error")
                    .and_then(|v| v.as_str())
                    .unwrap_or("internal")
                    .to_string();
                Err(PhoneError::new(code.clone(), format!("phone returned error: {code}")))
            }
            None => Err(PhoneError::internal("bridge response missing ok field")),
        }
    }
}

fn resp_b64(result: &Value, field: &str) -> PhoneResult<Vec<u8>> {
    let s = result
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| PhoneError::internal(format!("response missing field {field}")))?;
    B64.decode(s)
        .map_err(|e| PhoneError::internal(format!("response field {field}: bad base64: {e}")))
}

impl Phone for TcpPhone {
    fn ping(&mut self) -> PhoneResult<Value> {
        self.request("ping", json!({}))
    }

    fn maintain(&mut self) {
        // No session: the phone may have just been plugged in or the app
        // (re)launched. Try to connect; failures are expected while the
        // phone is absent and are retried on the next tick.
        if self.session.is_none() {
            if self.ensure_session().is_ok() {
                eprintln!("phone: bridge session established");
                self.last_activity = std::time::Instant::now();
            }
            return;
        }
        // Session held but idle: ping to notice a dead one (USB pulled,
        // app suspended) so it is dropped and re-established instead of
        // failing the next real request.
        if self.last_activity.elapsed() >= std::time::Duration::from_secs(25) {
            if self.ping().is_err() {
                eprintln!("phone: bridge session lost; will reconnect");
                self.session = None;
            }
        }
    }

    fn create_credential(
        &mut self,
        req: &CreateCredentialRequest,
    ) -> PhoneResult<CreateCredentialResponse> {
        let result = self.request(
            "create_credential",
            json!({
                "rp_id": req.rp_id,
                "rp_name": req.rp_name,
                "user_id": B64.encode(&req.user_id),
                "user_name": req.user_name,
                "user_display_name": req.user_display_name,
                "client_data_hash": B64.encode(req.client_data_hash),
            }),
        )?;
        let fmt = result
            .get("fmt")
            .and_then(|v| v.as_str())
            .unwrap_or("none")
            .to_string();
        Ok(CreateCredentialResponse {
            credential_id: resp_b64(&result, "credential_id")?,
            public_key_x963: resp_b64(&result, "public_key_x963")?,
            auth_data: resp_b64(&result, "auth_data")?,
            fmt,
        })
    }

    fn get_assertion(&mut self, req: &GetAssertionRequest) -> PhoneResult<GetAssertionResponse> {
        let allow: Vec<String> = req
            .allow_credential_ids
            .iter()
            .map(|id| B64.encode(id))
            .collect();
        let result = self.request(
            "get_assertion",
            json!({
                "rp_id": req.rp_id,
                "client_data_hash": B64.encode(req.client_data_hash),
                "allow_credential_ids": allow,
            }),
        )?;
        Ok(GetAssertionResponse {
            credential_id: resp_b64(&result, "credential_id")?,
            auth_data: resp_b64(&result, "auth_data")?,
            signature: resp_b64(&result, "signature")?,
            user_handle: resp_b64(&result, "user_handle").unwrap_or_default(),
            // The bridge get_assertion result carries no display name;
            // the CTAP layer omits `name` when this is None.
            user_name: None,
        })
    }

    fn list_credentials(&mut self) -> PhoneResult<Vec<CredentialInfo>> {
        let result = self.request("list_credentials", json!({}))?;
        let arr = result
            .as_array()
            .ok_or_else(|| PhoneError::internal("list_credentials result is not an array"))?;
        let mut out = Vec::new();
        for item in arr {
            let rp_id = item
                .get("rp_id")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_string();
            let user_name = item
                .get("user_name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let credential_id = resp_b64(item, "credential_id")?;
            out.push(CredentialInfo {
                rp_id,
                user_name,
                credential_id,
            });
        }
        Ok(out)
    }
}

// Re-export so the CTAP layer can verify mock signatures in tests
// without depending on p256 paths in several places.
pub fn verifying_key_from_x963(x963: &[u8]) -> Option<VerifyingKey> {
    let point = p256::EncodedPoint::from_bytes(x963).ok()?;
    VerifyingKey::from_encoded_point(&point).ok()
}

pub fn verify_der_signature(key: &VerifyingKey, message: &[u8], der: &[u8]) -> bool {
    let rs = match crate::ecdsa_der_to_rs(der) {
        Some(rs) => rs,
        None => return false,
    };
    let signature = match Signature::from_slice(&rs) {
        Ok(s) => s,
        Err(_) => return false,
    };
    key.verify(message, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(start: u8, len: usize) -> Vec<u8> {
        (0..len).map(|i| start.wrapping_add(i as u8)).collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Shared with Swift BridgeCoreTests.testAuthDataForCreateKnownVector.
    #[test]
    fn attested_auth_data_swift_known_vector() {
        let mut x963 = [0u8; 65];
        x963[0] = 0x04;
        x963[1..33].copy_from_slice(&seq(0x00, 32));
        x963[33..65].copy_from_slice(&seq(0x20, 32));
        let credential_id = seq(0x50, 32);
        let auth_data = build_attested_auth_data("github.com", &credential_id, &x963);
        let expected = "3aeb002460381c6f258e8395d3026f571f0d9a76488dcd837639b13aed316560".to_string()
            + "45" + "00000000"
            + "6970682d6669646f2d30303030303031"
            + "0020"
            + "505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f"
            + "a5010203262001215820"
            + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            + "225820"
            + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
        assert_eq!(hex(&auth_data), expected);
    }

    #[test]
    fn mock_phone_create_and_assert() {
        let mut phone = MockPhone::new();
        let created = phone
            .create_credential(&CreateCredentialRequest {
                rp_id: "example.com".into(),
                rp_name: None,
                user_id: b"u1".to_vec(),
                user_name: Some("sahen".into()),
                user_display_name: None,
                client_data_hash: [1u8; 32],
            })
            .unwrap();
        let assertion = phone
            .get_assertion(&GetAssertionRequest {
                rp_id: "example.com".into(),
                client_data_hash: [2u8; 32],
                allow_credential_ids: vec![created.credential_id.clone()],
            })
            .unwrap();
        assert_eq!(assertion.auth_data[33..37], [0, 0, 0, 1]);
        let vk = verifying_key_from_x963(&created.public_key_x963).unwrap();
        let mut msg = assertion.auth_data.clone();
        msg.extend_from_slice(&[2u8; 32]);
        assert!(verify_der_signature(&vk, &msg, &assertion.signature));
        // Wrong rp gets no credentials.
        let err = phone
            .get_assertion(&GetAssertionRequest {
                rp_id: "other.example".into(),
                client_data_hash: [2u8; 32],
                allow_credential_ids: vec![],
            })
            .unwrap_err();
        assert_eq!(err.code, "no_credentials");
    }
}
