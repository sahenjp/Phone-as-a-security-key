//! Small helpers around ciborium's `Value` for CTAP2 messages.

use ciborium::value::{Integer, Value};

pub fn vint(x: i64) -> Value {
    Value::Integer(Integer::from(x))
}

pub fn vbytes(b: impl Into<Vec<u8>>) -> Value {
    Value::Bytes(b.into())
}

pub fn vtext(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

pub fn vbool(b: bool) -> Value {
    Value::Bool(b)
}

/// Build a CBOR map with integer keys from (key, value) pairs.
pub fn imap(pairs: Vec<(i64, Value)>) -> Value {
    Value::Map(pairs.into_iter().map(|(k, v)| (vint(k), v)).collect())
}

/// Build a CBOR map with text keys.
pub fn tmap(pairs: Vec<(&str, Value)>) -> Value {
    Value::Map(
        pairs
            .into_iter()
            .map(|(k, v)| (vtext(k), v))
            .collect(),
    )
}

pub fn encode(value: &Value) -> Vec<u8> {
    let normalized = canonicalize(value);
    let mut out = Vec::new();
    ciborium::ser::into_writer(&normalized, &mut out)
        .expect("CBOR encode into Vec cannot fail");
    out
}

fn raw_encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).expect("CBOR encode into Vec cannot fail");
    out
}

/// Return a copy of `value` with every map's entries sorted in canonical
/// CBOR order: by encoded key length first, then bytewise (RFC 7049 /
/// CTAP2 canonical encoding). Map insertion order is NOT canonical in
/// general (e.g. a text-keyed map inserted as {"type", "alg"} must be
/// emitted {"alg", "type"}), and some clients enforce this strictly —
/// Chromium rejects a GetInfo response with out-of-order keys and
/// misclassifies the authenticator as U2F-only.
fn canonicalize(value: &Value) -> Value {
    match value {
        Value::Map(pairs) => {
            let mut keyed: Vec<(Vec<u8>, Value, Value)> = pairs
                .iter()
                .map(|(k, v)| {
                    let kv = canonicalize(k);
                    (raw_encode(&kv), kv, canonicalize(v))
                })
                .collect();
            keyed.sort_by(|a, b| {
                a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0))
            });
            Value::Map(keyed.into_iter().map(|(_, k, v)| (k, v)).collect())
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(canonicalize).collect())
        }
        other => other.clone(),
    }
}

pub fn decode(bytes: &[u8]) -> Result<Value, String> {
    ciborium::de::from_reader(bytes).map_err(|e| format!("CBOR decode: {e}"))
}

fn as_map(v: &Value) -> Option<&Vec<(Value, Value)>> {
    match v {
        Value::Map(m) => Some(m),
        _ => None,
    }
}

pub fn get_int_key<'a>(map: &'a Value, key: i64) -> Option<&'a Value> {
    let want = vint(key);
    as_map(map)?.iter().find(|(k, _)| *k == want).map(|(_, v)| v)
}

pub fn get_text_key<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    let want = vtext(key);
    as_map(map)?.iter().find(|(k, _)| *k == want).map(|(_, v)| v)
}

pub fn as_bytes(v: &Value) -> Option<&[u8]> {
    match v {
        Value::Bytes(b) => Some(b),
        _ => None,
    }
}

pub fn as_text(v: &Value) -> Option<&str> {
    match v {
        Value::Text(t) => Some(t),
        _ => None,
    }
}

pub fn as_int(v: &Value) -> Option<i64> {
    match v {
        Value::Integer(i) => {
            let wide: i128 = (*i).into();
            i64::try_from(wide).ok()
        }
        _ => None,
    }
}

pub fn as_bool(v: &Value) -> Option<bool> {
    match v {
        Value::Bool(b) => Some(*b),
        _ => None,
    }
}

pub fn as_array(v: &Value) -> Option<&[Value]> {
    match v {
        Value::Array(a) => Some(a),
        _ => None,
    }
}

/// COSE_Key for an ES256 public key: `{1:2, 3:-7, -1:1, -2:x, -3:y}`, CBOR-encoded.
pub fn cose_key_es256(x: &[u8], y: &[u8]) -> Vec<u8> {
    assert_eq!(x.len(), 32);
    assert_eq!(y.len(), 32);
    encode(&imap(vec![
        (1, vint(2)),   // kty: EC2
        (3, vint(-7)),  // alg: ES256
        (-1, vint(1)),  // crv: P-256
        (-2, vbytes(x.to_vec())),
        (-3, vbytes(y.to_vec())),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbor_roundtrip_nested() {
        let v = imap(vec![
            (1, vtext("none")),
            (
                2,
                vbytes(vec![1u8, 2, 3]),
            ),
            (
                4,
                tmap(vec![("id", vbytes(vec![9u8; 4])), ("name", vtext("sahen"))]),
            ),
            (5, Value::Array(vec![vint(-7), vbool(true)])),
        ]);
        let bytes = encode(&v);
        let back = decode(&bytes).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn cose_key_swift_known_vector() {
        // Shared with Swift BridgeCoreTests.testCOSEKeyEncoding:
        // x = 00..1f, y = 20..3f.
        let x: Vec<u8> = (0u8..32).collect();
        let y: Vec<u8> = (32u8..64).collect();
        let enc = cose_key_es256(&x, &y);
        let hex: String = enc.iter().map(|b| format!("{b:02x}")).collect();
        let expected = "a5010203262001215820".to_string()
            + "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            + "225820"
            + "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
        assert_eq!(hex, expected);
    }

    #[test]
    fn cose_key_layout() {
        let x = [0xAAu8; 32];
        let y = [0xBBu8; 32];
        let enc = cose_key_es256(&x, &y);
        let decoded = decode(&enc).unwrap();
        assert_eq!(as_int(get_int_key(&decoded, 1).unwrap()), Some(2));
        assert_eq!(as_int(get_int_key(&decoded, 3).unwrap()), Some(-7));
        assert_eq!(as_int(get_int_key(&decoded, -1).unwrap()), Some(1));
        assert_eq!(as_bytes(get_int_key(&decoded, -2).unwrap()).unwrap(), &x);
        assert_eq!(as_bytes(get_int_key(&decoded, -3).unwrap()).unwrap(), &y);
    }
    #[test]
    fn encode_sorts_map_keys_canonically() {
        // {"type": "public-key", "alg": -7} inserted in that order must be
        // emitted as {"alg": -7, "type": "public-key"}: canonical order is
        // by encoded key length, then bytewise ("alg" is shorter).
        let v = tmap(vec![
            ("type", vtext("public-key")),
            ("alg", vint(-7)),
        ]);
        let bytes = encode(&v);
        // a2 63 616c67 26 64 74797065 6a 7075626c69632d6b6579
        assert_eq!(
            bytes,
            vec![
                0xA2, 0x63, b'a', b'l', b'g', 0x26, 0x64, b't', b'y', b'p', b'e', 0x6A,
                b'p', b'u', b'b', b'l', b'i', b'c', b'-', b'k', b'e', b'y'
            ]
        );
    }

    #[test]
    fn encode_sorts_int_keys_canonically() {
        let v = imap(vec![(0x0A, vint(1)), (0x01, vint(2)), (0x03, vint(3))]);
        let bytes = encode(&v);
        assert_eq!(bytes, vec![0xA3, 0x01, 0x02, 0x03, 0x03, 0x0A, 0x01]);
    }

}
