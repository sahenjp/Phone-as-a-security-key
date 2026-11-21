use iphone_fido::{cbor_util, ecdsa_rs_to_der, phone};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

#[test]
fn fixed_key_wire_encoding() {
    let key = SigningKey::from_slice(&[1; 32]).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    let signature: Signature = key.sign(b"phone-fido crypto compatibility");
    let rs: [u8; 64] = signature.to_bytes().into();
    let der = ecdsa_rs_to_der(&rs);
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    // Captured with p256 0.13.2.
    assert_eq!(hex(point.as_bytes()), "046ff03b949241ce1dadd43519e6960e0a85b41a69a05c328103aa2bce1594ca163c4f753a55bf01dc53f6c0b0c7eee78b40c6ff7d25a96e2282b989cef71c144a");
    assert_eq!(hex(&rs), "e2641040c643a39c6b5bac0b348c21c3025604c2c15cddde31d4693f6c0033593c137f2f337e1ad636e83f55aec89c6eae0a8fee2c103879dd56739534d2c113");
    assert_eq!(hex(&der), "3045022100e2641040c643a39c6b5bac0b348c21c3025604c2c15cddde31d4693f6c00335902203c137f2f337e1ad636e83f55aec89c6eae0a8fee2c103879dd56739534d2c113");
    let cose = cbor_util::cose_key_es256(&point.as_bytes()[1..33], &point.as_bytes()[33..]);
    assert_eq!(hex(&cose), "a50102032620012158206ff03b949241ce1dadd43519e6960e0a85b41a69a05c328103aa2bce1594ca162258203c4f753a55bf01dc53f6c0b0c7eee78b40c6ff7d25a96e2282b989cef71c144a");
    assert!(phone::verify_der_signature(
        key.verifying_key(),
        b"phone-fido crypto compatibility",
        &der
    ));
}
