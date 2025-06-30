use base64::Engine;
use ecoblock_crypto::{keys::keypair::CryptoKeypair};

#[test]
fn test_signature_verification_with_dalek() {
    let keypair = CryptoKeypair::generate();
    let message = b"ecoblock dalek verification test";

    let signature = keypair.sign(message);
    let public_key_b64 = base64::engine::general_purpose::STANDARD
        .encode(keypair.public_key().as_bytes());

    let result = signature.verify(&public_key_b64, message);

    assert!(
        result,
        "The signature should be valid for the given message"
    );
}

#[test]
fn test_signature_verification_with_dalek_fail() {
    let keypair = CryptoKeypair::generate();
    let message = b"ecoblock dalek verification test";
    let tampered_message = b"tampered message";

    let signature = keypair.sign(message);
    let public_key_b64 = base64::engine::general_purpose::STANDARD
        .encode(keypair.public_key().as_bytes());

    let result = signature.verify(&public_key_b64, tampered_message);

    assert!(
        !result,
        "The signature should not be valid for the tampered message"
    );
}
