use base64::Engine;
use ecoblock_crypto::{keys::keypair::CryptoKeypair, signature::Signature};

#[test]
fn test_sign_and_verify() {
    let keypair = CryptoKeypair::generate();
    let message = b"hello_ecoblock";

    let signature = keypair.sign(message);
    let result = keypair.verify(message, &signature);

    assert!(result.is_ok());
}

#[test]
fn test_invalid_signature_fails() {
    let keypair1 = CryptoKeypair::generate();
    let keypair2 = CryptoKeypair::generate();
    let message = b"tampered_data";

    let signature = keypair1.sign(message);
    let result = keypair2.verify(message, &signature);

    assert!(result.is_err());
}

#[test]
fn test_signature_verification() {
    let keypair = CryptoKeypair::generate();
    let message = b"ecoblock data integrity test";

    // Signature
    let signature = keypair.sign(message); // signature est de type ecoblock_crypto::Signature
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()); // Encode the signature as base64

    let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(
        keypair.public_key().as_bytes()
    );

    println!("Message: {:?}", String::from_utf8_lossy(message));
    println!("Public Key (base64): {}", public_key_b64);
    println!("Signature (base64): {}", signature_b64);

    let signature = Signature(signature_b64);
    let result = signature.verify(&public_key_b64, message);

    println!("Résultat de la vérification : {}", result);
    assert!(result, "La signature aurait dû être valide");
}

#[test]
fn test_signature_verification_fail() {
    let keypair = CryptoKeypair::generate();
    let message = b"ecoblock data integrity test";
    let fake_message = b"altered message";

    let signature = keypair.sign(message);
    let signature_b64 = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());

    let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(
        keypair.public_key().as_bytes()
    );

    println!("Public Key (base64): {}", public_key_b64);
    println!("Signature (base64): {}", signature_b64);
    println!("Fake message: {:?}", String::from_utf8_lossy(fake_message));

    let signature = Signature(signature_b64);
    let result = signature.verify(&public_key_b64, fake_message);

    println!("Résultat de la vérification (fail attendu) : {}", result);
    assert!(!result, "La signature ne devrait pas être valide avec un message altéré");
}
