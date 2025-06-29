use ecoblock_crypto::keys::keypair::CryptoKeypair;
use ed25519_dalek::Signer;

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
