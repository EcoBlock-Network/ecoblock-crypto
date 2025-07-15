use base64::Engine;
use ed25519_dalek::{
    SigningKey, VerifyingKey, Signature, Signer, Verifier, SignatureError
};
use rand::rngs::OsRng;
use rand::RngCore;
use crate::signature::Signature as WrappedSignature;

#[derive(Debug, Clone)]
pub struct CryptoKeypair {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl CryptoKeypair {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let mut seed = [0u8; 32];
        csprng.fill_bytes(&mut seed);

        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = VerifyingKey::from(&signing_key);

        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn sign(&self, message: &[u8]) -> WrappedSignature {
        let raw_signature = self.signing_key.sign(message);
        let encoded = base64::engine::general_purpose::STANDARD.encode(raw_signature.to_bytes());
        WrappedSignature(encoded)
    }
    
    pub fn public_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.verifying_key.verify(message, signature)
    }
}
