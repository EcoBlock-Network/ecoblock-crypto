use ed25519_dalek::{Verifier, Signature as DalekSignature, VerifyingKey};
use base64::{engine::general_purpose, Engine as _};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature(pub String);

impl Signature {
    pub fn verify(&self, public_key_b64: &str, payload: &[u8]) -> bool {
        let signature_bytes = match general_purpose::STANDARD.decode(&self.0) {
            Ok(sig) => sig,
            Err(_) => {
                return false;
            }
        };

        let public_key_bytes = match general_purpose::STANDARD.decode(public_key_b64) {
            Ok(pk) => pk,
            Err(_) => {
                return false;
            }
        };

        let public_key_array: [u8; 32] = match public_key_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                return false;
            }
        };

        let signature_array: [u8; 64] = match signature_bytes.try_into() {
            Ok(arr) => arr,
            Err(_) => {
                return false;
            }
        };

        let verifying_key = match VerifyingKey::from_bytes(&public_key_array) {
            Ok(key) => key,
            Err(_) => {
                return false;
            }
        };

        let dalek_signature = match DalekSignature::try_from(&signature_array[..]) {
            Ok(sig) => sig,
            Err(_) => {
            return false;
            }
        };

        let result = verifying_key.verify(payload, &dalek_signature).is_ok();
        if !result {
        }
        result
    }
}
