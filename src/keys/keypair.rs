use ed25519_dalek::{Keypair, PublicKey, SecretKey, SignatureError, Signer, Verifier, Signature};
use rand::rngs::OsRng;

pub struct CryptoKeypair {
    pub keypair: Keypair,
}

impl CryptoKeypair {
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);
        Self { keypair }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.keypair.sign(message)
    }

    pub fn public_key(&self) -> PublicKey {
        self.keypair.public
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.keypair.public.verify(message, signature)
    }
}
