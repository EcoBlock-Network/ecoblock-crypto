# ecoblock-crypto

Provides cryptographic primitives for secure, verifiable and interoperable data exchange within the Ecoblock platform.

Purpose
-------
- Offer signature generation and verification primitives (Ed25519), keypair management and utilities.
- Provide deterministic hashing utilities used across the workspace (e.g. for IDs or canonical payloads).
- Support key serialization / deserialization and safe persistence helpers used by bridge and storage layers.

What lives here
---------------
- `src/keys` — keypair generation, serialization, conversion helpers and key file formats.
- `src/signature` — signing and verification helpers, signature type wrappers and error handling.
- `src/hash` — hashing utilities used for canonical IDs and integrity checks.

Stability contract
------------------
- Public key and signature encoding (hex/base64) must remain stable across releases unless a migration plan is provided.
- Algorithms choices (e.g. Ed25519) and canonical encodings used for signature verification are part of the compatibility contract. Changing them requires a documented migration and compatibility tests.

Quick example
-------------
Sign a payload and verify it (conceptual example):

```rust
use ecoblock_crypto::keys::keypair::CryptoKeypair;

let kp = CryptoKeypair::generate();
let payload = b"canonical-bytes".to_vec();
let sig = kp.sign(&payload);
assert!(kp.verify(&payload, &sig));
```

Running tests
-------------
Run the crate tests locally:

```bash
cd libs/ecoblock-crypto
cargo test
```

Contributing
------------
- Keep encodings and canonical formats stable. If you need to change an encoding, add regression vectors and tests for both old and new formats.
- Add unit tests for any new key or signature helper and include round-trip tests (generate -> serialize -> deserialize -> sign -> verify).

License
-------
MIT
