//! ML-DSA-65 test-vector generator for FFI consumers' integration tests.
//! Prints a base64 (seed, public key, message, signature) vector made with this
//! crate's own signing API, so it exercises exactly what `mldsa65_sign` ships.
//! Run: `cargo run --example gen_vector`.
//!
//! The seed is fixed (32 bytes of 0x2a — a test value, never a credential), so
//! `SEED` and `PK` are the same on every run. Signing is hedged, so `SIG`
//! differs on every run but always verifies: a consumer's test must verify it,
//! not compare it.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use mldsa_verify::{public_key_from_seed, sign, verify, SEED_LEN};

fn main() {
    let seed = [0x2au8; SEED_LEN];
    let msg = b"mldsa-verify-vector";
    let pk = public_key_from_seed(&seed);
    let sig = sign(&seed, msg).expect("OS randomness");
    assert!(verify(&pk, msg, &sig));
    println!("SEED={}", STANDARD.encode(seed));
    println!("PK={}", STANDARD.encode(pk));
    println!("MSG={}", String::from_utf8_lossy(msg));
    println!("SIG={}", STANDARD.encode(sig));
}
