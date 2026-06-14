//! One-off ML-DSA-65 test-vector generator. Prints a base64 (public key,
//! message, signature) triple for FFI consumers' integration tests.
//! Run: `cargo run --example gen_vector`. Signing is randomized, so each run
//! prints a different—but valid—vector; capture one and embed it.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ml_dsa::signature::Signer;
use ml_dsa::{Generate, Keypair, MlDsa65, SigningKey};

fn main() {
    let sk = SigningKey::<MlDsa65>::generate();
    let msg = b"mldsa-verify-vector";
    let sig = sk.sign(msg);
    println!(
        "PK={}",
        STANDARD.encode(sk.verifying_key().encode().as_slice())
    );
    println!("MSG={}", String::from_utf8_lossy(msg));
    println!("SIG={}", STANDARD.encode(sig.encode().as_slice()));
}
