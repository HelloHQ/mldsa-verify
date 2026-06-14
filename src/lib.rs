//! Verify-only ML-DSA-65 (FIPS 204) over a C ABI.
//!
//! A thin, embeddable wrapper around the RustCrypto [`ml-dsa`] crate exposing a
//! single C entry point, [`mldsa65_verify`], for FFI consumers (Dart/Flutter,
//! Swift, Kotlin/JNI, …). Verification touches only *public* data (public key,
//! message, signature) — there is no secret material and no side-channel
//! surface, which is what makes a small wrapper appropriate to embed widely.
//!
//! **Interop:** verifies **pure ML-DSA** (not HashML-DSA/prehash) with an
//! **empty context**, which is what Google Cloud KMS's `ML-DSA-65` and other
//! FIPS-204 signers produce by default. The public key is the raw 1952-byte
//! FIPS-204 encoding; the signature is the raw 3309-byte encoding.
//!
//! [`ml-dsa`]: https://crates.io/crates/ml-dsa

use ml_dsa::{EncodedSignature, EncodedVerifyingKey, MlDsa65, Signature, VerifyingKey};

/// FIPS 204 ML-DSA-65 sizes.
const PK_LEN: usize = 1952;
const SIG_LEN: usize = 3309;

/// Pure verification core. Returns true iff `sig` is a valid ML-DSA-65 signature
/// over `msg` (empty context) for `pk`. Wrong-length or malformed inputs → false
/// (fail closed). No panics for well-formed-length inputs.
fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    if pk.len() != PK_LEN || sig.len() != SIG_LEN {
        return false;
    }
    let Ok(enc_vk) = EncodedVerifyingKey::<MlDsa65>::try_from(pk) else {
        return false;
    };
    let Ok(enc_sig) = EncodedSignature::<MlDsa65>::try_from(sig) else {
        return false;
    };
    let Some(signature) = Signature::<MlDsa65>::decode(&enc_sig) else {
        return false;
    };
    let vk = VerifyingKey::<MlDsa65>::decode(&enc_vk);
    vk.verify_with_context(msg, &[], &signature)
}

/// Verify an ML-DSA-65 signature over a message (pure ML-DSA, empty context).
///
/// Returns `1` if valid, `0` otherwise — invalid signature, wrong-length inputs
/// (`pk` must be 1952 bytes, `sig` 3309), null pointers, or an internal panic.
/// Never unwinds across the FFI boundary.
///
/// # Safety
/// `pk_ptr`/`msg_ptr`/`sig_ptr` must each point to at least the corresponding
/// `*_len` readable bytes, or be null (treated as invalid — except a zero-length
/// message may pass a null `msg_ptr`).
#[no_mangle]
pub unsafe extern "C" fn mldsa65_verify(
    pk_ptr: *const u8,
    pk_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_ptr: *const u8,
    sig_len: usize,
) -> i32 {
    if pk_ptr.is_null() || sig_ptr.is_null() || (msg_ptr.is_null() && msg_len != 0) {
        return 0;
    }
    let result = std::panic::catch_unwind(|| {
        let pk = unsafe { std::slice::from_raw_parts(pk_ptr, pk_len) };
        let sig = unsafe { std::slice::from_raw_parts(sig_ptr, sig_len) };
        let msg: &[u8] = if msg_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) }
        };
        verify(pk, msg, sig)
    });
    match result {
        Ok(true) => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ml_dsa::signature::Signer;
    use ml_dsa::{Generate, Keypair, SigningKey};

    fn signed(msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let sk = SigningKey::<MlDsa65>::generate();
        let sig = sk.sign(msg);
        let pk = sk.verifying_key().encode().to_vec();
        let sigb = sig.encode().to_vec();
        assert_eq!(pk.len(), PK_LEN);
        assert_eq!(sigb.len(), SIG_LEN);
        (pk, sigb)
    }

    #[test]
    fn valid_signature_verifies() {
        let msg = b"mldsa-verify";
        let (pk, sig) = signed(msg);
        assert!(verify(&pk, msg, &sig));
    }

    #[test]
    fn tampered_message_fails() {
        let (pk, sig) = signed(b"original message");
        assert!(!verify(&pk, b"tampered message", &sig));
    }

    #[test]
    fn tampered_signature_fails() {
        let msg = b"msg";
        let (pk, mut sig) = signed(msg);
        sig[0] ^= 0xFF;
        assert!(!verify(&pk, msg, &sig));
    }

    #[test]
    fn wrong_key_fails() {
        let msg = b"msg";
        let (_pk, sig) = signed(msg);
        let (other_pk, _) = signed(msg);
        assert!(!verify(&other_pk, msg, &sig));
    }

    #[test]
    fn wrong_lengths_fail_closed() {
        let msg = b"msg";
        let (pk, sig) = signed(msg);
        assert!(!verify(&pk[..PK_LEN - 1], msg, &sig));
        assert!(!verify(&pk, msg, &sig[..SIG_LEN - 1]));
        assert!(!verify(&[], msg, &sig));
    }

    #[test]
    fn empty_message_round_trips() {
        let (pk, sig) = signed(b"");
        assert!(verify(&pk, b"", &sig));
    }

    // ── Static known-answer tests (Wycheproof, independent vectors) ──────────
    // Unlike the round-trip tests above, these use fixed bytes produced by
    // Google/C2SP's signer — not by this crate — so they prove cross-impl
    // interop and pin the FIPS-204 byte encoding: a future `ml-dsa` bump that
    // changed the layout would fail here even though the round-trips still pass.
    const KAT: &str = include_str!("../tests/vectors/wycheproof_mldsa65_verify.hex");

    fn decode_hex(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "odd hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
            .collect()
    }

    fn kat_field(name: &str) -> Vec<u8> {
        let prefix = format!("{name}=");
        let line = KAT
            .lines()
            .find(|l| l.starts_with(&prefix))
            .unwrap_or_else(|| panic!("KAT field {name} missing"));
        decode_hex(&line[prefix.len()..])
    }

    #[test]
    fn wycheproof_baseline_vector_verifies() {
        let (pk, msg, sig) = (
            kat_field("valid.pk"),
            kat_field("valid.msg"),
            kat_field("valid.sig"),
        );
        assert_eq!(pk.len(), PK_LEN);
        assert_eq!(sig.len(), SIG_LEN);
        assert!(verify(&pk, &msg, &sig), "Wycheproof baseline must verify");
    }

    #[test]
    fn wycheproof_modified_signature_rejected() {
        // tcId 8: a valid signature with a bit flipped in c~ (ModifiedSignature).
        let (pk, msg, sig) = (
            kat_field("invalid.pk"),
            kat_field("invalid.msg"),
            kat_field("invalid.sig"),
        );
        assert_eq!(sig.len(), SIG_LEN, "full-length forgery, not a length reject");
        assert!(!verify(&pk, &msg, &sig), "modified signature must be rejected");
    }
}
