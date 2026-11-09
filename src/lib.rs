//! ML-DSA-65 (FIPS 204) signing and verification over a C ABI.
//!
//! A thin, embeddable wrapper around the RustCrypto [`ml-dsa`] crate. Rust
//! callers use the safe functions [`verify`], [`public_key_from_seed`] and
//! [`sign`]; FFI consumers (Dart/Flutter, Swift, Kotlin/JNI, …) use the C entry
//! points [`mldsa65_verify`], [`mldsa65_public_key_from_seed`] and
//! [`mldsa65_sign`].
//!
//! **Interop:** **pure ML-DSA** (not HashML-DSA/prehash, not external-μ) with an
//! **empty context**, which is what standard `ML-DSA-65` FIPS-204 signers
//! produce by default. The public key is the raw 1952-byte FIPS-204 encoding;
//! the signature is the raw 3309-byte encoding.
//!
//! **Keys:** a signing key is its 32-byte FIPS 204 key-generation seed ξ
//! (`ML-DSA.KeyGen_internal`, Algorithm 6). Signing expands the seed inside each
//! call and wipes the expanded key before returning, so the expanded secret key
//! never exists outside this library and never crosses the C boundary. How the
//! seed is made or stored is the caller's business.
//!
//! **Signing is hedged** (FIPS 204 Algorithm 2, the default): each signature
//! takes 32 fresh bytes from the operating system, so signing the same message
//! twice gives two different signatures, both valid. A verifier must not expect
//! a particular signature, only a valid one.
//!
//! [`ml-dsa`]: https://crates.io/crates/ml-dsa

use getrandom::rand_core::TryCryptoRng;
use getrandom::SysRng;
use ml_dsa::{
    EncodedSignature, EncodedVerifyingKey, ExpandedSigningKey, MlDsa65, Seed, Signature,
    VerifyingKey,
};

/// The length of an ML-DSA-65 signing seed ξ (FIPS 204).
pub const SEED_LEN: usize = 32;
/// The length of an ML-DSA-65 public key (FIPS 204 encoding).
pub const PK_LEN: usize = 1952;
/// The length of an ML-DSA-65 signature (FIPS 204 encoding).
pub const SIG_LEN: usize = 3309;

/// Why [`sign`] made no signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SignError {
    /// The operating system gave no randomness. Nothing was signed; retrying
    /// later is safe.
    Randomness,
}

impl core::fmt::Display for SignError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            SignError::Randomness => f.write_str("the OS random number generator failed"),
        }
    }
}

impl std::error::Error for SignError {}

/// Verify an ML-DSA-65 signature — the safe Rust API.
///
/// Returns `true` iff `sig` is a valid **pure ML-DSA-65** signature (empty
/// context) over `msg` for the public key `pk`. All inputs are the raw FIPS-204
/// byte encodings: `pk` is 1952 bytes, `sig` is 3309 bytes. Wrong-length or
/// otherwise malformed inputs return `false` (fail closed); never panics.
///
/// ```
/// # use mldsa_verify::verify;
/// // pk: 1952-byte FIPS-204 public key, sig: 3309-byte signature.
/// # let (pk, msg, sig): (&[u8], &[u8], &[u8]) = (&[], b"", &[]);
/// let ok = verify(pk, msg, sig);
/// # assert!(!ok); // empty inputs fail closed
/// ```
pub fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
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

/// The expanded signing key for `seed`. It wipes itself when dropped (the
/// `zeroize` feature of `ml-dsa`), and so does the intermediate key it is
/// cloned from.
fn expand(seed: &[u8; SEED_LEN]) -> ExpandedSigningKey<MlDsa65> {
    // A view of the caller's bytes, not a copy: no unwiped seed is left behind.
    ExpandedSigningKey::<MlDsa65>::from_seed(<&Seed>::from(seed))
}

/// The ML-DSA-65 public key of the 32-byte seed ξ — the safe Rust API.
///
/// `ML-DSA.KeyGen_internal(ξ)` (FIPS 204 Algorithm 6), encoded as the raw
/// 1952-byte public key. The same seed always gives the same key.
///
/// ```
/// # use mldsa_verify::{public_key_from_seed, sign, verify};
/// let seed = [7u8; 32]; // in real use: 32 secret, uniformly random bytes
/// let pk = public_key_from_seed(&seed);
/// let sig = sign(&seed, b"hello").unwrap();
/// assert!(verify(&pk, b"hello", &sig));
/// ```
#[must_use]
pub fn public_key_from_seed(seed: &[u8; SEED_LEN]) -> [u8; PK_LEN] {
    let key = expand(seed);
    let mut pk = [0u8; PK_LEN];
    pk.copy_from_slice(key.verifying_key().encode().as_slice());
    pk
}

/// Sign `msg` with the ML-DSA-65 key of the 32-byte seed ξ — the safe Rust API.
///
/// **Pure ML-DSA-65, empty context, hedged** (FIPS 204 Algorithm 2 with fresh
/// `rnd` from the OS). The result is the raw 3309-byte signature, which
/// [`verify`] accepts under [`public_key_from_seed`]`(seed)`. The key is
/// derived from the seed for this call and wiped before it returns.
///
/// # Errors
/// [`SignError::Randomness`] if the OS gives no randomness.
pub fn sign(seed: &[u8; SEED_LEN], msg: &[u8]) -> Result<[u8; SIG_LEN], SignError> {
    sign_with(seed, msg, &mut SysRng)
}

/// [`sign`] with `rnd` from `rng`. Production signing passes the OS generator;
/// only the tests pass anything else (all-zero `rnd`, which is FIPS 204's
/// deterministic variant, to reproduce known signatures byte for byte).
fn sign_with<R: TryCryptoRng + ?Sized>(
    seed: &[u8; SEED_LEN],
    msg: &[u8],
    rng: &mut R,
) -> Result<[u8; SIG_LEN], SignError> {
    let key = expand(seed);
    // The only error sign_randomized has with an empty context is the RNG's.
    let signature = key
        .sign_randomized(msg, &[], rng)
        .map_err(|_| SignError::Randomness)?;
    drop(key);
    let mut sig = [0u8; SIG_LEN];
    sig.copy_from_slice(signature.encode().as_slice());
    Ok(sig)
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

/// Write `bytes` to `out`, which the caller vouched is `N` writable bytes.
/// `ptr::copy` is a memmove, so an `out` that overlaps an input (a contract
/// breach) still gets the whole result, read before this write.
unsafe fn write_out<const N: usize>(out: *mut u8, bytes: &[u8; N]) {
    unsafe { std::ptr::copy(bytes.as_ptr(), out, N) };
}

/// The ML-DSA-65 public key of a 32-byte seed ξ (FIPS 204 Algorithm 6).
///
/// Writes the raw 1952-byte public key to `pk_out` and returns `1`. Returns `0`
/// and writes nothing else if `seed_ptr` or `pk_out` is null, `seed_len` is not
/// 32, `pk_out_len` is not 1952, or an internal panic was caught; `pk_out` is
/// then zero-filled whenever it is non-null and 1952 bytes long. Never unwinds
/// across the FFI boundary. The expanded key is wiped before return.
///
/// # Safety
/// `seed_ptr` must point to `seed_len` readable bytes and `pk_out` to
/// `pk_out_len` writable bytes, or be null (refused). `pk_out` must not overlap
/// the seed.
#[no_mangle]
pub unsafe extern "C" fn mldsa65_public_key_from_seed(
    seed_ptr: *const u8,
    seed_len: usize,
    pk_out: *mut u8,
    pk_out_len: usize,
) -> i32 {
    if pk_out.is_null() || pk_out_len != PK_LEN {
        return 0;
    }
    let result = if seed_ptr.is_null() || seed_len != SEED_LEN {
        None
    } else {
        std::panic::catch_unwind(|| {
            let seed = unsafe { &*seed_ptr.cast::<[u8; SEED_LEN]>() };
            public_key_from_seed(seed)
        })
        .ok()
    };
    match result {
        Some(pk) => {
            unsafe { write_out(pk_out, &pk) };
            1
        }
        None => {
            unsafe { std::ptr::write_bytes(pk_out, 0, PK_LEN) };
            0
        }
    }
}

/// Sign a message with the ML-DSA-65 key of a 32-byte seed ξ (pure ML-DSA,
/// empty context, hedged with 32 bytes of OS randomness).
///
/// Writes the raw 3309-byte signature to `sig_out` and returns `1`. Returns `0`
/// if `seed_ptr` or `sig_out` is null, `msg_ptr` is null with a non-zero
/// `msg_len`, `seed_len` is not 32, `sig_out_len` is not 3309, the OS gave no
/// randomness, or an internal panic was caught; `sig_out` is then zero-filled
/// whenever it is non-null and 3309 bytes long, so a caller that ignores the
/// return value sends no stale bytes. Never unwinds across the FFI boundary.
/// The signing key is derived from the seed inside this call and wiped before
/// return; the expanded key never crosses the boundary.
///
/// # Safety
/// `seed_ptr` must point to `seed_len` readable bytes, `msg_ptr` to `msg_len`
/// readable bytes (a zero-length message may pass null), and `sig_out` to
/// `sig_out_len` writable bytes. `sig_out` must not overlap the inputs.
#[no_mangle]
pub unsafe extern "C" fn mldsa65_sign(
    seed_ptr: *const u8,
    seed_len: usize,
    msg_ptr: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
    sig_out_len: usize,
) -> i32 {
    if sig_out.is_null() || sig_out_len != SIG_LEN {
        return 0;
    }
    let result =
        if seed_ptr.is_null() || seed_len != SEED_LEN || (msg_ptr.is_null() && msg_len != 0) {
            None
        } else {
            std::panic::catch_unwind(|| {
                let seed = unsafe { &*seed_ptr.cast::<[u8; SEED_LEN]>() };
                let msg: &[u8] = if msg_len == 0 {
                    &[]
                } else {
                    unsafe { std::slice::from_raw_parts(msg_ptr, msg_len) }
                };
                sign(seed, msg).ok()
            })
            .ok()
            .flatten()
        };
    match result {
        Some(sig) => {
            unsafe { write_out(sig_out, &sig) };
            1
        }
        None => {
            unsafe { std::ptr::write_bytes(sig_out, 0, SIG_LEN) };
            0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use getrandom::rand_core::{TryCryptoRng, TryRng};
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
        assert!(s.len().is_multiple_of(2), "odd hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex"))
            .collect()
    }

    fn field(file: &str, name: &str) -> Vec<u8> {
        let prefix = format!("{name}=");
        let line = file
            .lines()
            .find(|l| l.starts_with(&prefix))
            .unwrap_or_else(|| panic!("vector field {name} missing"));
        decode_hex(&line[prefix.len()..])
    }

    fn kat_field(name: &str) -> Vec<u8> {
        field(KAT, name)
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
        assert_eq!(
            sig.len(),
            SIG_LEN,
            "full-length forgery, not a length reject"
        );
        assert!(
            !verify(&pk, &msg, &sig),
            "modified signature must be rejected"
        );
    }

    // ── Signing ──────────────────────────────────────────────────────────────

    /// `rnd` = 32 zero bytes: FIPS 204's deterministic variant. Tests only.
    struct ZeroRnd;

    impl TryRng for ZeroRnd {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(0)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(0)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            dst.fill(0);
            Ok(())
        }
    }

    impl TryCryptoRng for ZeroRnd {}

    /// An OS generator that has failed.
    struct BrokenRnd;

    #[derive(Debug)]
    struct Broken;

    impl core::fmt::Display for Broken {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            f.write_str("broken")
        }
    }

    impl core::error::Error for Broken {}

    impl TryRng for BrokenRnd {
        type Error = Broken;
        fn try_next_u32(&mut self) -> Result<u32, Broken> {
            Err(Broken)
        }
        fn try_next_u64(&mut self) -> Result<u64, Broken> {
            Err(Broken)
        }
        fn try_fill_bytes(&mut self, _: &mut [u8]) -> Result<(), Broken> {
            Err(Broken)
        }
    }

    impl TryCryptoRng for BrokenRnd {}

    fn sign_deterministic(seed: &[u8; SEED_LEN], msg: &[u8]) -> [u8; SIG_LEN] {
        sign_with(seed, msg, &mut ZeroRnd).expect("zero rnd cannot fail")
    }

    #[test]
    fn signature_verifies_under_its_public_key() {
        let seed = [0x5au8; SEED_LEN];
        let pk = public_key_from_seed(&seed);
        for msg in [&b""[..], b"x", &[0xa5u8; 10_000]] {
            let sig = sign(&seed, msg).unwrap();
            assert!(verify(&pk, msg, &sig));
            assert!(!verify(&pk, b"another message", &sig));
        }
    }

    #[test]
    fn signing_is_hedged() {
        let seed = [0x11u8; SEED_LEN];
        let pk = public_key_from_seed(&seed);
        let (a, b) = (sign(&seed, b"m").unwrap(), sign(&seed, b"m").unwrap());
        assert_ne!(a, b, "two signatures of one message must differ");
        assert_ne!(a, sign_deterministic(&seed, b"m"));
        assert!(verify(&pk, b"m", &a) && verify(&pk, b"m", &b));
    }

    #[test]
    fn a_failed_rng_signs_nothing() {
        assert_eq!(
            sign_with(&[1u8; SEED_LEN], b"m", &mut BrokenRnd),
            Err(SignError::Randomness)
        );
    }

    #[test]
    fn the_seed_is_fips_204_keygen_internal() {
        // ml-dsa's own seed keygen and its deterministic signer agree with ours.
        let seed = [0x42u8; SEED_LEN];
        let sk = SigningKey::<MlDsa65>::from_seed(<&Seed>::from(&seed));
        assert_eq!(
            public_key_from_seed(&seed)[..],
            sk.verifying_key().encode()[..]
        );
        assert_eq!(
            sign_deterministic(&seed, b"m")[..],
            sk.sign(b"m").encode()[..]
        );
    }

    #[test]
    fn different_seeds_give_different_keys() {
        assert_ne!(
            public_key_from_seed(&[0u8; SEED_LEN]),
            public_key_from_seed(&[1u8; SEED_LEN])
        );
    }

    // ── The HelloHQ connectors engine ────────────────────────────────────────
    // Keys and signatures the engine itself made (hellohq-connectors
    // approval_v2_vectors.json, extracted with provenance in the file header).
    // The engine signs pure ML-DSA-65 with an empty context, deterministically,
    // with the same ml-dsa 0.1.1. So: our keys from its seeds are its keys, and
    // our signing path with rnd = 0 reproduces its signatures byte for byte —
    // which pins the variant (pure, not HashML-DSA or external-μ) and the
    // context (empty), since any difference changes every byte. Then the hedged
    // signatures we ship must verify under the engine's own verifier.
    const ENGINE: &str = include_str!("../tests/vectors/connectors_approval_v2_mldsa65.txt");
    const ENGINE_KEYS: [&str; 3] = ["owner", "delegate", "stranger"];
    const ENGINE_OBJECTS: [&str; 6] = [
        "owner_token",
        "pin",
        "revocation",
        "delegation",
        "delegated_token",
        "rotation",
    ];

    fn engine_seed(who: &str) -> [u8; SEED_LEN] {
        field(ENGINE, &format!("{who}.seed")).try_into().unwrap()
    }

    fn engine_signer(obj: &str) -> String {
        let prefix = format!("{obj}.signer=");
        ENGINE
            .lines()
            .find_map(|l| l.strip_prefix(&prefix))
            .unwrap_or_else(|| panic!("{obj}.signer missing"))
            .to_owned()
    }

    /// The engine's verifier, verbatim from hellohq-connectors
    /// `agent/src/seal.rs` `AgentPublicKeys::verify_ml_dsa_65` (origin/main
    /// a949e66), so this crate's [`verify`] is not the only judge.
    fn engine_verify_ml_dsa_65(ml_dsa_65: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let (Ok(key), Ok(sig)) = (
            EncodedVerifyingKey::<MlDsa65>::try_from(ml_dsa_65),
            EncodedSignature::<MlDsa65>::try_from(signature),
        ) else {
            return false;
        };
        let Some(sig) = Signature::<MlDsa65>::decode(&sig) else {
            return false;
        };
        VerifyingKey::<MlDsa65>::decode(&key).verify_with_context(message, &[], &sig)
    }

    #[test]
    fn engine_public_keys_match_byte_for_byte() {
        for who in ENGINE_KEYS {
            let pk = field(ENGINE, &format!("{who}.pk"));
            assert_eq!(public_key_from_seed(&engine_seed(who))[..], pk[..], "{who}");
        }
    }

    #[test]
    fn engine_signatures_reproduce_byte_for_byte() {
        for obj in ENGINE_OBJECTS {
            let seed = engine_seed(&engine_signer(obj));
            let msg = field(ENGINE, &format!("{obj}.msg"));
            let sig = field(ENGINE, &format!("{obj}.sig"));
            assert_eq!(sign_deterministic(&seed, &msg)[..], sig[..], "{obj}");
        }
    }

    #[test]
    fn engine_signatures_verify_here() {
        for obj in ENGINE_OBJECTS {
            let pk = field(ENGINE, &format!("{}.pk", engine_signer(obj)));
            let msg = field(ENGINE, &format!("{obj}.msg"));
            let sig = field(ENGINE, &format!("{obj}.sig"));
            assert!(verify(&pk, &msg, &sig), "{obj}");
        }
    }

    #[test]
    fn hedged_signatures_verify_under_the_engine_verifier() {
        for obj in ENGINE_OBJECTS {
            let who = engine_signer(obj);
            let pk = field(ENGINE, &format!("{who}.pk"));
            let msg = field(ENGINE, &format!("{obj}.msg"));
            let sig = sign(&engine_seed(&who), &msg).unwrap();
            assert!(engine_verify_ml_dsa_65(&pk, &msg, &sig), "{obj}");
            // …and nowhere else: not under another key, not over other bytes.
            let other = field(ENGINE, "stranger.pk");
            assert!(!engine_verify_ml_dsa_65(&other, &msg, &sig), "{obj}");
            assert!(!engine_verify_ml_dsa_65(&pk, &msg[1..], &sig), "{obj}");
        }
    }
}
