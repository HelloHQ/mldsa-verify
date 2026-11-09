//! The C entry points, called the way an FFI consumer calls them: raw pointers
//! and lengths, null and wrong-length inputs, and the return codes. Runs on
//! every CI platform; `tests/c/abi_test.c` does the same from C against the
//! built shared library.

use mldsa_verify::{
    mldsa65_public_key_from_seed, mldsa65_sign, mldsa65_verify, PK_LEN, SEED_LEN, SIG_LEN,
};
use std::ptr::{null, null_mut};

const SEED: [u8; SEED_LEN] = [0x08; SEED_LEN];
const MSG: &[u8] = b"approval token claims";

fn pk_of(seed: &[u8]) -> (i32, Vec<u8>) {
    let mut pk = vec![0xffu8; PK_LEN];
    let rc =
        unsafe { mldsa65_public_key_from_seed(seed.as_ptr(), seed.len(), pk.as_mut_ptr(), PK_LEN) };
    (rc, pk)
}

fn sign(seed: &[u8], msg: &[u8]) -> (i32, Vec<u8>) {
    let mut sig = vec![0xffu8; SIG_LEN];
    let rc = unsafe {
        mldsa65_sign(
            seed.as_ptr(),
            seed.len(),
            msg.as_ptr(),
            msg.len(),
            sig.as_mut_ptr(),
            SIG_LEN,
        )
    };
    (rc, sig)
}

fn verify(pk: &[u8], msg: &[u8], sig: &[u8]) -> i32 {
    unsafe {
        mldsa65_verify(
            pk.as_ptr(),
            pk.len(),
            msg.as_ptr(),
            msg.len(),
            sig.as_ptr(),
            sig.len(),
        )
    }
}

#[test]
fn sign_then_verify_through_the_c_abi() {
    let (rc, pk) = pk_of(&SEED);
    assert_eq!(rc, 1);
    assert_eq!(pk, mldsa_verify::public_key_from_seed(&SEED));
    let (rc, sig) = sign(&SEED, MSG);
    assert_eq!(rc, 1);
    assert_eq!(verify(&pk, MSG, &sig), 1);
    assert_eq!(verify(&pk, b"other", &sig), 0);
}

#[test]
fn signatures_are_hedged() {
    let (_, pk) = pk_of(&SEED);
    let (a, b) = (sign(&SEED, MSG).1, sign(&SEED, MSG).1);
    assert_ne!(a, b);
    assert_eq!(verify(&pk, MSG, &a), 1);
    assert_eq!(verify(&pk, MSG, &b), 1);
}

#[test]
fn an_empty_message_may_pass_a_null_pointer() {
    let (_, pk) = pk_of(&SEED);
    let mut sig = vec![0u8; SIG_LEN];
    let rc = unsafe {
        mldsa65_sign(
            SEED.as_ptr(),
            SEED_LEN,
            null(),
            0,
            sig.as_mut_ptr(),
            SIG_LEN,
        )
    };
    assert_eq!(rc, 1);
    assert_eq!(
        unsafe { mldsa65_verify(pk.as_ptr(), PK_LEN, null(), 0, sig.as_ptr(), SIG_LEN) },
        1
    );
}

#[test]
fn sign_refuses_bad_inputs_and_zero_fills_the_output() {
    let refused = |seed: *const u8, seed_len: usize, msg: *const u8, msg_len: usize| {
        let mut sig = vec![0xffu8; SIG_LEN];
        let rc = unsafe { mldsa65_sign(seed, seed_len, msg, msg_len, sig.as_mut_ptr(), SIG_LEN) };
        assert_eq!(rc, 0);
        assert!(sig.iter().all(|&b| b == 0), "output must be zero-filled");
    };
    refused(null(), SEED_LEN, MSG.as_ptr(), MSG.len());
    refused(SEED.as_ptr(), SEED_LEN - 1, MSG.as_ptr(), MSG.len());
    refused(SEED.as_ptr(), SEED_LEN + 1, MSG.as_ptr(), MSG.len());
    refused(SEED.as_ptr(), 0, MSG.as_ptr(), MSG.len());
    refused(SEED.as_ptr(), SEED_LEN, null(), 1);
}

#[test]
fn sign_never_writes_a_wrong_output_buffer() {
    let mut sig = vec![0xffu8; SIG_LEN + 1];
    for len in [0, SIG_LEN - 1, SIG_LEN + 1] {
        let rc = unsafe {
            mldsa65_sign(
                SEED.as_ptr(),
                SEED_LEN,
                MSG.as_ptr(),
                MSG.len(),
                sig.as_mut_ptr(),
                len,
            )
        };
        assert_eq!(rc, 0, "sig_out_len {len}");
    }
    assert!(sig.iter().all(|&b| b == 0xff), "untouched");
    let rc = unsafe {
        mldsa65_sign(
            SEED.as_ptr(),
            SEED_LEN,
            MSG.as_ptr(),
            MSG.len(),
            null_mut(),
            SIG_LEN,
        )
    };
    assert_eq!(rc, 0);
}

#[test]
fn public_key_refuses_bad_inputs() {
    let mut pk = vec![0xffu8; PK_LEN];
    let rc = unsafe { mldsa65_public_key_from_seed(null(), SEED_LEN, pk.as_mut_ptr(), PK_LEN) };
    assert_eq!(rc, 0);
    assert!(pk.iter().all(|&b| b == 0), "output must be zero-filled");
    for len in [0, SEED_LEN - 1, SEED_LEN + 1] {
        let (rc, pk) = pk_of(&[0x08; SEED_LEN + 1][..len]);
        assert_eq!(rc, 0, "seed_len {len}");
        assert!(pk.iter().all(|&b| b == 0));
    }
    let mut pk = vec![0xffu8; PK_LEN + 1];
    for len in [0, PK_LEN - 1, PK_LEN + 1] {
        let rc =
            unsafe { mldsa65_public_key_from_seed(SEED.as_ptr(), SEED_LEN, pk.as_mut_ptr(), len) };
        assert_eq!(rc, 0, "pk_out_len {len}");
    }
    assert!(pk.iter().all(|&b| b == 0xff), "untouched");
    let rc = unsafe { mldsa65_public_key_from_seed(SEED.as_ptr(), SEED_LEN, null_mut(), PK_LEN) };
    assert_eq!(rc, 0);
}

#[test]
fn the_verify_abi_is_unchanged() {
    // Same symbol, same arguments, same codes as 0.1.x.
    let f: unsafe extern "C" fn(*const u8, usize, *const u8, usize, *const u8, usize) -> i32 =
        mldsa65_verify;
    let (_, pk) = pk_of(&SEED);
    let (_, sig) = sign(&SEED, MSG);
    unsafe {
        assert_eq!(
            f(
                pk.as_ptr(),
                PK_LEN,
                MSG.as_ptr(),
                MSG.len(),
                sig.as_ptr(),
                SIG_LEN
            ),
            1
        );
        assert_eq!(
            f(
                null(),
                PK_LEN,
                MSG.as_ptr(),
                MSG.len(),
                sig.as_ptr(),
                SIG_LEN
            ),
            0
        );
        assert_eq!(f(pk.as_ptr(), PK_LEN, null(), 1, sig.as_ptr(), SIG_LEN), 0);
        assert_eq!(
            f(
                pk.as_ptr(),
                PK_LEN - 1,
                MSG.as_ptr(),
                MSG.len(),
                sig.as_ptr(),
                SIG_LEN
            ),
            0
        );
    }
}
