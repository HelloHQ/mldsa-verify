/*
 * mldsa-verify: ML-DSA-65 (FIPS 204) signing and verification over a C ABI.
 *
 * Pure ML-DSA-65 (not HashML-DSA, not external-mu), empty context. Keys, the
 * signature and the seed are the raw FIPS 204 encodings. Every function returns
 * 1 on success and 0 otherwise, and never unwinds across this boundary.
 * Buffers must not overlap. Licensed MIT OR Apache-2.0.
 */
#ifndef MLDSA_VERIFY_H
#define MLDSA_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MLDSA65_SEED_LEN 32      /* the FIPS 204 key-generation seed xi */
#define MLDSA65_PK_LEN 1952      /* public key */
#define MLDSA65_SIG_LEN 3309     /* signature */

/* 1 if sig is a valid signature over msg under pk, 0 otherwise (invalid,
 * wrong-length inputs, null pointers, or an internal panic). A zero-length
 * message may pass a null msg. */
int32_t mldsa65_verify(const uint8_t *pk, size_t pk_len,
                       const uint8_t *msg, size_t msg_len,
                       const uint8_t *sig, size_t sig_len);

/* Writes the public key of the 32-byte seed to pk_out and returns 1.
 * Returns 0 on a null pointer, seed_len != 32, pk_out_len != 1952, or an
 * internal panic; pk_out is then zero-filled if it is non-null and 1952 bytes. */
int32_t mldsa65_public_key_from_seed(const uint8_t *seed, size_t seed_len,
                                     uint8_t *pk_out, size_t pk_out_len);

/* Signs msg with the key of the 32-byte seed (hedged: 32 bytes of OS
 * randomness per signature), writes the signature to sig_out and returns 1.
 * Returns 0 on a null pointer (a zero-length message may pass a null msg),
 * seed_len != 32, sig_out_len != 3309, no OS randomness, or an internal panic;
 * sig_out is then zero-filled if it is non-null and 3309 bytes. The key is
 * derived inside the call and wiped before it returns. */
int32_t mldsa65_sign(const uint8_t *seed, size_t seed_len,
                     const uint8_t *msg, size_t msg_len,
                     uint8_t *sig_out, size_t sig_out_len);

#ifdef __cplusplus
}
#endif

#endif /* MLDSA_VERIFY_H */
