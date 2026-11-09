/*
 * C-ABI test: links the built shared library the way an FFI consumer does,
 * through the header, and checks the exported symbols and their contracts.
 * Run by CI (Linux, macOS) after `cargo build --release`:
 *
 *   cc -std=c11 -Wall -Wextra -Werror -Iinclude tests/c/abi_test.c \
 *      -Ltarget/release -lmldsa_verify -o target/abi_test
 *   LD_LIBRARY_PATH=target/release DYLD_LIBRARY_PATH=target/release target/abi_test
 */
#include <stdio.h>
#include <string.h>

#include "mldsa_verify.h"

static int failures = 0;
#define CHECK(cond)                                                    \
  do {                                                                 \
    if (!(cond)) {                                                     \
      fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, \
              #cond);                                                  \
      failures++;                                                      \
    }                                                                  \
  } while (0)

static int all_zero(const uint8_t *p, size_t n) {
  for (size_t i = 0; i < n; i++)
    if (p[i]) return 0;
  return 1;
}

int main(void) {
  uint8_t seed[MLDSA65_SEED_LEN], pk[MLDSA65_PK_LEN], pk2[MLDSA65_PK_LEN];
  uint8_t sig[MLDSA65_SIG_LEN], sig2[MLDSA65_SIG_LEN];
  const uint8_t msg[] = "approval token claims";
  const size_t msg_len = sizeof msg - 1;
  memset(seed, 0x08, sizeof seed);

  /* Key from seed: deterministic. */
  CHECK(mldsa65_public_key_from_seed(seed, sizeof seed, pk, sizeof pk) == 1);
  CHECK(mldsa65_public_key_from_seed(seed, sizeof seed, pk2, sizeof pk2) == 1);
  CHECK(memcmp(pk, pk2, sizeof pk) == 0);
  /* The connectors engine's owner key from seed 0x08…: first bytes. */
  CHECK(pk[0] == 0x72 && pk[1] == 0x01 && pk[2] == 0xa7 && pk[3] == 0x05);

  /* Sign, then verify through the unchanged verify ABI. */
  CHECK(mldsa65_sign(seed, sizeof seed, msg, msg_len, sig, sizeof sig) == 1);
  CHECK(mldsa65_verify(pk, sizeof pk, msg, msg_len, sig, sizeof sig) == 1);
  CHECK(mldsa65_verify(pk, sizeof pk, msg, msg_len - 1, sig, sizeof sig) == 0);

  /* Hedged: a second signature differs and also verifies. */
  CHECK(mldsa65_sign(seed, sizeof seed, msg, msg_len, sig2, sizeof sig2) == 1);
  CHECK(memcmp(sig, sig2, sizeof sig) != 0);
  CHECK(mldsa65_verify(pk, sizeof pk, msg, msg_len, sig2, sizeof sig2) == 1);

  /* Empty message, null pointer allowed. */
  CHECK(mldsa65_sign(seed, sizeof seed, NULL, 0, sig, sizeof sig) == 1);
  CHECK(mldsa65_verify(pk, sizeof pk, NULL, 0, sig, sizeof sig) == 1);

  /* Refusals: 0, and the output zero-filled. */
  memset(sig, 0xff, sizeof sig);
  CHECK(mldsa65_sign(NULL, sizeof seed, msg, msg_len, sig, sizeof sig) == 0);
  CHECK(all_zero(sig, sizeof sig));
  memset(sig, 0xff, sizeof sig);
  CHECK(mldsa65_sign(seed, sizeof seed - 1, msg, msg_len, sig, sizeof sig) == 0);
  CHECK(all_zero(sig, sizeof sig));
  memset(sig, 0xff, sizeof sig);
  CHECK(mldsa65_sign(seed, sizeof seed, NULL, 1, sig, sizeof sig) == 0);
  CHECK(all_zero(sig, sizeof sig));
  CHECK(mldsa65_sign(seed, sizeof seed, msg, msg_len, NULL, sizeof sig) == 0);
  memset(sig, 0xff, sizeof sig);
  CHECK(mldsa65_sign(seed, sizeof seed, msg, msg_len, sig, sizeof sig - 1) == 0);
  CHECK(sig[0] == 0xff); /* a wrong-length buffer is not written at all */
  memset(pk2, 0xff, sizeof pk2);
  CHECK(mldsa65_public_key_from_seed(NULL, sizeof seed, pk2, sizeof pk2) == 0);
  CHECK(all_zero(pk2, sizeof pk2));
  CHECK(mldsa65_public_key_from_seed(seed, sizeof seed + 1, pk2, sizeof pk2) == 0);
  CHECK(mldsa65_public_key_from_seed(seed, sizeof seed, NULL, sizeof pk2) == 0);
  CHECK(mldsa65_public_key_from_seed(seed, sizeof seed, pk2, sizeof pk2 + 1) == 0);

  if (failures) {
    fprintf(stderr, "%d check(s) failed\n", failures);
    return 1;
  }
  puts("C ABI: all checks passed");
  return 0;
}
