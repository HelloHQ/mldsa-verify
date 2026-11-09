# mldsa-verify

**ML-DSA-65 (FIPS 204) post-quantum signing and verification over a C ABI** — a
thin, embeddable [RustCrypto `ml-dsa`](https://crates.io/crates/ml-dsa) wrapper
for FFI (Dart/Flutter, Swift, Kotlin/JNI, …).

It exposes three functions: verify a detached ML-DSA-65 signature, derive the
public key of a 32-byte seed, and sign with the key of a 32-byte seed. (The
name is from 0.1.x, which only verified; it stays so consumers' pins and
library names keep working.)

## Verifying and signing

Verification operates entirely on public data (public key, message,
signature), so a verifier can be shipped to untrusted devices and audited as a
pure function.

Signing touches a secret, so it is kept narrow:

- **The key is a 32-byte seed.** It is the FIPS 204 key-generation seed ξ
  (`ML-DSA.KeyGen_internal`, Algorithm 6): the same seed always gives the same
  key pair. How the seed is made, derived or stored is the caller's business.
- **The expanded secret key never leaves the library.** Each call expands the
  seed, uses the key and wipes it before returning; nothing secret is written
  back across the C boundary, and there is no key handle to leak or free.
- **Signing is hedged** — FIPS 204's default (Algorithm 2): each signature mixes
  32 fresh bytes from the operating system (`getrandom`) into the key's own
  secret. Signing one message twice gives two different signatures, both valid.
  Hedging is what FIPS 204 recommends where side channels or fault injection
  are a concern — a phone or a laptop holding a long-term key — and a weak or
  predictable generator only takes it back to the deterministic variant's
  security, never to a leaked key (unlike an ECDSA nonce). The cost is that signatures cannot be compared byte for byte:
  **verify them, never compare them.** If the OS gives no randomness, nothing is
  signed and the call fails.

## Interop

Signs and verifies **pure ML-DSA** (not HashML-DSA / prehash, not external-μ)
with an **empty context** — what standard FIPS-204 `ML-DSA-65` signers
(including major cloud KMS/HSM offerings) emit by default. Inputs and outputs
are the raw FIPS-204 encodings:

| | Bytes |
|---|---|
| Seed ξ | 32 |
| Public key | 1952 |
| Signature | 3309 |
| Message | any |

The tests pin this against two independent sources: the
[Wycheproof](https://github.com/C2SP/wycheproof) ML-DSA-65 vectors (verify),
and keys and signatures made by the HelloHQ connectors engine
([`tests/vectors/connectors_approval_v2_mldsa65.txt`](tests/vectors/connectors_approval_v2_mldsa65.txt)):
from the engine's seeds this library derives its public keys byte for byte, its
signing path with an all-zero `rnd` (FIPS 204's deterministic variant, which
the engine uses) reproduces the engine's signatures byte for byte, and the
hedged signatures it ships verify under the engine's verifier.

## C ABI

The header is [`include/mldsa_verify.h`](include/mldsa_verify.h). Every function
returns `1` on success and `0` otherwise, never unwinds across the boundary
(panics are caught), and takes no overlapping buffers.

```c
// 1 if valid, 0 otherwise (invalid signature, wrong-length inputs, null
// pointers, or an internal panic). Unchanged since 0.1.0.
int32_t mldsa65_verify(
    const uint8_t* pk,  size_t pk_len,       // 1952
    const uint8_t* msg, size_t msg_len,      // a zero-length msg may be NULL
    const uint8_t* sig, size_t sig_len);     // 3309

// Writes the public key of the seed to pk_out: 1, or 0 on a null pointer,
// seed_len != 32, pk_out_len != 1952, or an internal panic.
int32_t mldsa65_public_key_from_seed(
    const uint8_t* seed, size_t seed_len,    // 32
    uint8_t* pk_out,     size_t pk_out_len); // 1952

// Signs msg (hedged) and writes the signature to sig_out: 1, or 0 on a null
// pointer, seed_len != 32, sig_out_len != 3309, no OS randomness, or an
// internal panic.
int32_t mldsa65_sign(
    const uint8_t* seed, size_t seed_len,    // 32
    const uint8_t* msg,  size_t msg_len,     // a zero-length msg may be NULL
    uint8_t* sig_out,    size_t sig_out_len);// 3309
```

On a `0` from either new function, an output buffer that is non-null and the
right length is zero-filled, so a caller that ignores the return value sends no
stale bytes; a buffer of the wrong length is not written at all.

The seed buffer is read, never written or kept: wiping it is the caller's job.

## Build

```sh
cargo build --release            # libmldsa_verify.{dylib,so} / mldsa_verify.dll
cargo test                       # round-trip, known-answer + C-ABI tests
```

The C-ABI test in [`tests/c/abi_test.c`](tests/c/abi_test.c) links the built
shared library through the header, as an FFI consumer does (CI runs it on Linux
and macOS):

```sh
cargo build --release
cc -std=c11 -Wall -Wextra -Werror -Iinclude tests/c/abi_test.c \
   -Ltarget/release -lmldsa_verify -o target/abi_test
LD_LIBRARY_PATH=target/release DYLD_LIBRARY_PATH=target/release target/abi_test
```

Cross-platform artifacts (universal macOS dylib, iOS `.xcframework`, Linux/
Windows libs, Android jniLibs) are produced by [`build-release.sh`](build-release.sh)
and published — with SHA-256 + GitHub build-provenance attestation — by the
[release workflow](.github/workflows/release.yml). Consumers should verify both
before installing. Each iOS slice of the xcframework carries its dSYM in its
`dSYMs/` folder (from v0.1.4), built from the same compile so its UUID matches;
the app archive carries it to App Store Connect, which symbolicates crash
reports with it.

Releases are cut with `cargo release` (one command bumps the version, tags, and
pushes — which fires the release workflow). See [RELEASING.md](RELEASING.md).

## FFI example (Dart)

```dart
import 'dart:ffi';
import 'dart:typed_data';
import 'package:ffi/ffi.dart';

typedef _Verify = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);
final _verify = DynamicLibrary.open('libmldsa_verify.dylib')
    .lookupFunction<
        Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size,
            Pointer<Uint8>, Size),
        _Verify>('mldsa65_verify');

bool verify(Uint8List pk, Uint8List msg, Uint8List sig) {
  final p = malloc<Uint8>(pk.length), m = malloc<Uint8>(msg.length),
      s = malloc<Uint8>(sig.length);
  try {
    p.asTypedList(pk.length).setAll(0, pk);
    m.asTypedList(msg.length).setAll(0, msg);
    s.asTypedList(sig.length).setAll(0, sig);
    return _verify(p, pk.length, m, msg.length, s, sig.length) == 1;
  } finally {
    malloc..free(p)..free(m)..free(s);
  }
}

typedef _Sign = int Function(
    Pointer<Uint8>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);
final _sign = DynamicLibrary.open('libmldsa_verify.dylib')
    .lookupFunction<
        Int32 Function(Pointer<Uint8>, Size, Pointer<Uint8>, Size,
            Pointer<Uint8>, Size),
        _Sign>('mldsa65_sign');

Uint8List sign(Uint8List seed, Uint8List msg) {
  final k = malloc<Uint8>(32), m = malloc<Uint8>(msg.length),
      s = malloc<Uint8>(3309);
  try {
    k.asTypedList(32).setAll(0, seed);
    m.asTypedList(msg.length).setAll(0, msg);
    if (_sign(k, seed.length, m, msg.length, s, 3309) != 1) {
      throw StateError('ML-DSA-65 signing failed');
    }
    return Uint8List.fromList(s.asTypedList(3309));
  } finally {
    k.asTypedList(32).fillRange(0, 32, 0); // the seed copy is the caller's to wipe
    malloc..free(k)..free(m)..free(s);
  }
}
```

Generate a test vector with `cargo run --example gen_vector`: a fixed test
seed, its public key, a message and a fresh (hedged) signature over it.

## Security

Cryptography is delegated to the ACVP-validated RustCrypto `ml-dsa` crate; this
library only marshals bytes, pins the variant (pure, empty context) and takes
the signing randomness from the OS. All malformed/wrong-length inputs fail
closed (return 0).

What signing does and does not protect:

- The signing key `ml-dsa` holds — its copy of the seed and the expanded key —
  is wiped on drop (its `zeroize` feature), including when a panic unwinds.
  This library makes no copy of the seed of its own.
- `ml-dsa` 0.1.1 does not wipe every temporary its key generation and signing
  compute on the stack, and the upstream crate has not been independently
  audited; its constant-time behaviour is upstream's.
- The seed is the whole key. Anyone who reads it can sign; keep it where the
  platform keeps secrets, and wipe your own copies.

Found an issue? Please open a security advisory rather than a public issue.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option.
