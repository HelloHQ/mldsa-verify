# mldsa-verify

**Verify-only ML-DSA-65 (FIPS 204) post-quantum signatures over a C ABI** — a
thin, embeddable [RustCrypto `ml-dsa`](https://crates.io/crates/ml-dsa) wrapper
for FFI (Dart/Flutter, Swift, Kotlin/JNI, …).

It exposes exactly one function: verify a detached ML-DSA-65 signature. No key
generation, no signing — so there is **no secret material and no side-channel
surface**, which is what makes it safe to embed broadly (mobile apps, plugin
trust chains, firmware/document-signature checks).

## Why verify-only?

Signature *verification* operates entirely on public data (public key, message,
signature). A verifier can be shipped to untrusted devices and audited as a pure
function. Signing — which touches private keys and timing side-channels — is a
deliberately separate concern and is **not** in this library.

## Interop

Verifies **pure ML-DSA** (not HashML-DSA / prehash) with an **empty context** —
what standard FIPS-204 `ML-DSA-65` signers (including major cloud KMS/HSM
offerings) emit by default. Inputs are the raw FIPS-204 encodings:

| | Bytes |
|---|---|
| Public key | 1952 |
| Signature | 3309 |
| Message | any |

## C ABI

```c
// Returns 1 if valid, 0 otherwise (invalid signature, wrong-length inputs,
// null pointers, or an internal panic). Never unwinds across the boundary.
int32_t mldsa65_verify(
    const uint8_t* pk,  size_t pk_len,    // 1952
    const uint8_t* msg, size_t msg_len,
    const uint8_t* sig, size_t sig_len);  // 3309
```

## Build

```sh
cargo build --release            # libmldsa_verify.{dylib,so} / mldsa_verify.dll
cargo test                       # round-trip + negative tests
```

Cross-platform artifacts (universal macOS dylib, iOS `.xcframework`, Linux/
Windows libs, Android jniLibs) are produced by [`build-release.sh`](build-release.sh)
and published — with SHA-256 + GitHub build-provenance attestation — by the
[release workflow](.github/workflows/release.yml). Consumers should verify both
before installing.

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
```

Generate a test vector with `cargo run --example gen_vector`.

## Security

Cryptography is delegated to the ACVP-validated RustCrypto `ml-dsa` crate; this
library only marshals bytes and pins the variant (pure, empty context). All
malformed/wrong-length inputs fail closed (return 0). Found an issue? Please open
a security advisory rather than a public issue.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE) at
your option.
