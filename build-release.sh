#!/usr/bin/env bash
# Build the ML-DSA-65 verifier native libs for the CURRENT host's platforms and
# stage them (+ SHA-256SUMS) for the release pipeline (.github/workflows/release.yml).
#
#   macOS  → libmldsa_verify.dylib (universal) + MldsaVerify.xcframework (iOS)
#   Linux  → libmldsa_verify.so (x86_64) [+ Android jniLibs when cargo-ndk present]
#   Windows→ mldsa_verify.dll (x86_64)
set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGE="${1:-$CRATE_DIR/dist}"
cd "$CRATE_DIR"
rm -rf "$STAGE" && mkdir -p "$STAGE"

build() { echo "→ cargo build --release --target $1"; cargo build --release --target "$1"; }

build_android() {
  if ! command -v cargo-ndk >/dev/null 2>&1; then
    echo "⚠ cargo-ndk not found; skipping Android (install: cargo install cargo-ndk)"; return 0
  fi
  echo "→ cargo ndk → jniLibs (arm64-v8a, armeabi-v7a, x86_64, x86)"
  cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 -t x86 -o "$STAGE/jniLibs" build --release
  ( cd "$STAGE" && zip -qry jniLibs.zip jniLibs && rm -rf jniLibs )
}

case "$(uname -s)" in
  Darwin)
    for t in aarch64-apple-darwin x86_64-apple-darwin \
             aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do build "$t"; done
    lipo -create \
      target/aarch64-apple-darwin/release/libmldsa_verify.dylib \
      target/x86_64-apple-darwin/release/libmldsa_verify.dylib \
      -output "$STAGE/libmldsa_verify.dylib"
    SIM="$STAGE/_iossim.a"
    lipo -create \
      target/aarch64-apple-ios-sim/release/libmldsa_verify.a \
      target/x86_64-apple-ios/release/libmldsa_verify.a -output "$SIM"
    rm -rf "$STAGE/MldsaVerify.xcframework"
    xcodebuild -create-xcframework \
      -library target/aarch64-apple-ios/release/libmldsa_verify.a \
      -library "$SIM" -output "$STAGE/MldsaVerify.xcframework"
    rm -f "$SIM"
    ( cd "$STAGE" && zip -qry MldsaVerify.xcframework.zip MldsaVerify.xcframework && rm -rf MldsaVerify.xcframework )
    [ -n "${ANDROID_NDK_HOME:-}" ] && build_android || true
    ;;
  Linux)
    build x86_64-unknown-linux-gnu
    cp target/x86_64-unknown-linux-gnu/release/libmldsa_verify.so "$STAGE/"
    [ -n "${ANDROID_NDK_HOME:-}" ] && build_android || true
    ;;
  MINGW*|MSYS*|CYGWIN*|Windows_NT)
    build x86_64-pc-windows-msvc
    cp target/x86_64-pc-windows-msvc/release/mldsa_verify.dll "$STAGE/"
    ;;
esac

( cd "$STAGE" && shasum -a 256 * > SHA256SUMS 2>/dev/null || sha256sum * > SHA256SUMS )
echo "Staged for $(uname -s):" && ls -1 "$STAGE"
