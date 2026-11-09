#!/usr/bin/env bash
# Build the ML-DSA-65 sign + verify native libs for the CURRENT host's platforms and
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
STAGE="$(cd "$STAGE" && pwd)" # xcodebuild -debug-symbols needs an absolute path

build() { echo "→ cargo build --release --target $1"; cargo build --release --target "$1"; }

# iOS slices also get a dSYM: App Store Connect symbolicates crash reports with
# it, matched by Mach-O UUID, so it can only come from the build that produced
# the shipped binary. `split-debuginfo = packed` makes rustc run dsymutil before
# `strip = true`, so the dylib ships stripped as before and the debug info
# (line tables and function names, no variables) goes to <dylib>.dSYM. Build
# paths are remapped so the dSYM does not record the build machine's paths.
build_ios() {
  echo "→ cargo build --release --target $1 (+ dSYM)"
  CARGO_PROFILE_RELEASE_DEBUG=limited CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO=packed \
    RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$CRATE_DIR=/build --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$HOME=/home" \
    cargo build --release --target "$1"
}

# ios_dsym <out.dSYM> <target>...: the dSYM for one xcframework slice, lipo'd
# across that slice's targets. dsym_matches refuses one whose UUIDs differ.
ios_dsym() {
  local out="$1" dwarf="Contents/Resources/DWARF/libmldsa_verify.dylib" t parts=()
  shift
  cp -RL "target/$1/release/libmldsa_verify.dylib.dSYM" "$out"
  for t in "$@"; do parts+=("target/$t/release/libmldsa_verify.dylib.dSYM/$dwarf"); done
  [ "$#" -eq 1 ] || lipo -create "${parts[@]}" -output "$out/$dwarf"
}
dsym_matches() { # dsym_matches <dylib> <dSYM>
  [ "$(dwarfdump --uuid "$1" | awk '{print $2, $3}' | sort)" = \
    "$(dwarfdump --uuid "$2" | awk '{print $2, $3}' | sort)" ] \
    || { echo "::error::$2 does not match the UUIDs of $1"; dwarfdump --uuid "$1" "$2"; exit 1; }
}

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
    for t in aarch64-apple-darwin x86_64-apple-darwin; do build "$t"; done
    for t in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do build_ios "$t"; done
    lipo -create \
      target/aarch64-apple-darwin/release/libmldsa_verify.dylib \
      target/x86_64-apple-darwin/release/libmldsa_verify.dylib \
      -output "$STAGE/libmldsa_verify.dylib"
    # iOS: a DYNAMIC-library xcframework (not static), so the consuming app
    # embeds it into Frameworks/ and dlopen's it by name at runtime — matching
    # how other native libs here are loaded, and avoiding static dead-stripping
    # of the FFI symbol. @rpath install name lets the embedded copy resolve.
    # Each slice's library must be NAMED libmldsa_verify.dylib (xcframework keeps
    # the input basename, and the app dlopen's it by that name), so stage the
    # device and simulator dylibs in separate dirs under the same filename.
    DEV="$STAGE/_iosdev"
    SIM="$STAGE/_iossim"
    mkdir -p "$DEV" "$SIM"
    cp target/aarch64-apple-ios/release/libmldsa_verify.dylib "$DEV/libmldsa_verify.dylib"
    lipo -create \
      target/aarch64-apple-ios-sim/release/libmldsa_verify.dylib \
      target/x86_64-apple-ios/release/libmldsa_verify.dylib \
      -output "$SIM/libmldsa_verify.dylib"
    install_name_tool -id @rpath/libmldsa_verify.dylib "$DEV/libmldsa_verify.dylib"
    install_name_tool -id @rpath/libmldsa_verify.dylib "$SIM/libmldsa_verify.dylib"
    # install_name_tool leaves LC_UUID alone, so the dSYMs still match; checked
    # anyway, since a mismatched dSYM is silently useless.
    ios_dsym "$DEV/libmldsa_verify.dylib.dSYM" aarch64-apple-ios
    ios_dsym "$SIM/libmldsa_verify.dylib.dSYM" aarch64-apple-ios-sim x86_64-apple-ios
    for d in "$DEV" "$SIM"; do dsym_matches "$d/libmldsa_verify.dylib" "$d/libmldsa_verify.dylib.dSYM"; done
    rm -rf "$STAGE/MldsaVerify.xcframework"
    # -debug-symbols puts each slice's dSYM in <slice>/dSYMs, where Xcode finds
    # it and copies it into the app archive. It needs an absolute path.
    xcodebuild -create-xcframework \
      -library "$DEV/libmldsa_verify.dylib" -debug-symbols "$DEV/libmldsa_verify.dylib.dSYM" \
      -library "$SIM/libmldsa_verify.dylib" -debug-symbols "$SIM/libmldsa_verify.dylib.dSYM" \
      -output "$STAGE/MldsaVerify.xcframework"
    rm -rf "$DEV" "$SIM"
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
