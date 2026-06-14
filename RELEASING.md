# Releasing

Releases are cut with [`cargo-release`](https://github.com/crate-ci/cargo-release),
so the `Cargo.toml` version and the git tag never drift (config in
[`release.toml`](release.toml)).

## One-time setup

```sh
cargo install cargo-release
```

### crates.io Trusted Publishing (OIDC)

CI publishes the crate to crates.io with no long-lived token, via GitHub OIDC
(`release.yml` → `rust-lang/crates-io-auth-action`). Configure it once:

1. **First publish must claim the name with a token** — crates.io can only add a
   trusted publisher to a crate that already exists. From a clean tree:
   ```sh
   cargo login            # paste a crates.io API token (Account → API Tokens)
   cargo publish          # publishes the current version, creating the crate
   ```
2. On crates.io: open the crate → **Settings → Trusted Publishing → Add** a
   GitHub config: repository `HelloHQ/mldsa-verify`, workflow `release.yml`.
3. You can now revoke that API token — every subsequent release publishes via
   OIDC from CI (step below), no token needed.

## Cut a release

From a clean `main`:

```sh
cargo release patch --execute     # 0.1.0 -> 0.1.1 (bug/CI/test fixes)
cargo release minor --execute     # 0.1.0 -> 0.2.0 (additive changes)
cargo release major --execute     # breaking C ABI / behavior changes
```

`cargo release` will, in one step:

1. bump the version in `Cargo.toml` + `Cargo.lock`,
2. commit it (`release: X.Y.Z`),
3. create the tag `vX.Y.Z`,
4. push the commit and the tag.

It does **not** publish to crates.io itself (`publish = false` in
`release.toml`) — that's CI's job. The tag push triggers
[`.github/workflows/release.yml`](.github/workflows/release.yml), which:

- cross-builds every platform and publishes a **GitHub Release** with per-asset
  SHA-256 + build-provenance attestation (for FFI consumers), and
- **publishes the crate to crates.io** via Trusted Publishing/OIDC (for Rust
  consumers).

So one `cargo release` → one tag → both channels, no local crates.io token.

Dry-run first to see exactly what it will do (this is the default without
`--execute`):

```sh
cargo release patch
```

## After the release

Watch it publish, then confirm the attested assets:

```sh
gh run watch --repo HelloHQ/mldsa-verify
gh release view vX.Y.Z --repo HelloHQ/mldsa-verify
```

Consumers (e.g. the HelloHQ app) then re-pin to the new tag by updating their
`RELEASE_TAG` + SHA-256 trust pins against the release's `SHA256SUMS`.
