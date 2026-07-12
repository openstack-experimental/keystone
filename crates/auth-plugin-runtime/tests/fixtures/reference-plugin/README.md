# ADR 0025 reference dynamic auth plugin

A minimal Rust plugin used only by `openstack-keystone-auth-plugin-runtime`'s
test suite (`../../reference_plugin.rs`) to prove the runtime crate can load,
checksum-verify, invoke, and resource-bound a real `wasm32-unknown-unknown`
module compiled with the [Extism Rust PDK](https://github.com/extism/rust-pdk).
It is **not** a production plugin - see
`doc/src/adr/0025-implementation-plan.md` PR 0.3.

This crate is deliberately excluded from the top-level Cargo workspace (its
own `Cargo.toml` declares an empty `[workspace]` table) so its guest-side
dependency graph never affects the shipped `keystone` binary.

## Building it yourself

```sh
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

produces `target/wasm32-unknown-unknown/release/reference_plugin.wasm`. The
test suite does exactly this itself before every run, so the fixture can
never drift out of sync with its source.

## Writing your own plugin

A third-party author following this same pattern needs only:

- `extism-pdk` as a dependency (see `Cargo.toml`).
- `crate-type = ["cdylib"]` in `[lib]`.
- One `#[extism_pdk::plugin_fn]`-annotated function per guest entry point
  your plugin's `mode` requires (`authenticate` for `full_auth`, `mapping`
  for `mapping`, `route` for `route` - see ADR 0025 §4), each taking and
  returning `extism_pdk::Json<T>` for whatever `T` the entry point's
  contract specifies.
- Compile for `wasm32-unknown-unknown` and record the SHA-256 of the
  resulting `.wasm` file in the plugin's `[auth_plugin.<name>]`
  `sha256` config value.
