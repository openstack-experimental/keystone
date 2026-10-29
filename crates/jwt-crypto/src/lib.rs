// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
// Crypto inventory: TOK-2, TOK-4, TOK-11; see
// doc/src/contributor/crypto-inventory.md
//! # JWS crypto provider
//!
//! `jsonwebtoken` ships crypto providers for RustCrypto and `aws-lc-rs` only
//! and has no `ring` support. This crate supplies its own
//! [`CryptoProvider`](jsonwebtoken::crypto::CryptoProvider) so the primitives
//! come from the same backends as the rest of the workspace:
//!
//! * default (`ring` feature): the `ring` crate;
//! * `fips` feature: `aws-lc-rs` built against the FIPS 140-3 validated
//!   AWS-LC module, through the same code. When both features are enabled
//!   `fips` wins, because cargo features are additive and a workspace-wide
//!   build must not silently fall back to non-validated primitives.
//!
//! `aws-lc-rs` is a drop-in for the subset of `ring` used here, so one body
//! serves both; `provider` in [`backend`] is the only thing that differs.
//!
//! The process must call [`install`] before the first JWT operation:
//! `jsonwebtoken` is built without a backend and panics otherwise.

mod backend;
mod der;
mod keygen;
mod keys;

pub use keygen::{
    GeneratedKey, KeyKind, KeygenError, generate, p256_point_from_spki, rsa_pkcs1_from_spki,
};

use jsonwebtoken::crypto::{CryptoProvider, KeyUtils};

#[cfg(not(any(feature = "fips", feature = "ring")))]
compile_error!("enable either the `ring` (default) or the `fips` feature");

/// The [`CryptoProvider`] of this crate.
pub static PROVIDER: CryptoProvider = CryptoProvider {
    signer_factory: backend::new_signer,
    verifier_factory: backend::new_verifier,
    key_utils: KeyUtils {
        rsa_pub_components_from_private_key: keys::rsa_components_from_private_key,
        rsa_pub_components_from_public_key: keys::rsa_components_from_public_key,
        ec_pub_components_from_private_key: keys::ec_components_from_private_key,
        ed_pub_components_from_private_key: keys::ed_components_from_private_key,
        compute_digest: keys::compute_digest,
    },
};

/// Install [`PROVIDER`] as the `jsonwebtoken` provider of this process.
///
/// Idempotent and cheap, so libraries may call it defensively before using
/// `jsonwebtoken`. If another provider was installed first, it stays in
/// place.
pub fn install() {
    // `Err` only means a provider is already installed.
    let _ = PROVIDER.install_default();
}

#[cfg(test)]
mod tests;
