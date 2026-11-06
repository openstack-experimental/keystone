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
//! * `aws-lc` feature: `aws-lc-rs`, through the same code. When both `ring`
//!   and `aws-lc` are enabled `aws-lc` wins, because cargo features are
//!   additive and a workspace-wide build must not silently fall back to
//!   `ring`.
//! * `fips` feature: `aws-lc` built against the FIPS 140-3 validated AWS-LC
//!   module. Use [`is_fips`] or [`assert_fips`] to check it at start-up.
//!
//! `aws-lc-rs` is a drop-in for the subset of `ring` used here, so one body
//! serves both; `provider` in [`backend`] is the only thing that differs.
//!
//! The process must call [`install`] once at start-up, before the first JWT
//! operation: `jsonwebtoken` is built without a backend and panics
//! otherwise. A deployment that claims FIPS operation also calls
//! [`assert_fips`].

mod backend;
mod der;
mod keygen;
mod keys;

pub use keygen::{
    GeneratedKey, KeyKind, KeygenError, generate, p256_point_from_spki, rsa_pkcs1_from_spki,
    validate_private_key,
};

use jsonwebtoken::crypto::{CryptoProvider, KeyUtils};

#[cfg(not(any(feature = "aws-lc", feature = "ring")))]
compile_error!("enable the `ring` (default) or the `aws-lc` feature");

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

/// Whether this build routes JWS primitives through the FIPS-validated
/// module.
pub const FIPS_BUILD: bool = cfg!(feature = "fips");

/// Name of the selected provider, for logs and diagnostics.
pub const PROVIDER_NAME: &str = if cfg!(feature = "aws-lc") {
    "aws-lc-rs"
} else {
    "ring"
};

/// Whether this build uses the FIPS 140-3 validated module and it is active.
#[must_use]
pub fn is_fips() -> bool {
    cfg!(feature = "fips") && assert_fips().is_ok()
}

/// Errors of provider installation and of the FIPS check.
#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    /// A different `jsonwebtoken` provider was installed first, so JWS would
    /// silently run on its primitives.
    #[error("a foreign jsonwebtoken crypto provider is already installed")]
    ForeignProvider,
    /// A FIPS claim was made but the validated module is not active.
    #[error("the FIPS 140-3 validated cryptographic module is not active")]
    FipsUnavailable,
}

/// Install [`PROVIDER`] as the `jsonwebtoken` provider of this process.
///
/// Call it once at start-up, before the first JWT operation, and propagate
/// the error. Repeated calls are fine. It fails if another provider was
/// installed first, instead of silently keeping it.
///
/// # Errors
///
/// [`ProviderError::ForeignProvider`] when another provider is installed.
pub fn install() -> Result<(), ProviderError> {
    match PROVIDER.install_default() {
        Ok(()) => Ok(()),
        Err(installed) if std::ptr::eq(installed, &PROVIDER) => Ok(()),
        Err(_) => Err(ProviderError::ForeignProvider),
    }
}

/// Ok only when the validated module is compiled in and running in FIPS
/// mode. Always an error in a build without the `fips` feature.
///
/// # Errors
///
/// [`ProviderError::FipsUnavailable`] when the module is not active.
pub fn assert_fips() -> Result<(), ProviderError> {
    backend::fips_active()
}

#[cfg(test)]
mod tests;
