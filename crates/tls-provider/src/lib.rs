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
// Crypto inventory: NET-1, NET-2, STO-9, AUD-4; see
// doc/src/contributor/crypto-inventory.md
//! # TLS crypto provider selection
//!
//! The one place that decides which cryptographic provider rustls runs on,
//! so the choice is a cargo feature rather than a code change:
//!
//! * `ring` (default): the `ring` crate. Always available in the Debian
//!   archive, no C toolchain needed.
//! * `aws-lc`: `aws-lc-rs`. Takes precedence over `ring` when both are enabled,
//!   because cargo features are additive.
//! * `fips`: `aws-lc` built against the FIPS 140-3 validated module, via
//!   rustls' own `fips` feature. Use [`is_fips`] to assert it at start-up.
//!
//! Enabling a provider here also switches on the matching feature of
//! `rustls`, `tokio-rustls` and `tonic` through feature unification, so their
//! consumers need no feature of their own. Crates that cannot be reached that
//! way (for example `ldap3`) forward their own `rustls-ring` / `rustls-aws-lc`
//! features.
//!
//! Limitation: `spiffe-rustls` hardwires its provider through a mutually
//! exclusive feature, so SPIFFE mTLS stays on `ring` whatever is selected
//! here and `ring` is always part of the build.
//!
//! When more than one provider is compiled in, rustls cannot pick a process
//! default by itself; call [`install_default`] once at start-up, before any
//! TLS configuration is built.
//!
//! ## Adding a provider
//!
//! Add a cargo feature with the provider's optional dependency, one arm to
//! [`provider`], and extend the precedence order documented above.

use rustls::crypto::CryptoProvider;

#[cfg(not(any(feature = "ring", feature = "aws-lc")))]
compile_error!("enable the `ring` (default) or the `aws-lc` feature");

/// The crypto provider selected at build time.
#[must_use]
pub fn provider() -> CryptoProvider {
    #[cfg(feature = "aws-lc")]
    {
        rustls::crypto::aws_lc_rs::default_provider()
    }
    #[cfg(all(feature = "ring", not(feature = "aws-lc")))]
    {
        rustls::crypto::ring::default_provider()
    }
}

/// Whether the selected provider runs in FIPS mode (the `fips` feature, and
/// rustls reports every configured algorithm as validated).
#[must_use]
pub fn is_fips() -> bool {
    cfg!(feature = "fips") && provider().fips()
}

/// Name of the selected provider, for logs and diagnostics.
pub const PROVIDER_NAME: &str = if cfg!(feature = "aws-lc") {
    "aws-lc-rs"
} else {
    "ring"
};

/// Install [`provider`] as the process-wide rustls default.
///
/// Idempotent: returns `true` when a default is in place afterwards, whether
/// installed by this call or earlier by anyone else.
pub fn install_default() -> bool {
    CryptoProvider::get_default().is_some() || provider().install_default().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_install_default_is_idempotent() {
        assert!(install_default());
        assert!(install_default());
        assert!(CryptoProvider::get_default().is_some());
    }

    #[test]
    fn test_is_fips_matches_feature() {
        assert_eq!(is_fips(), cfg!(feature = "fips"));
    }

    #[test]
    fn test_provider_name_matches_features() {
        let expected = if cfg!(feature = "aws-lc") {
            "aws-lc-rs"
        } else {
            "ring"
        };
        assert_eq!(PROVIDER_NAME, expected);
        assert!(!provider().cipher_suites.is_empty());
    }
}
