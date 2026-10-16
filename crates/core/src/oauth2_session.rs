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
// Crypto inventory: TOK-5; see doc/src/contributor/crypto-inventory.md
//! # OAuth2 browser session provider (ADR 0026 §10 Phase 4)
//!
//! Internal plumbing consumed directly by the `/authorize` and `/token`
//! handlers -- not an admin-facing CRUD resource, so (like
//! [`crate::oauth2_key`]) this provider takes `&ServiceState` directly
//! rather than routing through [`crate::auth::ExecutionContext`]'s policy
//! layer.

pub mod audit;
pub mod backend;
pub mod error;
pub mod hook;
pub mod janitor;
pub mod provider_api;
pub mod service;

#[cfg(any(test, feature = "mock"))]
pub use crate::mocks::MockOauth2SessionProvider;
pub use error::Oauth2SessionProviderError;
pub use hook::Oauth2SessionHook;
pub use provider_api::{
    CreateSsoSessionRequest, DeviceAuthorizationStart, DevicePollOutcome,
    IssueAuthorizationCodeRequest, IssueRefreshTokenRequest, Oauth2SessionApi,
    RefreshTokenRedemption, StartDeviceAuthorizationRequest, StartPreAuthSessionRequest,
};
pub use service::Oauth2SessionService;

/// Non-secret reference of an SSO session.
///
/// The `sso_id` is the bearer value of the SSO cookie; the relying party
/// index, audit events and the `sid` derive from this one-way hash instead,
/// so none of them can be used to hijack the session.
pub fn sso_ref(sso_id: &str) -> String {
    use sha2::{Digest, Sha256};
    data_encoding::HEXLOWER.encode(&Sha256::digest(sso_id.as_bytes()))
}

/// The OIDC `sid` a relying party sees for an SSO session (identified by its
/// [`sso_ref`]).
///
/// Stable for the lifetime of the session, different per relying party so
/// two of them cannot correlate users by it, and not reversible.
pub fn derive_sid(sso_ref: &str, client_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"keystone-oauth2-sid\0");
    hasher.update(sso_ref.as_bytes());
    hasher.update([0]);
    hasher.update(client_id.as_bytes());
    data_encoding::BASE64URL_NOPAD.encode(&hasher.finalize())
}

#[cfg(test)]
mod sid_tests {
    use super::{derive_sid, sso_ref};

    #[test]
    fn test_derive_sid_is_stable_and_scoped() {
        let a = sso_ref("sso-1");
        assert_eq!(derive_sid(&a, "rp-1"), derive_sid(&a, "rp-1"));
        assert_ne!(derive_sid(&a, "rp-1"), derive_sid(&a, "rp-2"));
        assert_ne!(
            derive_sid(&a, "rp-1"),
            derive_sid(&sso_ref("sso-2"), "rp-1")
        );
        assert!(!derive_sid(&a, "rp-1").contains("sso-1"));
        assert!(!a.contains("sso-1"));
    }
}
