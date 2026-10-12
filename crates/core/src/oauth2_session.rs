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

/// The OIDC `sid` of an SSO session as seen by one relying party.
///
/// A hash of the (secret, cookie-valued) `sso_id` and the `client_id`:
/// stable for the lifetime of the session, different per relying party so
/// two RPs cannot correlate users by it, and not reversible to the cookie.
pub fn derive_sid(sso_id: &str, client_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"keystone-oauth2-sid\0");
    hasher.update(sso_id.as_bytes());
    hasher.update([0]);
    hasher.update(client_id.as_bytes());
    data_encoding::BASE64URL_NOPAD.encode(&hasher.finalize())
}

#[cfg(test)]
mod sid_tests {
    use super::derive_sid;

    #[test]
    fn test_derive_sid_is_stable_and_scoped() {
        assert_eq!(derive_sid("sso-1", "rp-1"), derive_sid("sso-1", "rp-1"));
        assert_ne!(derive_sid("sso-1", "rp-1"), derive_sid("sso-1", "rp-2"));
        assert_ne!(derive_sid("sso-1", "rp-1"), derive_sid("sso-2", "rp-1"));
        assert!(!derive_sid("sso-1", "rp-1").contains("sso-1"));
    }
}
