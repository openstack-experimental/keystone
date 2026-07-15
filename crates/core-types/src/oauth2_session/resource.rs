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
//! # OAuth2 browser session resource types (ADR 0026 §10 Phase 4)

use serde::{Deserialize, Serialize};

/// Pre-authentication browser session, created at `GET /authorize` and
/// consumed across the login -> consent -> code-issuance sequence. Keyed by
/// an opaque `session_id` carried in an `HttpOnly`, `SameSite=Lax` cookie
/// (ADR 0026 §8). Single-flight: deleted on completion or expiry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreAuthSession {
    /// Opaque session identifier (the cookie value).
    pub session_id: String,
    /// Domain the `/authorize` request targets.
    pub domain_id: String,
    /// Requesting `OAuth2Client.client_id`.
    pub client_id: String,
    /// Validated (allowlisted) redirect URI for this request.
    pub redirect_uri: String,
    /// Requested scope values.
    pub scope: Vec<String>,
    /// Client-supplied `state`, echoed back on redirect (RFC 6749 §4.1).
    pub state: String,
    /// PKCE `code_challenge` (RFC 7636). `S256` only.
    pub code_challenge: String,
    /// PKCE `code_challenge_method`. Always `"S256"` -- `plain` is rejected
    /// at `/authorize` (ADR 0026 §1).
    pub code_challenge_method: String,
    /// OIDC `nonce`, echoed into the `id_token` (replay prevention).
    pub nonce: Option<String>,
    /// Server-side secret used to derive the CSRF token for the login/
    /// consent POST forms (ADR 0026 §8): `HMAC-SHA256(secret, session_id
    /// || state || code_challenge)`. Never transmitted to the client.
    pub server_side_session_secret: String,
    /// Set once login succeeds: the authenticated principal's `user_id`.
    pub user_id: Option<String>,
    /// Set once login succeeds: epoch seconds of primary authentication
    /// (OIDC Core §3.1.2.1 `auth_time`).
    pub auth_time: Option<i64>,
    /// Set once the consent step completes: `true` if the user approved,
    /// `false` if denied.
    pub consent_granted: Option<bool>,
    /// UTC epoch seconds.
    pub created_at: i64,
    /// UTC epoch seconds after which this session is no longer valid
    /// (`[oauth2] pre_auth_session_lifetime_minutes`).
    pub expires_at: i64,
}

/// Input to create a new [`PreAuthSession`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreAuthSessionCreate {
    /// Opaque session identifier (the cookie value).
    pub session_id: String,
    /// Domain the `/authorize` request targets.
    pub domain_id: String,
    /// Requesting `OAuth2Client.client_id`.
    pub client_id: String,
    /// Validated (allowlisted) redirect URI for this request.
    pub redirect_uri: String,
    /// Requested scope values.
    pub scope: Vec<String>,
    /// Client-supplied `state`.
    pub state: String,
    /// PKCE `code_challenge`.
    pub code_challenge: String,
    /// PKCE `code_challenge_method`.
    pub code_challenge_method: String,
    /// OIDC `nonce`.
    pub nonce: Option<String>,
    /// Server-side CSRF-derivation secret.
    pub server_side_session_secret: String,
    /// UTC epoch seconds.
    pub created_at: i64,
    /// UTC epoch seconds.
    pub expires_at: i64,
}

/// Single-use authorization code minted on successful consent (RFC 6749
/// §4.1.2). Redeemed exactly once at `/token`; a second redemption attempt
/// is treated as an attack, not tolerated like refresh token reuse.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationCode {
    /// The code value itself (256-bit entropy), also the storage key.
    pub code: String,
    /// Owning domain.
    pub domain_id: String,
    /// The `OAuth2Client.client_id` this code was issued to.
    pub client_id: String,
    /// The authenticated principal's `user_id`.
    pub user_id: String,
    /// Must match exactly at `/token` redemption (RFC 6749 §4.1.3).
    pub redirect_uri: String,
    /// PKCE `code_challenge` recorded at `/authorize`.
    pub code_challenge: String,
    /// PKCE `code_challenge_method`.
    pub code_challenge_method: String,
    /// Granted scope values.
    pub scope: Vec<String>,
    /// OIDC `nonce`, carried through to the `id_token`.
    pub nonce: Option<String>,
    /// Epoch seconds of primary authentication.
    pub auth_time: i64,
    /// Authentication methods references.
    pub amr: Vec<String>,
    /// UTC epoch seconds.
    pub created_at: i64,
    /// UTC epoch seconds (`[oauth2] authorization_code_lifetime_seconds`).
    pub expires_at: i64,
}

/// Input to create a new [`AuthorizationCode`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthorizationCodeCreate {
    /// The code value itself.
    pub code: String,
    /// Owning domain.
    pub domain_id: String,
    /// The `OAuth2Client.client_id` this code is issued to.
    pub client_id: String,
    /// The authenticated principal's `user_id`.
    pub user_id: String,
    /// Redirect URI recorded at `/authorize`.
    pub redirect_uri: String,
    /// PKCE `code_challenge`.
    pub code_challenge: String,
    /// PKCE `code_challenge_method`.
    pub code_challenge_method: String,
    /// Granted scope values.
    pub scope: Vec<String>,
    /// OIDC `nonce`.
    pub nonce: Option<String>,
    /// Epoch seconds of primary authentication.
    pub auth_time: i64,
    /// Authentication methods references.
    pub amr: Vec<String>,
    /// UTC epoch seconds.
    pub created_at: i64,
    /// UTC epoch seconds.
    pub expires_at: i64,
}

/// A single node in a `refresh_token` rotation family tree (ADR 0026 §2,
/// §9). `token_id` is a SHA-256 hex digest of the opaque bearer value --
/// the bearer value itself is never persisted, mirroring
/// `OAuth2ClientResource.client_secret_hash`'s posture of never storing a
/// presentable secret at rest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefreshToken {
    /// SHA-256 hex digest of the bearer value; also the storage key.
    pub token_id: String,
    /// Identifies the whole rotation lineage. Stable across rotations,
    /// used to fan out revocation on reuse detection.
    pub family_id: String,
    /// The `token_id` this token was rotated from. `None` for the family
    /// root (minted directly by the `authorization_code` grant).
    pub parent_token_id: Option<String>,
    /// Owning domain.
    pub domain_id: String,
    /// The `OAuth2Client.client_id` this family belongs to.
    pub client_id: String,
    /// The authenticated principal's `user_id`.
    pub user_id: String,
    /// The scope grant this family carries. Fixed at family creation --
    /// rotation never escalates scope beyond what `/authorize` originally
    /// granted.
    pub scope: Vec<String>,
    /// UTC epoch seconds this token was minted.
    pub issued_at: i64,
    /// UTC epoch seconds this token was rotated away (presented once,
    /// exchanged for its child). `None` while still the family's live
    /// leaf.
    pub spent_at: Option<i64>,
    /// UTC epoch seconds after which this token, and thus the family (idle
    /// lifetime), is no longer valid (`[oauth2] refresh_token_lifetime_days`).
    pub expires_at: i64,
}

/// Status of an RFC 8628 Device Authorization Grant (ADR 0026 §7.C).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceGrantStatus {
    /// Awaiting the user to complete the verification-page login/consent
    /// flow.
    Pending,
    /// Consent granted; the device may redeem `device_code` at `/token`
    /// exactly once.
    Authorized,
    /// Consent denied; polling returns `access_denied`.
    Denied,
}

/// An RFC 8628 Device Authorization Grant, minted at
/// `POST /device_authorization` and completed via the browser verification
/// page (ADR 0026 §7.C). Single-use like [`AuthorizationCode`]: redeemed
/// exactly once at `/token` while `Authorized`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceCodeGrant {
    /// 256-bit-entropy value the polling device holds; also the storage
    /// key. Never displayed to the user.
    pub device_code: String,
    /// Short, human-typeable code displayed to the user and entered at the
    /// verification page.
    pub user_code: String,
    /// Owning domain.
    pub domain_id: String,
    /// The `OAuth2Client.client_id` this grant was issued to.
    pub client_id: String,
    /// Requested scope values.
    pub scope: Vec<String>,
    /// Current lifecycle state.
    pub status: DeviceGrantStatus,
    /// Set once the verification page's login step succeeds.
    pub user_id: Option<String>,
    /// Set once the verification page's login step succeeds: epoch seconds
    /// of primary authentication.
    pub auth_time: Option<i64>,
    /// Authentication methods references, set alongside `user_id`.
    pub amr: Vec<String>,
    /// OIDC `nonce`, if the polling device supplied one.
    pub nonce: Option<String>,
    /// Server-side secret used to derive the CSRF token for the
    /// verification page's login/consent POST forms, mirroring
    /// `PreAuthSession.server_side_session_secret`.
    pub server_side_session_secret: String,
    /// Epoch seconds of the most recent `/token` poll for this
    /// `device_code`, for RFC 8628 §3.5 `slow_down` interval enforcement.
    /// `None` before the first poll.
    pub last_polled_at: Option<i64>,
    /// UTC epoch seconds.
    pub created_at: i64,
    /// UTC epoch seconds (`[oauth2] device_code_lifetime_minutes`).
    pub expires_at: i64,
}

/// Input to create a new [`DeviceCodeGrant`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceCodeGrantCreate {
    /// 256-bit-entropy value the polling device holds.
    pub device_code: String,
    /// Short, human-typeable code displayed to the user.
    pub user_code: String,
    /// Owning domain.
    pub domain_id: String,
    /// The `OAuth2Client.client_id` this grant is issued to.
    pub client_id: String,
    /// Requested scope values.
    pub scope: Vec<String>,
    /// Server-side CSRF-derivation secret.
    pub server_side_session_secret: String,
    /// UTC epoch seconds.
    pub created_at: i64,
    /// UTC epoch seconds.
    pub expires_at: i64,
}

/// Input to create a new [`RefreshToken`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefreshTokenCreate {
    /// SHA-256 hex digest of the bearer value.
    pub token_id: String,
    /// The rotation family this token belongs to.
    pub family_id: String,
    /// The `token_id` this token was rotated from.
    pub parent_token_id: Option<String>,
    /// Owning domain.
    pub domain_id: String,
    /// The `OAuth2Client.client_id` this family belongs to.
    pub client_id: String,
    /// The authenticated principal's `user_id`.
    pub user_id: String,
    /// The scope grant this family carries.
    pub scope: Vec<String>,
    /// UTC epoch seconds.
    pub issued_at: i64,
    /// UTC epoch seconds.
    pub expires_at: i64,
}
