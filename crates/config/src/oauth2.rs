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
//! # OAuth2/OIDC provider configuration (ADR 0026)
//!
//! Phase 1 scope only: the per-domain signing-key algorithm and rotation
//! cadence for the `GET /v4/oauth2/{domain_id}/jwks` cryptographic engine.
//! Later phases (client registration, scopes, grants) get their own config
//! sections when implemented.
use std::path::{Path, PathBuf};

use serde::Deserialize;
use validator::Validate;

use crate::pagination::ListLimitConfig;

/// OAuth2 signing algorithm (ADR 0026 §3).
///
/// This same value governs both outbound signing and inbound verification;
/// the two must always match to prevent cross-algorithm signature exploits.
#[derive(Debug, Default, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum SigningAlgorithm {
    /// ECDSA over P-256, SHA-256. Default per ADR 0026 §3.
    #[default]
    #[serde(rename = "ES256")]
    Es256,
    /// RSA-2048, SHA-256.
    #[serde(rename = "RS256")]
    Rs256,
}

impl std::fmt::Display for SigningAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::Es256 => write!(f, "ES256"),
            Self::Rs256 => write!(f, "RS256"),
        }
    }
}

/// OAuth2/OIDC provider configuration.
#[derive(Debug, Deserialize, Clone, Validate)]
pub struct Oauth2Provider {
    /// Signing algorithm for per-domain OAuth2 signing keypairs.
    #[serde(default)]
    pub signing_algorithm: SigningAlgorithm,

    /// Days between automatic signing-key rotations. Manual rotation via
    /// `keystone-manage oauth2 rotate-signing-key` is always available
    /// regardless of this value.
    #[serde(default = "default_signing_key_rotation_days")]
    #[validate(range(min = 1))]
    pub signing_key_rotation_days: u32,

    /// Argon2id memory cost, in KiB, for `OAuth2Client` confidential-client
    /// secret hashing (ADR 0026 §5). A separate knob set from `[api_key]`
    /// so the two credential classes can be tuned independently.
    #[serde(default = "default_argon2_memory_kib")]
    #[validate(range(min = 1))]
    pub argon2_memory_kib: u32,

    /// Argon2id time cost (iterations) for client secret hashing.
    #[serde(default = "default_argon2_time_cost")]
    #[validate(range(min = 1))]
    pub argon2_time_cost: u32,

    /// Argon2id parallelism (lanes) for client secret hashing.
    #[serde(default = "default_argon2_parallelism")]
    #[validate(range(min = 1))]
    pub argon2_parallelism: u32,

    /// Lifetime, in minutes, of an `access_token` minted at `/token` (ADR
    /// 0026 §4).
    #[serde(default = "default_access_token_lifetime_minutes")]
    #[validate(range(min = 1))]
    pub access_token_lifetime_minutes: u32,

    /// Maximum burst of `/token` requests accepted instantaneously, per
    /// rate-limit key (the presented, unverified `client_id`), before
    /// throttling kicks in (ADR 0026 §7.A). A separate pool from
    /// `[api_key] rate_limit_burst_size` so SCIM ingress and OAuth2 ingress
    /// have independently tunable blast radii.
    #[serde(default = "default_token_rate_limit_burst_size")]
    #[validate(range(min = 1))]
    pub token_rate_limit_burst_size: u32,

    /// Sustained `/token` requests allowed per minute, per rate-limit key,
    /// once the burst allowance is exhausted.
    #[serde(default = "default_token_rate_limit_replenish_per_minute")]
    #[validate(range(min = 1))]
    pub token_rate_limit_replenish_per_minute: u32,

    /// Lifetime, in minutes, of an `id_token` minted at `/token` for the
    /// `authorization_code` grant (ADR 0026 §4). Mirrors
    /// `access_token_lifetime_minutes` per the ADR's default, but kept as
    /// an independent knob since the two tokens serve different consumers.
    #[serde(default = "default_id_token_lifetime_minutes")]
    #[validate(range(min = 1))]
    pub id_token_lifetime_minutes: u32,

    /// Lifetime, in seconds, of an authorization code minted at
    /// `/authorize` before it must be redeemed at `/token` (ADR 0026 §10
    /// Phase 4). Single-use regardless of this TTL.
    #[serde(default = "default_authorization_code_lifetime_seconds")]
    #[validate(range(min = 1))]
    pub authorization_code_lifetime_seconds: u32,

    /// Idle lifetime, in days, of a `refresh_token` family before it must
    /// be re-established via a fresh `authorization_code` grant (ADR 0026
    /// §2). Reset on each successful rotation, but never beyond the
    /// family's absolute lifetime (`refresh_token_absolute_lifetime_days`).
    #[serde(default = "default_refresh_token_lifetime_days")]
    #[validate(range(min = 1))]
    pub refresh_token_lifetime_days: u32,

    /// Absolute lifetime, in days, of a `refresh_token` family measured
    /// from the root issuance. Rotation never extends it: once reached the
    /// family must be re-established via a fresh `authorization_code`
    /// grant, no matter how recently it was rotated.
    #[serde(default = "default_refresh_token_absolute_lifetime_days")]
    #[validate(range(min = 1))]
    pub refresh_token_absolute_lifetime_days: u32,

    /// Grace period, in minutes, during which a `refresh_token` presented
    /// a second time is tolerated as a benign multi-device race rather
    /// than treated as a breach (ADR 0026 §9). `0` disables the grace
    /// period entirely (tightest breach detection).
    #[serde(default = "default_refresh_token_reuse_grace_minutes")]
    #[validate(range(max = 30))]
    pub refresh_token_reuse_grace_minutes: u32,

    /// Lifetime, in minutes, of the pre-authentication browser session
    /// created at `GET /authorize` -- bounds how long a user has to
    /// complete the login + consent sequence before it expires (ADR 0026
    /// §10 Phase 4, §8).
    #[serde(default = "default_pre_auth_session_lifetime_minutes")]
    #[validate(range(min = 1))]
    pub pre_auth_session_lifetime_minutes: u32,

    /// Lifetime, in minutes, of a `device_code`/`user_code` pair minted at
    /// `POST /device_authorization` before the grant expires unclaimed
    /// (RFC 8628 §3.2 `expires_in`, ADR 0026 §7.C).
    #[serde(default = "default_device_code_lifetime_minutes")]
    #[validate(range(min = 1))]
    pub device_code_lifetime_minutes: u32,

    /// Minimum interval, in seconds, between two `/token` polls for the
    /// same `device_code` (RFC 8628 §3.2 `interval`, §3.5 `slow_down`).
    #[serde(default = "default_device_code_poll_interval_seconds")]
    #[validate(range(min = 1))]
    pub device_code_poll_interval_seconds: u32,

    /// Quiet period, in seconds, during which further `/token` polls
    /// presenting a `device_code` that was answered with `invalid_grant` or
    /// `expired_token` are refused with `429` + `Retry-After` before any
    /// storage lookup (ADR 0026 §7.C).
    #[serde(default = "default_device_code_invalid_quiet_period_seconds")]
    #[validate(range(min = 1))]
    pub device_code_invalid_quiet_period_seconds: u32,

    /// Days a revoked (tombstoned) refresh token is retained after its own
    /// `expires_at` before the session janitor purges it. Presenting an
    /// expired token is rejected regardless; retention only keeps the
    /// record for forensics and correlation with the breach audit event.
    /// Refresh tokens that were never revoked are purged shortly after
    /// they expire.
    #[serde(default = "default_revoked_family_retention_days")]
    #[validate(range(min = 1))]
    pub revoked_family_retention_days: u32,

    /// Interval, in seconds, between two sweeps of the OAuth2 session
    /// janitor that purges expired pre-auth sessions, authorization
    /// codes, device grants and refresh tokens.
    #[serde(default = "default_session_janitor_interval_seconds")]
    #[validate(range(min = 1))]
    pub session_janitor_interval_seconds: u32,

    /// `GET /v4/oauth2/{domain_id}/clients` pagination limits.
    #[serde(default)]
    pub list_limit: ListLimitConfig,

    /// Allow the OP to derive its issuer (and the `Secure` cookie attribute)
    /// from the request `Host` / `X-Forwarded-Proto` headers when
    /// `[DEFAULT] public_endpoint` is unset.
    ///
    /// **Development only.** Left `false`, the OP refuses `/authorize`,
    /// `/device_authorization`, `/token` and discovery with `503
    /// server_error` until `public_endpoint` is configured, so a client
    /// cannot choose the `iss` claim, the discovery document or the device
    /// flow `verification_uri` through the `Host` header.
    #[serde(default)]
    pub allow_host_header_issuer: bool,

    /// Directory with operator-supplied page templates (`login.html`,
    /// `consent.html`, `device_entry.html`, `device_result.html`,
    /// `error.html`). A page whose file is absent falls back to the
    /// built-in default. Templates are read once at startup; a restart is
    /// required to pick up changes.
    #[serde(default)]
    pub templates_dir: Option<PathBuf>,

    /// Directory with operator-supplied static assets (stylesheets, logos)
    /// served read-only under `/v4/oauth2/static/`. The route is only
    /// available when this is set; a `style.css` placed here replaces the
    /// built-in default stylesheet.
    #[serde(default)]
    pub static_dir: Option<PathBuf>,

    /// Product name shown in the page title, the logo `alt` text and
    /// the page footer.
    #[serde(default = "default_ui_product_name")]
    pub ui_product_name: String,

    /// Logo shown at the top of every page. Either an absolute path on this
    /// host (for example `/v4/oauth2/static/logo.svg`) or an `https://` URL.
    /// The page CSP only allows same-origin images, so use a same-origin
    /// path unless a reverse proxy relaxes it.
    #[serde(default)]
    pub ui_logo_url: Option<String>,

    /// Link to a support page, shown in the page footer.
    #[serde(default)]
    pub ui_support_url: Option<String>,

    /// Link to a privacy policy, shown in the page footer.
    #[serde(default)]
    pub ui_privacy_url: Option<String>,

    /// Link to the terms of service, shown in the page footer.
    #[serde(default)]
    pub ui_terms_url: Option<String>,

    /// Failed second-factor (TOTP) attempts allowed on one login before the
    /// pending sign-in is discarded and the user has to start over. The
    /// per-user `[rate_limit_user_auth]` limiter applies on top.
    #[serde(default = "default_mfa_max_attempts")]
    #[validate(range(min = 1, max = 20))]
    pub mfa_max_attempts: u32,

    /// Show the `logo_uri` registered for a client on its login and consent
    /// pages. The browser then fetches that image from the client's host
    /// (allowed by adding `https:` to the CSP `img-src`), which tells that
    /// host who is signing in; off by default.
    #[serde(default)]
    pub ui_show_client_logos: bool,

    /// Locale used when `Accept-Language` matches none of the available
    /// locale bundles.
    #[serde(default = "default_ui_default_locale")]
    pub ui_default_locale: String,
}

fn default_mfa_max_attempts() -> u32 {
    5
}

fn default_ui_product_name() -> String {
    "OpenStack".to_string()
}

fn default_ui_default_locale() -> String {
    "en".to_string()
}

fn default_signing_key_rotation_days() -> u32 {
    90
}

fn default_argon2_memory_kib() -> u32 {
    65536
}

fn default_argon2_time_cost() -> u32 {
    3
}

fn default_argon2_parallelism() -> u32 {
    4
}

fn default_access_token_lifetime_minutes() -> u32 {
    15
}

fn default_token_rate_limit_burst_size() -> u32 {
    10
}

fn default_token_rate_limit_replenish_per_minute() -> u32 {
    60
}

fn default_id_token_lifetime_minutes() -> u32 {
    15
}

fn default_authorization_code_lifetime_seconds() -> u32 {
    60
}

fn default_refresh_token_lifetime_days() -> u32 {
    30
}

fn default_refresh_token_absolute_lifetime_days() -> u32 {
    90
}

fn default_refresh_token_reuse_grace_minutes() -> u32 {
    10
}

fn default_pre_auth_session_lifetime_minutes() -> u32 {
    10
}

fn default_device_code_lifetime_minutes() -> u32 {
    10
}

fn default_device_code_poll_interval_seconds() -> u32 {
    5
}

fn default_device_code_invalid_quiet_period_seconds() -> u32 {
    300
}

fn default_revoked_family_retention_days() -> u32 {
    30
}

fn default_session_janitor_interval_seconds() -> u32 {
    300
}

impl Default for Oauth2Provider {
    fn default() -> Self {
        Self {
            signing_algorithm: SigningAlgorithm::default(),
            signing_key_rotation_days: default_signing_key_rotation_days(),
            argon2_memory_kib: default_argon2_memory_kib(),
            argon2_time_cost: default_argon2_time_cost(),
            argon2_parallelism: default_argon2_parallelism(),
            access_token_lifetime_minutes: default_access_token_lifetime_minutes(),
            token_rate_limit_burst_size: default_token_rate_limit_burst_size(),
            token_rate_limit_replenish_per_minute: default_token_rate_limit_replenish_per_minute(),
            id_token_lifetime_minutes: default_id_token_lifetime_minutes(),
            authorization_code_lifetime_seconds: default_authorization_code_lifetime_seconds(),
            refresh_token_lifetime_days: default_refresh_token_lifetime_days(),
            refresh_token_absolute_lifetime_days: default_refresh_token_absolute_lifetime_days(),
            refresh_token_reuse_grace_minutes: default_refresh_token_reuse_grace_minutes(),
            pre_auth_session_lifetime_minutes: default_pre_auth_session_lifetime_minutes(),
            device_code_lifetime_minutes: default_device_code_lifetime_minutes(),
            device_code_poll_interval_seconds: default_device_code_poll_interval_seconds(),
            device_code_invalid_quiet_period_seconds:
                default_device_code_invalid_quiet_period_seconds(),
            revoked_family_retention_days: default_revoked_family_retention_days(),
            session_janitor_interval_seconds: default_session_janitor_interval_seconds(),
            list_limit: ListLimitConfig::default(),
            allow_host_header_issuer: false,
            templates_dir: None,
            static_dir: None,
            ui_product_name: default_ui_product_name(),
            ui_logo_url: None,
            ui_support_url: None,
            ui_privacy_url: None,
            ui_terms_url: None,
            mfa_max_attempts: default_mfa_max_attempts(),
            ui_show_client_logos: false,
            ui_default_locale: default_ui_default_locale(),
        }
    }
}

impl Oauth2Provider {
    /// Check the page customisation settings: the directories must exist and
    /// the branding URLs must be `https://` URLs or absolute paths.
    ///
    /// Called at startup so a typo fails fast instead of silently serving
    /// the default pages.
    pub fn validate_ui(&self) -> Result<(), String> {
        fn check(name: &str, path: &Path) -> Result<(), String> {
            match std::fs::read_dir(path) {
                Ok(_) => Ok(()),
                Err(e) => Err(format!(
                    "[oauth2] {name} `{}` is not a readable directory: {e}",
                    path.display()
                )),
            }
        }
        if let Some(dir) = &self.templates_dir {
            check("templates_dir", dir)?;
        }
        if let Some(dir) = &self.static_dir {
            check("static_dir", dir)?;
        }
        for (name, url) in [
            ("ui_logo_url", &self.ui_logo_url),
            ("ui_support_url", &self.ui_support_url),
            ("ui_privacy_url", &self.ui_privacy_url),
            ("ui_terms_url", &self.ui_terms_url),
        ] {
            if let Some(url) = url
                && !(url.starts_with("https://")
                    || (url.starts_with('/') && !url.starts_with("//")))
            {
                return Err(format!(
                    "[oauth2] {name} must be an https:// URL or an absolute path, got `{url}`"
                ));
            }
        }
        if self.ui_product_name.trim().is_empty() {
            return Err("[oauth2] ui_product_name must not be empty".to_string());
        }
        if self.ui_default_locale.is_empty()
            || !self
                .ui_default_locale
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err("[oauth2] ui_default_locale must be a locale tag such as `en`".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let cfg = Oauth2Provider::default();
        assert_eq!(cfg.signing_algorithm, SigningAlgorithm::Es256);
        assert_eq!(cfg.signing_key_rotation_days, 90);
        assert_eq!(cfg.access_token_lifetime_minutes, 15);
        assert_eq!(cfg.token_rate_limit_burst_size, 10);
        assert_eq!(cfg.token_rate_limit_replenish_per_minute, 60);
        assert_eq!(cfg.id_token_lifetime_minutes, 15);
        assert_eq!(cfg.authorization_code_lifetime_seconds, 60);
        assert_eq!(cfg.refresh_token_lifetime_days, 30);
        assert_eq!(cfg.refresh_token_absolute_lifetime_days, 90);
        assert_eq!(cfg.refresh_token_reuse_grace_minutes, 10);
        assert_eq!(cfg.pre_auth_session_lifetime_minutes, 10);
        assert_eq!(cfg.device_code_lifetime_minutes, 10);
        assert_eq!(cfg.device_code_poll_interval_seconds, 5);
        assert_eq!(cfg.device_code_invalid_quiet_period_seconds, 300);
        assert_eq!(cfg.revoked_family_retention_days, 30);
        assert_eq!(cfg.session_janitor_interval_seconds, 300);
        assert!(!cfg.allow_host_header_issuer);
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_validate_rejects_refresh_token_reuse_grace_minutes_over_30() {
        let cfg: Oauth2Provider =
            serde_json::from_str(r#"{"refresh_token_reuse_grace_minutes": 31}"#).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_zero_refresh_token_absolute_lifetime_days() {
        let cfg: Oauth2Provider =
            serde_json::from_str(r#"{"refresh_token_absolute_lifetime_days": 0}"#).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_deserialize_defaults_when_empty() {
        let cfg: Oauth2Provider = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.signing_algorithm, SigningAlgorithm::Es256);
        assert_eq!(cfg.signing_key_rotation_days, 90);
    }

    #[test]
    fn test_deserialize_rs256_override() {
        let cfg: Oauth2Provider =
            serde_json::from_str(r#"{"signing_algorithm": "RS256"}"#).unwrap();
        assert_eq!(cfg.signing_algorithm, SigningAlgorithm::Rs256);
        assert_eq!(cfg.signing_algorithm.to_string(), "RS256");
    }

    #[test]
    fn test_validate_rejects_zero_rotation_days() {
        let cfg: Oauth2Provider =
            serde_json::from_str(r#"{"signing_key_rotation_days": 0}"#).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_rejects_zero_janitor_settings() {
        let cfg: Oauth2Provider =
            serde_json::from_str(r#"{"revoked_family_retention_days": 0}"#).unwrap();
        assert!(cfg.validate().is_err());
        let cfg: Oauth2Provider =
            serde_json::from_str(r#"{"session_janitor_interval_seconds": 0}"#).unwrap();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_validate_ui() {
        let cfg = Oauth2Provider::default();
        assert!(cfg.validate_ui().is_ok());

        let dir = std::env::temp_dir();
        let cfg = Oauth2Provider {
            templates_dir: Some(dir.clone()),
            static_dir: Some(dir),
            ..Default::default()
        };
        assert!(cfg.validate_ui().is_ok());

        let cfg = Oauth2Provider {
            static_dir: Some(PathBuf::from("/nonexistent/keystone-static")),
            ..Default::default()
        };
        assert!(cfg.validate_ui().unwrap_err().contains("static_dir"));
    }

    #[test]
    fn test_validate_ui_branding() {
        let cfg = Oauth2Provider::default();
        assert_eq!(cfg.ui_product_name, "OpenStack");
        assert_eq!(cfg.ui_default_locale, "en");
        let ok = Oauth2Provider {
            ui_logo_url: Some("/v4/oauth2/static/logo.svg".into()),
            ui_support_url: Some("https://example.com/help".into()),
            ..Default::default()
        };
        assert!(ok.validate_ui().is_ok());
        for bad in [
            "http://example.com/x",
            "javascript:alert(1)",
            "//evil.example/x",
        ] {
            let cfg = Oauth2Provider {
                ui_privacy_url: Some(bad.into()),
                ..Default::default()
            };
            assert!(
                cfg.validate_ui().unwrap_err().contains("ui_privacy_url"),
                "{bad}"
            );
        }
        let cfg = Oauth2Provider {
            ui_default_locale: "en us".into(),
            ..Default::default()
        };
        assert!(cfg.validate_ui().is_err());
    }
}
