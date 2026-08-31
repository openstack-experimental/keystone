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
//! # Token metrics (ADR 0031 "Tokens")
//!
//! Process-wide Prometheus primitives for the token subsystem, exposed as a
//! single [`TOKEN_METRICS`] static (ADR 0031's "Design pattern" — a
//! `LazyLock` avoids threading a new field through
//! `ServiceState`/`Provider`/every builder and mock across the workspace).
//!
//! **Cardinality / PII guardrail (ADR 0031):** `driver` is always
//! `"fernet"`/`"jws"` (`TokenProviderDriver::to_string()`,
//! `crates/config/src/token.rs`); `method` is the fixed ADR 0031 method set
//! (see [`issue_method_label`]); `outcome` is `"success"`/`"failure"`;
//! `reason` on `revoked_total` is one of `"user_request"`/`"admin"`/
//! `"cascade"`/`"expired_trust"`. Never a raw token/user/trust ID.

use std::sync::LazyLock;

use openstack_keystone_metrics::{
    Gauge, LabeledCounter, LabeledHistogram, PrometheusText, write_metric_header,
};

use openstack_keystone_core_types::auth::AuthenticationContext;
use openstack_keystone_core_types::token::TokenProviderError;

/// Process-wide token metrics (ADR 0031).
pub struct TokenMetrics {
    /// `keystone_token_issued_total{driver,method}` — issuance volume.
    pub issued_total: LabeledCounter<2>,
    /// `keystone_token_validated_total{driver,outcome}` — validation
    /// volume/outcome.
    pub validated_total: LabeledCounter<2>,
    /// `keystone_token_validation_duration_seconds{driver}` — validation
    /// latency.
    pub validation_duration_seconds: LabeledHistogram<1>,
    /// `keystone_token_revoked_total{reason}` — revocation volume.
    pub revoked_total: LabeledCounter<1>,
    /// `keystone_token_revocation_list_size` — in-memory/DB revocation-event
    /// backlog size. No labels.
    pub revocation_list_size: Gauge,
}

impl TokenMetrics {
    fn new() -> Self {
        Self {
            issued_total: LabeledCounter::new(["driver", "method"]),
            validated_total: LabeledCounter::new(["driver", "outcome"]),
            validation_duration_seconds: LabeledHistogram::new(["driver"]),
            revoked_total: LabeledCounter::new(["reason"]),
            revocation_list_size: Gauge::new(),
        }
    }
}

/// Process-wide [`TokenMetrics`] instance (ADR 0031 "Design pattern").
pub static TOKEN_METRICS: LazyLock<TokenMetrics> = LazyLock::new(TokenMetrics::new);

impl PrometheusText for TokenMetrics {
    fn format_prometheus_text(&self) -> String {
        let mut out = String::new();

        write_metric_header(
            &mut out,
            "keystone_token_issued_total",
            "Token issuance volume by driver and authentication method.",
            "counter",
        );
        self.issued_total
            .write_lines(&mut out, "keystone_token_issued_total");

        write_metric_header(
            &mut out,
            "keystone_token_validated_total",
            "Token validation volume by driver and outcome.",
            "counter",
        );
        self.validated_total
            .write_lines(&mut out, "keystone_token_validated_total");

        write_metric_header(
            &mut out,
            "keystone_token_validation_duration_seconds",
            "Token validation latency by driver.",
            "histogram",
        );
        self.validation_duration_seconds
            .write_lines(&mut out, "keystone_token_validation_duration_seconds");

        write_metric_header(
            &mut out,
            "keystone_token_revoked_total",
            "Token revocation volume by reason.",
            "counter",
        );
        self.revoked_total
            .write_lines(&mut out, "keystone_token_revoked_total");

        write_metric_header(
            &mut out,
            "keystone_token_revocation_list_size",
            "In-memory/DB revocation-event backlog size.",
            "gauge",
        );
        self.revocation_list_size
            .write_line(&mut out, "keystone_token_revocation_list_size");

        out
    }
}

/// Maps an [`AuthenticationContext`] to the ADR 0031 fixed `method` label
/// value for `keystone_token_issued_total`, or `None` when the context does
/// not correspond to one of the catalog's nine method values (e.g. `Trust`,
/// `Admin`, `Totp`, `Mapping`, `WasmPlugin`) — the cardinality guardrail
/// requires every label value to come from that fixed set, so an unmapped
/// context is simply not recorded rather than inventing a new value.
pub fn issue_method_label(ctx: &AuthenticationContext) -> Option<&'static str> {
    match ctx {
        AuthenticationContext::Password => Some("password"),
        AuthenticationContext::Token(_) => Some("token"),
        AuthenticationContext::ApplicationCredential { .. } => Some("application_credential"),
        AuthenticationContext::Ec2Credential => Some("ec2"),
        // "Login using OIDC federation" (core-types doc comment) — ADR
        // 0031's `federation` method (ADR 0007/0020), distinct from the
        // `oauth2` method (ADR 0026 OAuth2/OIDC *provider* surface, which
        // does not mint a `FernetToken` through this path).
        AuthenticationContext::Oidc { .. } => Some("federation"),
        AuthenticationContext::K8s(_) => Some("k8s"),
        AuthenticationContext::WebauthN => Some("passkey"),
        AuthenticationContext::Trust { .. }
        | AuthenticationContext::Admin
        | AuthenticationContext::Totp
        | AuthenticationContext::Mapping(_)
        | AuthenticationContext::WasmPlugin { .. } => None,
    }
}

/// Maps a [`TokenProviderError`] to a bounded, PII-free reason string.
///
/// `TokenProviderError` is `#[non_exhaustive]`, so this always ends in a
/// catch-all `"ProviderError"` arm for the wrapped-provider-error variants
/// whose detail isn't meaningful at the metrics layer (`Driver`,
/// `AssignmentProvider`, `ResourceProvider`, `RoleProvider`,
/// `RevokeProvider`, `TrustProvider`, `IdentityProvider`, `StructBuilder`,
/// `Validation`, `Uuid`, `Conflict`, `ExpiryCalculation`,
/// `UnsupportedDriver`, `UnsupportedTRDriver`, and any future variant).
pub fn token_failure_reason(e: &TokenProviderError) -> &'static str {
    match e {
        TokenProviderError::Authentication(source) => {
            crate::auth_metrics::auth_failure_reason(source)
        }
        TokenProviderError::Expired => "TokenExpired",
        TokenProviderError::TokenRevoked => "TokenRevoked",
        TokenProviderError::UserNotFound(_) => "UserNotFound",
        TokenProviderError::UserDisabled(_) => "UserDisabled",
        TokenProviderError::UserDomainDisabled => "UserDomainDisabled",
        TokenProviderError::DomainDisabled(_) => "DomainDisabled",
        TokenProviderError::ProjectDisabled(_) => "ProjectDisabled",
        TokenProviderError::TrustNotFound(_) => "TrustNotFound",
        TokenProviderError::TrustorDomainDisabled => "TrustorDomainDisabled",
        TokenProviderError::TrustorUserDisabled(_) => "TrustorUserDisabled",
        TokenProviderError::UserIsNotTrustee => "UserIsNotTrustee",
        TokenProviderError::ApplicationCredentialNotFound(_) => "ApplicationCredentialNotFound",
        TokenProviderError::ApplicationCredentialExpired => "ApplicationCredentialExpired",
        TokenProviderError::ApplicationCredentialScopeMismatch => {
            "ApplicationCredentialScopeMismatch"
        }
        TokenProviderError::ScopeMissing => "ScopeMissing",
        TokenProviderError::SubjectMissing => "SubjectMissing",
        TokenProviderError::RestrictedTokenNotProjectScoped => "RestrictedTokenNotProjectScoped",
        TokenProviderError::TokenRestrictionNotFound(_) => "TokenRestrictionNotFound",
        TokenProviderError::TokenRestrictionPrincipalNotSupported => {
            "TokenRestrictionPrincipalNotSupported"
        }
        TokenProviderError::ActorHasNoRolesOnTarget => "ActorHasNoRolesOnTarget",
        TokenProviderError::UnsupportedPrinciple => "UnsupportedPrinciple",
        TokenProviderError::FederatedPayloadMissingData => "FederatedPayloadMissingData",
        _ => "ProviderError",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use openstack_keystone_core_types::application_credential::ApplicationCredentialBuilder;
    use openstack_keystone_core_types::auth::AuthenticationError;

    #[test]
    fn issued_and_validated_are_labeled_by_driver() {
        let metrics = TokenMetrics::new();
        metrics.issued_total.inc(["fernet", "password"]);
        metrics.validated_total.inc(["fernet", "success"]);
        metrics.validation_duration_seconds.record(["fernet"], 0.01);
        assert_eq!(metrics.issued_total.get(["fernet", "password"]), 1);
        assert_eq!(metrics.validated_total.get(["fernet", "success"]), 1);
    }

    #[test]
    fn revoked_total_is_labeled_by_reason_only() {
        let metrics = TokenMetrics::new();
        metrics.revoked_total.inc(["user_request"]);
        metrics.revoked_total.inc(["cascade"]);
        assert_eq!(metrics.revoked_total.get(["user_request"]), 1);
        assert_eq!(metrics.revoked_total.get(["cascade"]), 1);
        assert_eq!(metrics.revoked_total.get(["admin"]), 0);
    }

    #[test]
    fn revocation_list_size_is_a_plain_gauge() {
        let metrics = TokenMetrics::new();
        metrics.revocation_list_size.set(42);
        assert_eq!(metrics.revocation_list_size.get(), 42);
    }

    #[test]
    fn format_prometheus_text_includes_all_series_headers() {
        let metrics = TokenMetrics::new();
        metrics.issued_total.inc(["fernet", "password"]);
        metrics.validated_total.inc(["fernet", "success"]);
        metrics.validation_duration_seconds.record(["fernet"], 0.01);
        metrics.revoked_total.inc(["admin"]);
        metrics.revocation_list_size.set(1);
        let text = metrics.format_prometheus_text();
        assert!(text.contains("# TYPE keystone_token_issued_total counter"));
        assert!(text.contains("# TYPE keystone_token_validated_total counter"));
        assert!(text.contains("# TYPE keystone_token_validation_duration_seconds histogram"));
        assert!(text.contains("# TYPE keystone_token_revoked_total counter"));
        assert!(text.contains("# TYPE keystone_token_revocation_list_size gauge"));
        assert!(text.contains("keystone_token_revocation_list_size 1"));
    }

    #[test]
    fn issue_method_label_maps_fixed_set_and_skips_unmapped_contexts() {
        assert_eq!(
            issue_method_label(&AuthenticationContext::Password),
            Some("password")
        );
        assert_eq!(
            issue_method_label(&AuthenticationContext::Ec2Credential),
            Some("ec2")
        );
        let app_cred = ApplicationCredentialBuilder::default()
            .id("cred-id")
            .name("cred-name")
            .project_id("project-id")
            .user_id("user-id")
            .roles(Vec::new())
            .unrestricted(false)
            .build()
            .expect("valid application credential fixture");
        assert_eq!(
            issue_method_label(&AuthenticationContext::ApplicationCredential {
                application_credential: app_cred,
                token: None,
            }),
            Some("application_credential")
        );
        assert_eq!(issue_method_label(&AuthenticationContext::Admin), None);
        assert_eq!(issue_method_label(&AuthenticationContext::Totp), None);
    }

    #[test]
    fn token_failure_reason_delegates_authentication_variant() {
        assert_eq!(
            token_failure_reason(&TokenProviderError::Authentication(
                AuthenticationError::UserLocked("u".into())
            )),
            "UserLocked"
        );
        assert_eq!(
            token_failure_reason(&TokenProviderError::Expired),
            "TokenExpired"
        );
        assert_eq!(
            token_failure_reason(&TokenProviderError::TokenRevoked),
            "TokenRevoked"
        );
    }

    #[test]
    fn token_failure_reason_falls_back_for_non_exhaustive_variants() {
        assert_eq!(
            token_failure_reason(&TokenProviderError::Driver {
                source: Box::new(std::io::Error::other("boom")),
            }),
            "ProviderError"
        );
    }
}
