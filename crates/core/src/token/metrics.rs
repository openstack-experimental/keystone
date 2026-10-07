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

use openstack_keystone_telemetry::metrics::{
    self, CounterVec, GaugeVec, HistogramVec, LATENCY_BUCKETS, Label, Meter,
};

use openstack_keystone_core_types::auth::AuthenticationContext;
use openstack_keystone_core_types::token::TokenProviderError;

/// Process-wide token metrics (ADR 0031).
pub struct TokenMetrics {
    /// `keystone_token_issued_total{driver,method}` — issuance volume.
    issued_total: CounterVec<2>,
    /// `keystone_token_validated_total{driver,outcome}` — validation
    /// volume/outcome.
    validated_total: CounterVec<2>,
    /// `keystone_token_validation_duration_seconds{driver}` — validation
    /// latency.
    validation_duration_seconds: HistogramVec<1>,
    /// `keystone_token_revoked_total{reason}` — revocation volume.
    revoked_total: CounterVec<1>,
    /// `keystone_token_revocation_list_size` — in-memory/DB revocation-event
    /// backlog size. No labels.
    revocation_list_size: GaugeVec<0>,
}

impl TokenMetrics {
    /// Create the instruments on `meter`.
    pub fn new(meter: &Meter) -> Self {
        Self {
            issued_total: CounterVec::new(
                meter,
                "keystone_token_issued_total",
                "Token issuance volume by driver and authentication method.",
                ["driver", "method"],
            ),
            validated_total: CounterVec::new(
                meter,
                "keystone_token_validated_total",
                "Token validation volume by driver and outcome.",
                ["driver", "outcome"],
            ),
            validation_duration_seconds: HistogramVec::new(
                meter,
                "keystone_token_validation_duration_seconds",
                "Token validation latency by driver.",
                ["driver"],
                &LATENCY_BUCKETS,
            ),
            revoked_total: CounterVec::new(
                meter,
                "keystone_token_revoked_total",
                "Token revocation volume by reason.",
                ["reason"],
            ),
            revocation_list_size: GaugeVec::new(
                meter,
                "keystone_token_revocation_list_size",
                "In-memory/DB revocation-event backlog size.",
                [],
            ),
        }
    }

    /// Counts one issued token. `driver` is the configured token provider
    /// (`fernet`/`jws`); `method` comes from [`issue_method_label`].
    pub fn record_issued(&self, driver: &str, method: &'static str) {
        self.issued_total
            .inc([Label::bounded(driver), Label::fixed(method)]);
    }

    /// Records one token validation: its outcome and latency.
    pub fn record_validation(&self, driver: &str, success: bool, seconds: f64) {
        let driver = Label::bounded(driver);
        let outcome = if success { "success" } else { "failure" };
        self.validated_total.inc([driver, outcome.into()]);
        self.validation_duration_seconds.record(seconds, [driver]);
    }

    /// Counts one revocation. `reason` is one of `"user_request"`,
    /// `"admin"`, `"cascade"`, `"expired_trust"`.
    pub fn record_revoked(&self, reason: &'static str) {
        self.revoked_total.inc([Label::fixed(reason)]);
    }

    /// Sets the current size of the revocation-event backlog.
    pub fn set_revocation_list_size(&self, size: i64) {
        self.revocation_list_size.set(size, []);
    }
}

/// Process-wide [`TokenMetrics`] instance (ADR 0031 "Design pattern").
pub static TOKEN_METRICS: LazyLock<TokenMetrics> =
    LazyLock::new(|| TokenMetrics::new(&metrics::meter()));

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
    use openstack_keystone_telemetry::metrics::MetricsPipeline;

    use super::*;

    fn fixture() -> (MetricsPipeline, TokenMetrics) {
        let pipeline = MetricsPipeline::new();
        let metrics = TokenMetrics::new(&pipeline.meter());
        (pipeline, metrics)
    }

    /// Pins the rendered exposition text (series names, labels, HELP/TYPE and
    /// bucket layout) against `tests/golden/token.prom` (ADR 0040).
    #[test]
    fn golden_exposition() {
        let (pipeline, metrics) = fixture();
        metrics.record_issued("fernet", "password");
        metrics.record_issued("fernet", "token");
        metrics.record_validation("fernet", true, 0.002);
        metrics.record_validation("fernet", true, 0.08);
        metrics
            .validated_total
            .inc(["fernet".into(), "failure".into()]);
        metrics.record_revoked("user_request");
        metrics.set_revocation_list_size(7);
        openstack_keystone_telemetry::assert_golden!("token", pipeline.render());
    }

    use openstack_keystone_core_types::application_credential::ApplicationCredentialBuilder;
    use openstack_keystone_core_types::auth::AuthenticationError;

    #[test]
    fn issued_and_validated_are_labeled_by_driver() {
        let (pipeline, metrics) = fixture();
        metrics.record_issued("fernet", "password");
        metrics.record_validation("fernet", true, 0.01);
        let text = pipeline.render();
        assert!(
            text.contains("keystone_token_issued_total{driver=\"fernet\",method=\"password\"} 1\n")
        );
        assert!(
            text.contains(
                "keystone_token_validated_total{driver=\"fernet\",outcome=\"success\"} 1\n"
            )
        );
        assert!(
            text.contains(
                "keystone_token_validation_duration_seconds_count{driver=\"fernet\"} 1\n"
            )
        );
    }

    #[test]
    fn revoked_total_is_labeled_by_reason_only() {
        let (pipeline, metrics) = fixture();
        metrics.record_revoked("user_request");
        metrics.record_revoked("cascade");
        let text = pipeline.render();
        assert!(text.contains("keystone_token_revoked_total{reason=\"user_request\"} 1\n"));
        assert!(text.contains("keystone_token_revoked_total{reason=\"cascade\"} 1\n"));
        assert!(!text.contains("reason=\"admin\""));
    }

    #[test]
    fn revocation_list_size_is_a_plain_gauge() {
        let (pipeline, metrics) = fixture();
        metrics.set_revocation_list_size(42);
        assert!(pipeline.render().contains("# TYPE keystone_token_revocation_list_size gauge\nkeystone_token_revocation_list_size 42\n"));
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
