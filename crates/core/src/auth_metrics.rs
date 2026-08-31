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
//! # Authentication metrics (ADR 0031 "Authentication")
//!
//! Process-wide Prometheus primitives for the authentication subsystem,
//! exposed as a single [`AUTH_METRICS`] static (see ADR 0031's "Design
//! pattern" — a `LazyLock` avoids threading a new field through
//! `ServiceState`/`Provider`/every builder and mock across the workspace).
//!
//! Call sites increment these directly once an outcome is known, e.g.
//! `crate::auth_metrics::AUTH_METRICS.attempts_total.inc(["password",
//! "success"])`, or via the [`AuthMetrics::record_attempt`] convenience
//! method that fills in `attempts_total`/`duration_seconds`/`failures_total`
//! together from a single `Result`.
//!
//! **Cardinality / PII guardrail (ADR 0031):** `method` is always one of the
//! fixed set documented on [`AuthMetrics::record_attempt`]; `reason` is
//! always a `&'static str` returned by [`auth_failure_reason`] or
//! [`identity_failure_reason`] below — never a raw error message, user ID,
//! or other unbounded value. `plugin_name` is the operator-configured
//! `[auth_plugin.<name>]` section name (ADR 0025), the same bounded value
//! already used by the pre-existing `keystone_auth_plugin_load_failure`
//! metric (`crates/keystone/src/auth_plugin_startup.rs`).

use std::sync::LazyLock;

use openstack_keystone_metrics::{
    Counter, LabeledCounter, LabeledHistogram, PrometheusText, write_metric_header,
};

use openstack_keystone_core_types::assignment::AssignmentProviderError;
use openstack_keystone_core_types::auth::AuthenticationError;
use openstack_keystone_core_types::catalog::CatalogProviderError;
use openstack_keystone_core_types::identity::IdentityProviderError;
use openstack_keystone_core_types::resource::ResourceProviderError;
use openstack_keystone_core_types::role::RoleProviderError;

/// Process-wide authentication metrics (ADR 0031).
pub struct AuthMetrics {
    /// `keystone_auth_attempts_total{method,outcome}` — auth volume by
    /// method, `outcome` is `"success"`/`"failure"`.
    pub attempts_total: LabeledCounter<2>,
    /// `keystone_auth_duration_seconds{method}` — auth latency.
    pub duration_seconds: LabeledHistogram<1>,
    /// `keystone_auth_failures_total{method,reason}` — failure breakdown,
    /// `reason` from [`auth_failure_reason`]/[`identity_failure_reason`].
    pub failures_total: LabeledCounter<2>,
    /// `keystone_auth_lockouts_total` — PCI-DSS account lockouts (ADR 0010).
    /// No labels: the lockout itself already carries no user identifier
    /// onto this metric surface (only the audit trail does).
    pub lockouts_total: Counter,
    /// `keystone_auth_plugin_invocations_total{plugin_name,outcome}` — WASM
    /// plugin call volume (ADR 0025).
    pub plugin_invocations_total: LabeledCounter<2>,
    /// `keystone_auth_plugin_duration_seconds{plugin_name}` — WASM plugin
    /// call latency (ADR 0025).
    pub plugin_duration_seconds: LabeledHistogram<1>,
}

impl AuthMetrics {
    fn new() -> Self {
        Self {
            attempts_total: LabeledCounter::new(["method", "outcome"]),
            duration_seconds: LabeledHistogram::new(["method"]),
            failures_total: LabeledCounter::new(["method", "reason"]),
            lockouts_total: Counter::new(),
            plugin_invocations_total: LabeledCounter::new(["plugin_name", "outcome"]),
            plugin_duration_seconds: LabeledHistogram::new(["plugin_name"]),
        }
    }

    /// Records one authentication attempt's outcome and latency.
    ///
    /// `method` MUST be one of the fixed ADR 0031 values: `"password"`,
    /// `"token"`, `"application_credential"`, `"ec2"`, `"federation"`,
    /// `"oauth2"`, `"passkey"`, `"k8s"`, `"api_key"`. `reason` is `None` for
    /// a successful attempt, or `Some(bounded_reason)` for a failed one
    /// (`attempts_total`'s `outcome` label is derived from this, and
    /// `failures_total` is only incremented when it is `Some`).
    pub fn record_attempt(&self, method: &str, duration_seconds: f64, reason: Option<&str>) {
        let outcome = if reason.is_some() {
            "failure"
        } else {
            "success"
        };
        self.attempts_total.inc([method, outcome]);
        self.duration_seconds.record([method], duration_seconds);
        if let Some(reason) = reason {
            self.failures_total.inc([method, reason]);
        }
    }
}

/// Process-wide [`AuthMetrics`] instance (ADR 0031 "Design pattern").
pub static AUTH_METRICS: LazyLock<AuthMetrics> = LazyLock::new(AuthMetrics::new);

impl PrometheusText for AuthMetrics {
    fn format_prometheus_text(&self) -> String {
        let mut out = String::new();

        write_metric_header(
            &mut out,
            "keystone_auth_attempts_total",
            "Authentication attempts by method and outcome.",
            "counter",
        );
        self.attempts_total
            .write_lines(&mut out, "keystone_auth_attempts_total");

        write_metric_header(
            &mut out,
            "keystone_auth_duration_seconds",
            "Authentication latency by method.",
            "histogram",
        );
        self.duration_seconds
            .write_lines(&mut out, "keystone_auth_duration_seconds");

        write_metric_header(
            &mut out,
            "keystone_auth_failures_total",
            "Authentication failures by method and sanitized reason.",
            "counter",
        );
        self.failures_total
            .write_lines(&mut out, "keystone_auth_failures_total");

        write_metric_header(
            &mut out,
            "keystone_auth_lockouts_total",
            "PCI-DSS account lockouts (ADR 0010).",
            "counter",
        );
        self.lockouts_total
            .write_line(&mut out, "keystone_auth_lockouts_total");

        write_metric_header(
            &mut out,
            "keystone_auth_plugin_invocations_total",
            "Dynamic auth-plugin (ADR 0025) call volume by plugin and outcome.",
            "counter",
        );
        self.plugin_invocations_total
            .write_lines(&mut out, "keystone_auth_plugin_invocations_total");

        write_metric_header(
            &mut out,
            "keystone_auth_plugin_duration_seconds",
            "Dynamic auth-plugin (ADR 0025) call latency by plugin.",
            "histogram",
        );
        self.plugin_duration_seconds
            .write_lines(&mut out, "keystone_auth_plugin_duration_seconds");

        out
    }
}

/// Maps an [`AuthenticationError`] to a bounded, PII-free reason string for
/// the `keystone_auth_failures_total`/`keystone_token_*` `reason` labels.
///
/// Mirrors the variant-name style (and, for every shared variant, the exact
/// string) of `sanitize_authentication_error`
/// (`crates/keystone/src/audit.rs`) — kept as an independent copy rather
/// than a shared call because `openstack-keystone-core` cannot depend on
/// the `keystone` binary crate (the dependency edge runs the other way).
/// If `AuthenticationError` gains a variant, update both match statements.
pub fn auth_failure_reason(e: &AuthenticationError) -> &'static str {
    match e {
        AuthenticationError::DomainDisabled(_) => "DomainDisabled",
        AuthenticationError::ProjectDisabled(_) => "ProjectDisabled",
        AuthenticationError::TrustorUserDisabled(_) => "TrustorUserDisabled",
        AuthenticationError::UserDisabled(_) => "UserDisabled",
        AuthenticationError::UserLocked(_) => "UserLocked",
        AuthenticationError::UserPasswordExpired(_) => "UserPasswordExpired",
        AuthenticationError::Provider { source, .. } => {
            extract_provider_name(source.as_ref()).unwrap_or("ProviderError")
        }
        AuthenticationError::Validation(_) => "ValidationError",
        AuthenticationError::StructBuilder { .. } => "StructBuilderError",
        AuthenticationError::AuthTokenExpired => "TokenExpired",
        AuthenticationError::AuthApplicationCredentialExpired => "AuthCredentialExpired",
        AuthenticationError::Unauthorized => "Unauthorized",
        AuthenticationError::Forbidden => "Forbidden",
        AuthenticationError::UserNameOrPasswordWrong => "UserNameOrPasswordWrong",
        AuthenticationError::ActorHasNoRolesOnTarget => "ActorHasNoRolesOnTarget",
        AuthenticationError::AuthnPrincipalMismatch => "PrincipalMismatch",
        AuthenticationError::AuthzPrincipalMismatch => "PrincipalMismatch",
        AuthenticationError::SecurityContextNotResolved => "SecurityContextNotResolved",
        AuthenticationError::ScopeNotAllowed => "ScopeNotAllowed",
        AuthenticationError::TokenNotInContext => "TokenNotInContext",
        AuthenticationError::TokenRenewalForbidden => "TokenRenewalForbidden",
        AuthenticationError::TrustorPrincipalUseNotSupported => "TrustorPrincipalUseNotSupported",
        AuthenticationError::TrustorDomainDisabled => "TrustorDomainDisabled",
        AuthenticationError::UserDomainDisabled => "UserDomainDisabled",
        AuthenticationError::RoleConversionFailed => "RoleConversionFailed",
        AuthenticationError::NoAuthorizationsFound => "NoAuthorizationsFound",
        AuthenticationError::MultipleScopesForbidden => "MultipleScopesForbidden",
        AuthenticationError::SystemScopeForbiddenForApiKey => "SystemScopeForbiddenForApiKey",
        AuthenticationError::NonDomainScopeForbiddenForApiKey => "NonDomainScopeForbiddenForApiKey",
        AuthenticationError::Ec2AccessKeyNotFound => "Ec2AccessKeyNotFound",
        AuthenticationError::Ec2SignatureMissing => "Ec2SignatureMissing",
        AuthenticationError::Ec2SignatureInvalid => "Ec2SignatureInvalid",
        AuthenticationError::Ec2UnknownSignatureVersion => "Ec2UnknownSignatureVersion",
        AuthenticationError::Ec2TimestampMissing => "Ec2TimestampMissing",
        AuthenticationError::Ec2TimestampInvalid(_) => "Ec2TimestampInvalid",
        AuthenticationError::Ec2TimestampExpired => "Ec2TimestampExpired",
        AuthenticationError::Ec2CredentialScopeDateMismatch => "Ec2CredentialScopeDateMismatch",
        AuthenticationError::TotpPasscodeInvalid => "TotpPasscodeInvalid",
        AuthenticationError::PluginVersionMismatch(_) => "PluginVersionMismatch",
    }
}

/// Type-only dispatch mirroring `extract_provider_name`
/// (`crates/keystone/src/audit.rs`) — no provider error string content is
/// used, guaranteeing PII in third-party provider errors never reaches a
/// metric label.
fn extract_provider_name(
    source: &(dyn std::error::Error + Send + Sync + 'static),
) -> Option<&'static str> {
    if source.is::<IdentityProviderError>() {
        Some("Identity")
    } else if source.is::<CatalogProviderError>() {
        Some("Catalog")
    } else if source.is::<RoleProviderError>() {
        Some("Role")
    } else if source.is::<AssignmentProviderError>() {
        Some("Assignment")
    } else if source.is::<ResourceProviderError>() {
        Some("Resource")
    } else {
        None
    }
}

/// Maps an [`IdentityProviderError`] (the error type returned by
/// `IdentityApi::authenticate_by_password`/`authenticate_by_totp`) to a
/// bounded, PII-free reason string for `keystone_auth_failures_total`.
///
/// Exhaustive match: every variant is explicitly handled, so a new
/// `IdentityProviderError` variant breaks compilation here rather than
/// silently falling back to a generic reason.
pub fn identity_failure_reason(e: &IdentityProviderError) -> &'static str {
    match e {
        IdentityProviderError::Authentication { source } => auth_failure_reason(source),
        IdentityProviderError::Conflict(_) => "Conflict",
        IdentityProviderError::CredentialProvider { .. } => "ProviderError",
        IdentityProviderError::DateError => "DateError",
        IdentityProviderError::Driver(_) => "Driver",
        IdentityProviderError::GroupNotFound(_) => "GroupNotFound",
        IdentityProviderError::Join { .. } => "ProviderError",
        IdentityProviderError::LdapConnection(_) => "LdapConnection",
        IdentityProviderError::LdapFilterBuild(_) => "LdapFilterBuild",
        IdentityProviderError::MalformedUser(_) => "MalformedUser",
        IdentityProviderError::NoPasswordsForUser(_) => "NoPasswordsForUser",
        IdentityProviderError::NoPasswordHash(_) => "NoPasswordHash",
        IdentityProviderError::NoMainUserEntry(_) => "NoMainUserEntry",
        IdentityProviderError::NotImplemented(_) => "NotImplemented",
        IdentityProviderError::PasswordHash { .. } => "PasswordHash",
        IdentityProviderError::Readonly(_) => "Readonly",
        IdentityProviderError::ResourceProvider { .. } => "ProviderError",
        IdentityProviderError::SecurityCompliance(_) => "SecurityCompliance",
        IdentityProviderError::Serde { .. } => "Serde",
        IdentityProviderError::StructBuilder { .. } => "StructBuilderError",
        IdentityProviderError::TooManyRequests { .. } => "TooManyRequests",
        IdentityProviderError::UnsupportedDriver(_) => "UnsupportedDriver",
        IdentityProviderError::UserIdMissing => "UserIdMissing",
        IdentityProviderError::UserIdOrNameWithDomain => "UserIdOrNameWithDomain",
        IdentityProviderError::UserNotFound(_) => "UserNotFound",
        IdentityProviderError::Validation { .. } => "ValidationError",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_attempt_success_increments_only_attempts_and_duration() {
        let metrics = AuthMetrics::new();
        metrics.record_attempt("password", 0.01, None);
        assert_eq!(metrics.attempts_total.get(["password", "success"]), 1);
        assert_eq!(metrics.attempts_total.get(["password", "failure"]), 0);
        assert_eq!(metrics.failures_total.get(["password", "anything"]), 0);
    }

    #[test]
    fn record_attempt_failure_increments_failures_with_reason() {
        let metrics = AuthMetrics::new();
        metrics.record_attempt("password", 0.02, Some("UserNameOrPasswordWrong"));
        assert_eq!(metrics.attempts_total.get(["password", "failure"]), 1);
        assert_eq!(
            metrics
                .failures_total
                .get(["password", "UserNameOrPasswordWrong"]),
            1
        );
    }

    #[test]
    fn lockouts_total_has_no_labels() {
        let metrics = AuthMetrics::new();
        metrics.lockouts_total.inc();
        assert_eq!(metrics.lockouts_total.get(), 1);
    }

    #[test]
    fn plugin_invocation_metrics_are_labeled_by_plugin_name() {
        let metrics = AuthMetrics::new();
        metrics.plugin_invocations_total.inc(["p1", "success"]);
        metrics.plugin_duration_seconds.record(["p1"], 0.05);
        assert_eq!(metrics.plugin_invocations_total.get(["p1", "success"]), 1);
    }

    #[test]
    fn format_prometheus_text_includes_all_series_headers() {
        let metrics = AuthMetrics::new();
        metrics.record_attempt("password", 0.01, None);
        metrics.lockouts_total.inc();
        metrics.plugin_invocations_total.inc(["p", "failure"]);
        metrics.plugin_duration_seconds.record(["p"], 0.02);
        let text = metrics.format_prometheus_text();
        assert!(text.contains("# TYPE keystone_auth_attempts_total counter"));
        assert!(text.contains("# TYPE keystone_auth_duration_seconds histogram"));
        assert!(text.contains("# TYPE keystone_auth_failures_total counter"));
        assert!(text.contains("# TYPE keystone_auth_lockouts_total counter"));
        assert!(text.contains("# TYPE keystone_auth_plugin_invocations_total counter"));
        assert!(text.contains("# TYPE keystone_auth_plugin_duration_seconds histogram"));
        assert!(
            text.contains(
                "keystone_auth_attempts_total{method=\"password\",outcome=\"success\"} 1"
            )
        );
        assert!(text.contains("keystone_auth_lockouts_total 1"));
    }

    #[test]
    fn auth_failure_reason_covers_provider_and_plain_variants() {
        assert_eq!(
            auth_failure_reason(&AuthenticationError::UserLocked("u".into())),
            "UserLocked"
        );
        assert_eq!(
            auth_failure_reason(&AuthenticationError::UserNameOrPasswordWrong),
            "UserNameOrPasswordWrong"
        );
        let wrapped = AuthenticationError::Provider {
            source: Box::new(IdentityProviderError::UserIdMissing),
            context: None,
        };
        assert_eq!(auth_failure_reason(&wrapped), "Identity");
    }

    #[test]
    fn identity_failure_reason_delegates_authentication_variant() {
        let e = IdentityProviderError::Authentication {
            source: AuthenticationError::UserNameOrPasswordWrong,
        };
        assert_eq!(identity_failure_reason(&e), "UserNameOrPasswordWrong");
        assert_eq!(
            identity_failure_reason(&IdentityProviderError::UserIdOrNameWithDomain),
            "UserIdOrNameWithDomain"
        );
        assert_eq!(
            identity_failure_reason(&IdentityProviderError::TooManyRequests {
                retry_after_secs: 1
            }),
            "TooManyRequests"
        );
    }
}
