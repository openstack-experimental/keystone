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
//! # Prometheus metrics for OPA policy decisions (ADR 0031, "Policy (OPA)")
//!
//! This module owns the process-wide counters/histogram for the "Policy
//! (OPA)" section of the metrics catalog:
//!
//! - `keystone_policy_decisions_total{outcome}` (counter)
//! - `keystone_policy_decision_duration_seconds{transport}` (histogram)
//! - `keystone_policy_errors_total{transport}` (counter)
//!
//! Following the pattern the sibling ADR-0031 subsystems use, the metrics
//! live behind a process-wide [`std::sync::LazyLock`] ([`POLICY_METRICS`])
//! rather than being threaded through `ServiceState`/`Provider` builders --
//! `PolicyEnforcer` is trait-object-dispatched and has hundreds of mock call
//! sites across the workspace, so adding a field there would ripple far
//! beyond this change.
//!
//! **Cardinality / PII guardrail (ADR 0031):** the only label values ever
//! passed here are the fixed `outcome` set (`allow`/`deny`/`error`) and the
//! fixed `transport` set (`http`/`wasm`). No `policy_name`/action label (the
//! ADR explicitly excludes it for this subsystem -- decision volume/latency
//! is tracked in aggregate, not per-rule), no raw resource IDs, and no
//! free-text OPA error message ever becomes a label value.

use std::sync::LazyLock;
use std::time::Duration;

use openstack_keystone_metrics::{
    LabeledCounter, LabeledHistogram, PrometheusText, write_metric_header,
};

use crate::policy::{PolicyError, PolicyEvaluationResult};

/// Prometheus metrics for OPA policy decisions.
///
/// Label sets are fixed and bounded (ADR 0031 cardinality guardrail):
/// - `outcome`: `allow` | `deny` | `error` (see [`outcome_label`] for the
///   exact mapping from a policy-enforcement `Result`).
/// - `transport`: `http` | `wasm`. `wasm` is part of the fixed label set
///   defined by ADR 0031 but is **not currently emitted**: as of this
///   change the only `PolicyEnforcer` implementation in the tree is
///   `HttpPolicyEnforcer` (`crates/keystone/src/policy.rs`), which records
///   `transport = "http"`. No WASM-transport policy enforcer exists yet --
///   when one lands it should record into these same series with
///   `transport = "wasm"` instead of introducing a parallel metric.
pub struct PolicyMetrics {
    /// `keystone_policy_decisions_total{outcome}` -- decision volume.
    pub decisions_total: LabeledCounter<1>,
    /// `keystone_policy_decision_duration_seconds{transport}` -- OPA
    /// round-trip latency. Recorded for every outcome (allow/deny/error),
    /// not just successful round-trips, so a slow-failing OPA call is
    /// visible too.
    pub decision_duration_seconds: LabeledHistogram<1>,
    /// `keystone_policy_errors_total{transport}` -- OPA-unreachable or
    /// malformed-response errors. A subset of the `error` outcome above;
    /// never incremented for a genuine `deny` decision (see
    /// [`outcome_label`]).
    pub errors_total: LabeledCounter<1>,
}

impl PolicyMetrics {
    fn new() -> Self {
        Self {
            decisions_total: LabeledCounter::new(["outcome"]),
            decision_duration_seconds: LabeledHistogram::new(["transport"]),
            errors_total: LabeledCounter::new(["transport"]),
        }
    }
}

/// Process-wide policy metrics, shared by every `PolicyEnforcer`
/// implementation/call site.
pub static POLICY_METRICS: LazyLock<PolicyMetrics> = LazyLock::new(PolicyMetrics::new);

impl PrometheusText for PolicyMetrics {
    fn format_prometheus_text(&self) -> String {
        let mut out = String::new();
        write_metric_header(
            &mut out,
            "keystone_policy_decisions_total",
            "Total number of OPA policy decisions, by outcome.",
            "counter",
        );
        self.decisions_total
            .write_lines(&mut out, "keystone_policy_decisions_total");

        write_metric_header(
            &mut out,
            "keystone_policy_decision_duration_seconds",
            "OPA policy decision (round-trip) latency in seconds.",
            "histogram",
        );
        self.decision_duration_seconds
            .write_lines(&mut out, "keystone_policy_decision_duration_seconds");

        write_metric_header(
            &mut out,
            "keystone_policy_errors_total",
            "Total number of OPA policy evaluation errors (unreachable OPA, \
             malformed response, or a pre-flight invariant failure), by transport.",
            "counter",
        );
        self.errors_total
            .write_lines(&mut out, "keystone_policy_errors_total");

        out
    }
}

/// Derives the `outcome` label from a policy-enforcement `Result`.
///
/// # Mapping
/// - `Ok(_)` -> `"allow"`.
/// - `Err(PolicyError::Forbidden(_))` -> `"deny"`. This is a genuine OPA
///   decision -- the request reached OPA, was evaluated, and was denied --
///   not an infrastructure failure. It does **not** count toward
///   `errors_total`.
/// - Every other `Err(_)` variant -- `PolicyError::IO` (OPA unreachable /
///   transport failure), `Json` (malformed response), `SecurityContextNotResolved`,
///   `ScopeDrift`, `StructBuilder`, `UrlParse`, `UnsupportedScheme`,
///   `Compilation`, `Join`, `Dummy` -- -> `"error"`. These are
///   plumbing/invariant failures rather than policy decisions, mirroring the
///   split `PolicyError`'s `From<PolicyError> for KeystoneApiError`
///   already draws for HTTP status mapping: only `Forbidden` maps to a
///   caller-facing 403, every other variant is an internal (500) failure.
#[must_use]
pub fn outcome_label(result: &Result<PolicyEvaluationResult, PolicyError>) -> &'static str {
    match result {
        Ok(_) => "allow",
        Err(PolicyError::Forbidden(_)) => "deny",
        Err(_) => "error",
    }
}

/// Records one policy-enforcement outcome into [`POLICY_METRICS`] for the
/// given `transport` (`"http"` or `"wasm"`), plus the measured `elapsed`
/// round-trip duration. See [`outcome_label`] for the allow/deny/error
/// mapping and `errors_total` semantics.
pub fn record_decision(
    transport: &str,
    result: &Result<PolicyEvaluationResult, PolicyError>,
    elapsed: Duration,
) {
    record_decision_on(&POLICY_METRICS, transport, result, elapsed);
}

/// Same as [`record_decision`], but against a caller-supplied
/// [`PolicyMetrics`] instance instead of the process-wide static -- used by
/// unit tests so assertions don't race the shared global across the test
/// binary's parallel test threads.
fn record_decision_on(
    metrics: &PolicyMetrics,
    transport: &str,
    result: &Result<PolicyEvaluationResult, PolicyError>,
    elapsed: Duration,
) {
    let outcome = outcome_label(result);
    metrics.decisions_total.inc([outcome]);
    metrics
        .decision_duration_seconds
        .record([transport], elapsed.as_secs_f64());
    if outcome == "error" {
        metrics.errors_total.inc([transport]);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn allowed() -> Result<PolicyEvaluationResult, PolicyError> {
        Ok(PolicyEvaluationResult {
            allow: true,
            can_see_other_domain_resources: None,
            violations: None,
        })
    }

    fn forbidden() -> Result<PolicyEvaluationResult, PolicyError> {
        Err(PolicyError::Forbidden(PolicyEvaluationResult {
            allow: false,
            can_see_other_domain_resources: None,
            violations: None,
        }))
    }

    fn scope_drift() -> Result<PolicyEvaluationResult, PolicyError> {
        Err(PolicyError::ScopeDrift)
    }

    #[test]
    fn outcome_label_maps_ok_to_allow() {
        assert_eq!(outcome_label(&allowed()), "allow");
    }

    #[test]
    fn outcome_label_maps_forbidden_to_deny() {
        assert_eq!(outcome_label(&forbidden()), "deny");
    }

    #[test]
    fn outcome_label_maps_other_errors_to_error() {
        assert_eq!(outcome_label(&scope_drift()), "error");
        assert_eq!(
            outcome_label(&Err(PolicyError::SecurityContextNotResolved)),
            "error"
        );
        assert_eq!(
            outcome_label(&Err(PolicyError::IO(std::io::Error::other("boom")))),
            "error"
        );
    }

    #[test]
    fn record_decision_allow_increments_decisions_and_duration_not_errors() {
        let metrics = PolicyMetrics::new();
        record_decision_on(&metrics, "http", &allowed(), Duration::from_millis(5));

        assert_eq!(metrics.decisions_total.get(["allow"]), 1);
        assert_eq!(metrics.decisions_total.get(["deny"]), 0);
        assert_eq!(metrics.decisions_total.get(["error"]), 0);
        assert_eq!(metrics.errors_total.get(["http"]), 0);

        let mut out = String::new();
        metrics
            .decision_duration_seconds
            .write_lines(&mut out, "keystone_policy_decision_duration_seconds");
        assert!(
            out.contains("keystone_policy_decision_duration_seconds_count{transport=\"http\"} 1")
        );
    }

    #[test]
    fn record_decision_forbidden_counts_as_deny_not_error() {
        let metrics = PolicyMetrics::new();
        record_decision_on(&metrics, "http", &forbidden(), Duration::from_millis(3));

        assert_eq!(metrics.decisions_total.get(["deny"]), 1);
        assert_eq!(metrics.decisions_total.get(["allow"]), 0);
        assert_eq!(metrics.decisions_total.get(["error"]), 0);
        // A genuine OPA `deny` decision is not an infrastructure error.
        assert_eq!(metrics.errors_total.get(["http"]), 0);
    }

    #[test]
    fn record_decision_infra_error_counts_as_error_and_increments_errors_total() {
        let metrics = PolicyMetrics::new();
        record_decision_on(&metrics, "http", &scope_drift(), Duration::from_millis(1));

        assert_eq!(metrics.decisions_total.get(["error"]), 1);
        assert_eq!(metrics.decisions_total.get(["allow"]), 0);
        assert_eq!(metrics.decisions_total.get(["deny"]), 0);
        assert_eq!(metrics.errors_total.get(["http"]), 1);
    }

    #[test]
    fn record_decision_tracks_transport_independently() {
        let metrics = PolicyMetrics::new();
        record_decision_on(&metrics, "http", &scope_drift(), Duration::from_millis(1));
        record_decision_on(&metrics, "wasm", &scope_drift(), Duration::from_millis(1));

        assert_eq!(metrics.errors_total.get(["http"]), 1);
        assert_eq!(metrics.errors_total.get(["wasm"]), 1);
        // Total decisions are still counted in aggregate by outcome only --
        // no per-transport decisions_total split, matching the ADR's
        // catalog (`decisions_total` is labeled `outcome` only).
        assert_eq!(metrics.decisions_total.get(["error"]), 2);
    }

    #[test]
    fn format_prometheus_text_includes_all_three_series_headers() {
        let metrics = PolicyMetrics::new();
        record_decision_on(&metrics, "http", &allowed(), Duration::from_millis(2));
        let text = metrics.format_prometheus_text();

        assert!(text.contains("# TYPE keystone_policy_decisions_total counter"));
        assert!(text.contains("# TYPE keystone_policy_decision_duration_seconds histogram"));
        assert!(text.contains("# TYPE keystone_policy_errors_total counter"));
        assert!(text.contains("keystone_policy_decisions_total{outcome=\"allow\"} 1"));
    }

    #[test]
    fn global_policy_metrics_static_is_reachable_and_starts_empty_for_unused_labels() {
        // Smoke test that the LazyLock initializes without panicking and
        // that an outcome/transport nothing has recorded yet reads zero.
        assert_eq!(POLICY_METRICS.decisions_total.get(["allow"]), 0);
    }
}
