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
//! # Federation Prometheus metrics (ADR 0031)
//!
//! Tracks federated authentication volume by identity provider and outcome.
//! `idp_id` is an operator-configured identifier (the finite set of IdPs a
//! deployment has registered), which ADR 0031 explicitly allows as a label
//! despite normally being an "identifier" under the cardinality/PII
//! guardrail — see the ADR's Federation/mapping catalog entry. `outcome` is
//! always one of the fixed strings below, never a free-text error.

use std::sync::LazyLock;

use openstack_keystone_metrics::{LabeledCounter, PrometheusText, write_metric_header};

/// `outcome` label value for a successful federated authentication.
pub const OUTCOME_SUCCESS: &str = "success";
/// `outcome` label value for a failed federated authentication.
pub const OUTCOME_FAILURE: &str = "failure";

/// Federation subsystem's Prometheus counters.
pub struct FederationMetrics {
    /// `keystone_federation_authentications_total{idp_id,outcome}` — federated
    /// authentication volume.
    pub authentications_total: LabeledCounter<2>,
}

impl Default for FederationMetrics {
    fn default() -> Self {
        Self {
            authentications_total: LabeledCounter::new(["idp_id", "outcome"]),
        }
    }
}

impl PrometheusText for FederationMetrics {
    fn format_prometheus_text(&self) -> String {
        let mut out = String::new();
        write_metric_header(
            &mut out,
            "keystone_federation_authentications_total",
            "Federated authentication volume by identity provider and outcome.",
            "counter",
        );
        self.authentications_total
            .write_lines(&mut out, "keystone_federation_authentications_total");
        out
    }
}

/// Process-wide federation metrics.
pub static FEDERATION_METRICS: LazyLock<FederationMetrics> =
    LazyLock::new(FederationMetrics::default);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_success_and_failure_per_idp() {
        let metrics = FederationMetrics::default();
        metrics
            .authentications_total
            .inc(["idp-okta", OUTCOME_SUCCESS]);
        metrics
            .authentications_total
            .inc(["idp-okta", OUTCOME_SUCCESS]);
        metrics
            .authentications_total
            .inc(["idp-okta", OUTCOME_FAILURE]);
        metrics
            .authentications_total
            .inc(["idp-azure", OUTCOME_SUCCESS]);

        assert_eq!(
            metrics
                .authentications_total
                .get(["idp-okta", OUTCOME_SUCCESS]),
            2
        );
        assert_eq!(
            metrics
                .authentications_total
                .get(["idp-okta", OUTCOME_FAILURE]),
            1
        );
        assert_eq!(
            metrics
                .authentications_total
                .get(["idp-azure", OUTCOME_SUCCESS]),
            1
        );
    }

    #[test]
    fn formats_prometheus_text_with_header_and_labels() {
        let metrics = FederationMetrics::default();
        metrics
            .authentications_total
            .inc(["idp-okta", OUTCOME_SUCCESS]);

        let text = metrics.format_prometheus_text();
        assert!(text.contains("# HELP keystone_federation_authentications_total"));
        assert!(text.contains("# TYPE keystone_federation_authentications_total counter"));
        assert!(text.contains(
            "keystone_federation_authentications_total{idp_id=\"idp-okta\",outcome=\"success\"} 1"
        ));
    }

    #[test]
    fn static_instance_is_reachable_and_independent_per_test_process() {
        FEDERATION_METRICS
            .authentications_total
            .inc(["idp-static", OUTCOME_SUCCESS]);
        assert!(
            FEDERATION_METRICS
                .authentications_total
                .get(["idp-static", OUTCOME_SUCCESS])
                >= 1
        );
    }
}
