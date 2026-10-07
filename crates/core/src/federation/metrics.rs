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

use openstack_keystone_telemetry::metrics::{self, CounterVec, Label, Meter};

/// `outcome` label value for a successful federated authentication.
pub const OUTCOME_SUCCESS: &str = "success";
/// `outcome` label value for a failed federated authentication.
pub const OUTCOME_FAILURE: &str = "failure";

/// Federation subsystem's Prometheus counters.
pub struct FederationMetrics {
    /// `keystone_federation_authentications_total{idp_id,outcome}` — federated
    /// authentication volume.
    authentications_total: CounterVec<2>,
}

impl FederationMetrics {
    /// Create the instruments on `meter`.
    pub fn new(meter: &Meter) -> Self {
        Self {
            authentications_total: CounterVec::new(
                meter,
                "keystone_federation_authentications_total",
                "Federated authentication volume by identity provider and outcome.",
                ["idp_id", "outcome"],
            ),
        }
    }

    /// Count one federated authentication against `idp_id`.
    ///
    /// `idp_id` is one of the operator-registered identity providers (ADR
    /// 0031), hence a bounded label; `success` selects the fixed outcome.
    pub fn record_authentication(&self, idp_id: &str, success: bool) {
        let outcome = if success {
            OUTCOME_SUCCESS
        } else {
            OUTCOME_FAILURE
        };
        self.authentications_total
            .inc([Label::bounded(idp_id), outcome.into()]);
    }
}

/// Process-wide federation metrics.
pub static FEDERATION_METRICS: LazyLock<FederationMetrics> =
    LazyLock::new(|| FederationMetrics::new(&metrics::meter()));

#[cfg(test)]
mod tests {
    use openstack_keystone_telemetry::metrics::MetricsPipeline;

    use super::*;

    /// Pins the rendered exposition text (series names, labels, HELP/TYPE and
    /// bucket layout) against `tests/golden/federation.prom` (ADR 0040).
    #[test]
    fn golden_exposition() {
        let pipeline = MetricsPipeline::new();
        let metrics = FederationMetrics::new(&pipeline.meter());
        metrics.record_authentication("idp-okta", true);
        metrics.record_authentication("idp-okta", false);
        metrics.record_authentication("idp-azure", true);
        openstack_keystone_telemetry::assert_golden!("federation", pipeline.render());
    }

    #[test]
    fn records_success_and_failure_per_idp() {
        let pipeline = MetricsPipeline::new();
        let metrics = FederationMetrics::new(&pipeline.meter());
        metrics.record_authentication("idp-okta", true);
        metrics.record_authentication("idp-okta", true);
        metrics.record_authentication("idp-okta", false);
        metrics.record_authentication("idp-azure", true);

        let text = pipeline.render();
        for expected in [
            "keystone_federation_authentications_total{idp_id=\"idp-okta\",outcome=\"success\"} 2\n",
            "keystone_federation_authentications_total{idp_id=\"idp-okta\",outcome=\"failure\"} 1\n",
            "keystone_federation_authentications_total{idp_id=\"idp-azure\",outcome=\"success\"} 1\n",
        ] {
            assert!(text.contains(expected), "{expected} not in {text}");
        }
    }

    #[test]
    fn has_header_with_help_and_type() {
        let pipeline = MetricsPipeline::new();
        FederationMetrics::new(&pipeline.meter()).record_authentication("idp-okta", true);

        let text = pipeline.render();
        assert!(text.contains("# HELP keystone_federation_authentications_total"));
        assert!(text.contains("# TYPE keystone_federation_authentications_total counter"));
    }

    #[test]
    fn static_instance_records_without_panicking() {
        FEDERATION_METRICS.record_authentication("idp-static", true);
    }
}
