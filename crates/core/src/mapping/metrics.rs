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
//! # Mapping-engine Prometheus metrics (ADR 0031)
//!
//! Tracks mapping-rule evaluation volume and latency. `outcome` is always
//! one of the fixed strings below (never a free-text error), per the ADR
//! 0031 cardinality/PII guardrail.

use std::sync::LazyLock;

use openstack_keystone_telemetry::metrics::{
    self, CounterVec, HistogramVec, LATENCY_BUCKETS, Meter,
};

/// `outcome` label value: a rule in the ruleset matched the claims.
pub const OUTCOME_MATCHED: &str = "matched";
/// `outcome` label value: no rule in the ruleset matched the claims.
pub const OUTCOME_NO_MATCH: &str = "no_match";
/// `outcome` label value: rule evaluation itself errored (e.g. malformed
/// claim data), distinct from a clean no-match.
pub const OUTCOME_ERROR: &str = "error";

/// Mapping-engine subsystem's Prometheus counters/histograms.
pub struct MappingMetrics {
    /// `keystone_mapping_evaluations_total{outcome}` — mapping-engine
    /// evaluation volume.
    evaluations_total: CounterVec<1>,
    /// `keystone_mapping_evaluation_duration_seconds` — mapping-engine
    /// evaluation latency (unlabeled).
    evaluation_duration_seconds: HistogramVec<0>,
}

impl MappingMetrics {
    /// Create the instruments on `meter`.
    pub fn new(meter: &Meter) -> Self {
        Self {
            evaluations_total: CounterVec::new(
                meter,
                "keystone_mapping_evaluations_total",
                "Mapping-engine rule evaluation volume by outcome.",
                ["outcome"],
            ),
            evaluation_duration_seconds: HistogramVec::new(
                meter,
                "keystone_mapping_evaluation_duration_seconds",
                "Mapping-engine rule evaluation latency.",
                [],
                &LATENCY_BUCKETS,
            ),
        }
    }

    /// Record one rule evaluation: `outcome` is one of the `OUTCOME_*`
    /// constants of this module.
    pub fn record_evaluation(&self, outcome: &'static str, seconds: f64) {
        self.evaluation_duration_seconds.record(seconds, []);
        self.evaluations_total.inc([outcome.into()]);
    }
}

/// Process-wide mapping-engine metrics.
pub static MAPPING_METRICS: LazyLock<MappingMetrics> =
    LazyLock::new(|| MappingMetrics::new(&metrics::meter()));

#[cfg(test)]
mod tests {
    use openstack_keystone_telemetry::metrics::MetricsPipeline;

    use super::*;

    /// Pins the rendered exposition text (series names, labels, HELP/TYPE and
    /// bucket layout) against `tests/golden/mapping.prom` (ADR 0040).
    #[test]
    fn golden_exposition() {
        let pipeline = MetricsPipeline::new();
        let metrics = MappingMetrics::new(&pipeline.meter());
        metrics.record_evaluation(OUTCOME_MATCHED, 0.002);
        metrics.record_evaluation(OUTCOME_NO_MATCH, 0.7);
        metrics.evaluations_total.inc([OUTCOME_ERROR.into()]);
        openstack_keystone_telemetry::assert_golden!("mapping", pipeline.render());
    }

    #[test]
    fn records_evaluations_and_duration() {
        let pipeline = MetricsPipeline::new();
        let metrics = MappingMetrics::new(&pipeline.meter());
        metrics.record_evaluation(OUTCOME_MATCHED, 0.01);
        metrics.record_evaluation(OUTCOME_MATCHED, 0.01);
        metrics.record_evaluation(OUTCOME_NO_MATCH, 0.01);

        let text = pipeline.render();
        assert!(text.contains("# TYPE keystone_mapping_evaluations_total counter"));
        assert!(text.contains("keystone_mapping_evaluations_total{outcome=\"matched\"} 2\n"));
        assert!(text.contains("keystone_mapping_evaluations_total{outcome=\"no_match\"} 1\n"));
        assert!(text.contains("# TYPE keystone_mapping_evaluation_duration_seconds histogram"));
        assert!(text.contains("keystone_mapping_evaluation_duration_seconds_count 3\n"));
    }

    #[test]
    fn static_instance_records_without_panicking() {
        MAPPING_METRICS.record_evaluation(OUTCOME_MATCHED, 0.0);
    }
}
