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

use openstack_keystone_metrics::{Histogram, LabeledCounter, PrometheusText, write_metric_header};

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
    pub evaluations_total: LabeledCounter<1>,
    /// `keystone_mapping_evaluation_duration_seconds` — mapping-engine
    /// evaluation latency (unlabeled).
    pub evaluation_duration_seconds: Histogram,
}

impl Default for MappingMetrics {
    fn default() -> Self {
        Self {
            evaluations_total: LabeledCounter::new(["outcome"]),
            evaluation_duration_seconds: Histogram::new(),
        }
    }
}

impl PrometheusText for MappingMetrics {
    fn format_prometheus_text(&self) -> String {
        let mut out = String::new();
        write_metric_header(
            &mut out,
            "keystone_mapping_evaluations_total",
            "Mapping-engine rule evaluation volume by outcome.",
            "counter",
        );
        self.evaluations_total
            .write_lines(&mut out, "keystone_mapping_evaluations_total");

        write_metric_header(
            &mut out,
            "keystone_mapping_evaluation_duration_seconds",
            "Mapping-engine rule evaluation latency.",
            "histogram",
        );
        self.evaluation_duration_seconds.write_lines(
            &mut out,
            "keystone_mapping_evaluation_duration_seconds",
            &[],
            &[],
        );
        out
    }
}

/// Process-wide mapping-engine metrics.
pub static MAPPING_METRICS: LazyLock<MappingMetrics> = LazyLock::new(MappingMetrics::default);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_evaluations_by_outcome() {
        let metrics = MappingMetrics::default();
        metrics.evaluations_total.inc([OUTCOME_MATCHED]);
        metrics.evaluations_total.inc([OUTCOME_MATCHED]);
        metrics.evaluations_total.inc([OUTCOME_NO_MATCH]);
        metrics.evaluations_total.inc([OUTCOME_ERROR]);

        assert_eq!(metrics.evaluations_total.get([OUTCOME_MATCHED]), 2);
        assert_eq!(metrics.evaluations_total.get([OUTCOME_NO_MATCH]), 1);
        assert_eq!(metrics.evaluations_total.get([OUTCOME_ERROR]), 1);
    }

    #[test]
    fn records_evaluation_duration() {
        let metrics = MappingMetrics::default();
        metrics.evaluation_duration_seconds.record(0.002);
        assert_eq!(metrics.evaluation_duration_seconds.count(), 1);
    }

    #[test]
    fn formats_prometheus_text_with_headers() {
        let metrics = MappingMetrics::default();
        metrics.evaluations_total.inc([OUTCOME_MATCHED]);
        metrics.evaluation_duration_seconds.record(0.01);

        let text = metrics.format_prometheus_text();
        assert!(text.contains("# HELP keystone_mapping_evaluations_total"));
        assert!(text.contains("# TYPE keystone_mapping_evaluations_total counter"));
        assert!(text.contains("keystone_mapping_evaluations_total{outcome=\"matched\"} 1"));
        assert!(text.contains("# HELP keystone_mapping_evaluation_duration_seconds"));
        assert!(text.contains("# TYPE keystone_mapping_evaluation_duration_seconds histogram"));
        assert!(text.contains("keystone_mapping_evaluation_duration_seconds_count 1"));
    }

    #[test]
    fn static_instance_is_reachable() {
        MAPPING_METRICS.evaluations_total.inc([OUTCOME_MATCHED]);
        assert!(MAPPING_METRICS.evaluations_total.get([OUTCOME_MATCHED]) >= 1);
    }
}
