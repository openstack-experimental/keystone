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
//! Prometheus text-format scrape endpoint helpers (ADR 0023 Phase 4).
//!
//! [`format_prometheus_text`] serialises the three audit counters into the
//! Prometheus text exposition format (version 0.0.4) so they can be scraped
//! by any Prometheus-compatible collector without pulling in the full
//! `prometheus` client library.
//!
//! Metric names match the alert rules in `deploy/prometheus/alert_rules.yaml`.

use crate::AuditDispatcher;

/// Serialise the three audit counters as Prometheus text exposition format.
///
/// Output is valid for Prometheus text format version 0.0.4 and contains:
/// - `keystone_audit_dropped_total`
/// - `keystone_audit_postaudit_dropped_total`
/// - `keystone_audit_events_total`
pub fn format_prometheus_text(dispatcher: &AuditDispatcher) -> String {
    format!(
        "# HELP keystone_audit_dropped_total \
Total perimeter audit events dropped because the best-effort channel was full.\n\
# TYPE keystone_audit_dropped_total counter\n\
keystone_audit_dropped_total {dropped}\n\
# HELP keystone_audit_postaudit_dropped_total \
Post-audit outcome records (Success/Failure) lost after a DB commit; \
compensating local log entries were written.\n\
# TYPE keystone_audit_postaudit_dropped_total counter\n\
keystone_audit_postaudit_dropped_total {postaudit}\n\
# HELP keystone_audit_events_total \
Total audit events dispatched across both the perimeter and critical channels.\n\
# TYPE keystone_audit_events_total counter\n\
keystone_audit_events_total {total}\n",
        dropped = dispatcher.dropped_count(),
        postaudit = dispatcher.postaudit_dropped_count(),
        total = dispatcher.events_total(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_contains_all_three_metrics() {
        let dispatcher = AuditDispatcher::noop();
        let text = format_prometheus_text(&dispatcher);
        assert!(text.contains("keystone_audit_dropped_total"));
        assert!(text.contains("keystone_audit_postaudit_dropped_total"));
        assert!(text.contains("keystone_audit_events_total"));
        // Each metric has HELP and TYPE headers.
        assert_eq!(text.matches("# HELP").count(), 3);
        assert_eq!(text.matches("# TYPE").count(), 3);
        assert_eq!(text.matches("counter").count(), 3);
    }

    #[test]
    fn format_zero_values() {
        let dispatcher = AuditDispatcher::noop();
        let text = format_prometheus_text(&dispatcher);
        assert!(text.contains("keystone_audit_dropped_total 0"));
        assert!(text.contains("keystone_audit_postaudit_dropped_total 0"));
        assert!(text.contains("keystone_audit_events_total 0"));
    }
}
