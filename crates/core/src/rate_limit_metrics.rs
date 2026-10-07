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

//! Prometheus metrics for handler-level rate limiting (ADR-0022, ADR-0031).
//!
//! `keystone_rate_limit_evaluations_total{scope,outcome}` and
//! `keystone_rate_limit_rejections_total{scope}` are recorded from
//! [`crate::rate_limit::RateLimitState::check_ip`] and
//! [`crate::rate_limit::RateLimitState::check_user`], the two points where a
//! request either consumes a token bucket cell or is rejected with a
//! `Retry-After` duration.
//!
//! ## `scope` label mapping
//!
//! ADR 0031 names four scope values (`per_ip`, `per_user`, `global`,
//! `auth_endpoint`), but ADR 0022's configuration (and this module's
//! [`AppliedRateLimitConfig`](crate::rate_limit)) only defines two distinct
//! limiter instances: `rate_limit_global_ip` (an IP-keyed bucket — despite
//! the config section's name, it is *not* one shared global bucket, it is
//! keyed per client IP, see `IpRateLimitKey`) and `rate_limit_user_auth` (a
//! user-keyed bucket that only ever guards authentication endpoints). There
//! is no separate single-bucket "global" limiter and no "auth_endpoint"
//! limiter distinct from the per-user one. This module therefore emits only
//! two `scope` values, both drawn from the same fixed, code-defined set the
//! ADR requires:
//!
//! - `check_ip` (the `global_ip` limiter) -> `scope = "per_ip"`
//! - `check_user` (the `user_auth` limiter, only ever called on authentication
//!   paths) -> `scope = "per_user"`
//!
//! `global` and `auth_endpoint` are intentionally unused today; if a future
//! limiter instance is added that genuinely matches one of those scopes,
//! record it under that value at its own check function rather than
//! reusing `per_ip`/`per_user`.

use std::sync::LazyLock;

use openstack_keystone_telemetry::metrics::{self, CounterVec, Label, Meter};

/// `scope` label value for [`crate::rate_limit::RateLimitState::check_ip`]
/// (the `rate_limit_global_ip` limiter, keyed per client IP).
pub const SCOPE_PER_IP: &str = "per_ip";
/// `scope` label value for [`crate::rate_limit::RateLimitState::check_user`]
/// (the `rate_limit_user_auth` limiter, keyed per authenticated user id).
pub const SCOPE_PER_USER: &str = "per_user";

/// `outcome` label value for an evaluation that stayed within quota.
const OUTCOME_ALLOWED: &str = "allowed";
/// `outcome` label value for an evaluation that exceeded quota.
const OUTCOME_REJECTED: &str = "rejected";

/// Process-wide rate-limit counters (ADR-0031).
pub struct RateLimitMetrics {
    /// `keystone_rate_limit_evaluations_total{scope,outcome}` — every
    /// `check_ip`/`check_user` call, labeled by which side of the quota it
    /// landed on.
    evaluations_total: CounterVec<2>,
    /// `keystone_rate_limit_rejections_total{scope}` — the subset of
    /// evaluations that returned `Err` (a 429 was issued to the caller).
    rejections_total: CounterVec<1>,
}

impl RateLimitMetrics {
    /// Create the instruments on `meter`.
    pub fn new(meter: &Meter) -> Self {
        Self {
            evaluations_total: CounterVec::new(
                meter,
                "keystone_rate_limit_evaluations_total",
                "Total rate-limit evaluations by scope and outcome.",
                ["scope", "outcome"],
            ),
            rejections_total: CounterVec::new(
                meter,
                "keystone_rate_limit_rejections_total",
                "Total rate-limit rejections (HTTP 429) by scope.",
                ["scope"],
            ),
        }
    }

    /// Record one rate-limit check's outcome under `scope` ([`SCOPE_PER_IP`]
    /// or [`SCOPE_PER_USER`]).
    ///
    /// `allowed` is `true` when the checked function returned `Ok(())`.
    /// Updates `evaluations_total` unconditionally and `rejections_total`
    /// only when `allowed` is `false`.
    pub fn record(&self, scope: &'static str, allowed: bool) {
        let outcome = if allowed {
            OUTCOME_ALLOWED
        } else {
            OUTCOME_REJECTED
        };
        self.evaluations_total.inc([scope.into(), outcome.into()]);
        if !allowed {
            self.rejections_total.inc([Label::fixed(scope)]);
        }
    }
}

/// Process-wide singleton, mirroring the other ADR-0031 subsystem statics
/// (audit, auth-plugin) — `RateLimitState` snapshots are reloadable and
/// short-lived, so the counters live independently of them.
pub static RATE_LIMIT_METRICS: LazyLock<RateLimitMetrics> =
    LazyLock::new(|| RateLimitMetrics::new(&metrics::meter()));

#[cfg(test)]
mod tests {
    use openstack_keystone_telemetry::metrics::MetricsPipeline;

    use super::*;

    fn fixture() -> (MetricsPipeline, RateLimitMetrics) {
        let pipeline = MetricsPipeline::new();
        let metrics = RateLimitMetrics::new(&pipeline.meter());
        (pipeline, metrics)
    }

    /// Pins the rendered exposition text (series names, labels, HELP/TYPE and
    /// bucket layout) against `tests/golden/rate_limit.prom` (ADR 0040).
    #[test]
    fn golden_exposition() {
        let (pipeline, metrics) = fixture();
        metrics.record(SCOPE_PER_IP, true);
        metrics.record(SCOPE_PER_IP, false);
        metrics.record(SCOPE_PER_USER, true);
        openstack_keystone_telemetry::assert_golden!("rate_limit", pipeline.render());
    }

    #[test]
    fn record_allowed_increments_evaluations_only() {
        let (pipeline, metrics) = fixture();
        metrics.record(SCOPE_PER_IP, true);
        let text = pipeline.render();
        assert!(text.contains(
            "keystone_rate_limit_evaluations_total{outcome=\"allowed\",scope=\"per_ip\"} 1\n"
        ));
        assert!(!text.contains("outcome=\"rejected\""));
        assert!(!text.contains("keystone_rate_limit_rejections_total{"));
    }

    #[test]
    fn record_rejected_increments_both_counters() {
        let (pipeline, metrics) = fixture();
        metrics.record(SCOPE_PER_USER, false);
        let text = pipeline.render();
        assert!(text.contains(
            "keystone_rate_limit_evaluations_total{outcome=\"rejected\",scope=\"per_user\"} 1\n"
        ));
        assert!(text.contains("keystone_rate_limit_rejections_total{scope=\"per_user\"} 1\n"));
    }

    #[test]
    fn scopes_are_independent_series() {
        let (pipeline, metrics) = fixture();
        metrics.record(SCOPE_PER_IP, false);
        metrics.record(SCOPE_PER_USER, true);
        let text = pipeline.render();
        assert!(text.contains("keystone_rate_limit_rejections_total{scope=\"per_ip\"} 1\n"));
        assert!(!text.contains("keystone_rate_limit_rejections_total{scope=\"per_user\"}"));
    }

    #[test]
    fn has_both_metric_families() {
        let (pipeline, metrics) = fixture();
        metrics.record(SCOPE_PER_IP, true);
        metrics.record(SCOPE_PER_USER, false);
        let text = pipeline.render();
        assert!(text.contains("# TYPE keystone_rate_limit_evaluations_total counter"));
        assert!(text.contains("# TYPE keystone_rate_limit_rejections_total counter"));
    }

    #[test]
    fn static_singleton_records_without_panicking() {
        RATE_LIMIT_METRICS.record(SCOPE_PER_IP, true);
    }
}
