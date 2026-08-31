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
//! - `check_user` (the `user_auth` limiter, only ever called on
//!   authentication paths) -> `scope = "per_user"`
//!
//! `global` and `auth_endpoint` are intentionally unused today; if a future
//! limiter instance is added that genuinely matches one of those scopes,
//! record it under that value at its own check function rather than
//! reusing `per_ip`/`per_user`.

use std::sync::LazyLock;

use openstack_keystone_metrics::{LabeledCounter, PrometheusText, write_metric_header};

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
    pub evaluations_total: LabeledCounter<2>,
    /// `keystone_rate_limit_rejections_total{scope}` — the subset of
    /// evaluations that returned `Err` (a 429 was issued to the caller).
    pub rejections_total: LabeledCounter<1>,
}

impl RateLimitMetrics {
    fn new() -> Self {
        Self {
            evaluations_total: LabeledCounter::new(["scope", "outcome"]),
            rejections_total: LabeledCounter::new(["scope"]),
        }
    }

    /// Record one rate-limit check's outcome under `scope`.
    ///
    /// `allowed` is `true` when the checked function returned `Ok(())`.
    /// Updates `evaluations_total` unconditionally and `rejections_total`
    /// only when `allowed` is `false`.
    pub fn record(&self, scope: &str, allowed: bool) {
        let outcome = if allowed {
            OUTCOME_ALLOWED
        } else {
            OUTCOME_REJECTED
        };
        self.evaluations_total.inc([scope, outcome]);
        if !allowed {
            self.rejections_total.inc([scope]);
        }
    }
}

/// Process-wide singleton, mirroring the other ADR-0031 subsystem statics
/// (audit, auth-plugin) — `RateLimitState` snapshots are reloadable and
/// short-lived, so the counters live independently of them.
pub static RATE_LIMIT_METRICS: LazyLock<RateLimitMetrics> = LazyLock::new(RateLimitMetrics::new);

impl PrometheusText for RateLimitMetrics {
    fn format_prometheus_text(&self) -> String {
        let mut out = String::new();
        write_metric_header(
            &mut out,
            "keystone_rate_limit_evaluations_total",
            "Total rate-limit evaluations by scope and outcome.",
            "counter",
        );
        self.evaluations_total
            .write_lines(&mut out, "keystone_rate_limit_evaluations_total");
        write_metric_header(
            &mut out,
            "keystone_rate_limit_rejections_total",
            "Total rate-limit rejections (HTTP 429) by scope.",
            "counter",
        );
        self.rejections_total
            .write_lines(&mut out, "keystone_rate_limit_rejections_total");
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_allowed_increments_evaluations_only() {
        let metrics = RateLimitMetrics::new();
        metrics.record(SCOPE_PER_IP, true);
        assert_eq!(metrics.evaluations_total.get([SCOPE_PER_IP, "allowed"]), 1);
        assert_eq!(metrics.evaluations_total.get([SCOPE_PER_IP, "rejected"]), 0);
        assert_eq!(metrics.rejections_total.get([SCOPE_PER_IP]), 0);
    }

    #[test]
    fn record_rejected_increments_both_counters() {
        let metrics = RateLimitMetrics::new();
        metrics.record(SCOPE_PER_USER, false);
        assert_eq!(
            metrics.evaluations_total.get([SCOPE_PER_USER, "rejected"]),
            1
        );
        assert_eq!(metrics.rejections_total.get([SCOPE_PER_USER]), 1);
    }

    #[test]
    fn scopes_are_independent_series() {
        let metrics = RateLimitMetrics::new();
        metrics.record(SCOPE_PER_IP, false);
        metrics.record(SCOPE_PER_USER, true);
        assert_eq!(metrics.rejections_total.get([SCOPE_PER_IP]), 1);
        assert_eq!(metrics.rejections_total.get([SCOPE_PER_USER]), 0);
    }

    #[test]
    fn format_prometheus_text_contains_both_metric_families() {
        let metrics = RateLimitMetrics::new();
        metrics.record(SCOPE_PER_IP, true);
        metrics.record(SCOPE_PER_USER, false);
        let text = metrics.format_prometheus_text();
        assert!(text.contains("# TYPE keystone_rate_limit_evaluations_total counter"));
        assert!(text.contains("# TYPE keystone_rate_limit_rejections_total counter"));
        assert!(text.contains(
            "keystone_rate_limit_evaluations_total{scope=\"per_ip\",outcome=\"allowed\"} 1"
        ));
        assert!(text.contains(
            "keystone_rate_limit_evaluations_total{scope=\"per_user\",outcome=\"rejected\"} 1"
        ));
        assert!(text.contains("keystone_rate_limit_rejections_total{scope=\"per_user\"} 1"));
    }

    #[test]
    fn static_singleton_is_reachable() {
        RATE_LIMIT_METRICS.record(SCOPE_PER_IP, true);
        assert!(
            RATE_LIMIT_METRICS
                .evaluations_total
                .get([SCOPE_PER_IP, "allowed"])
                >= 1
        );
    }
}
