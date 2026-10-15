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
//! # OAuth2 provider metrics (ADR 0031, ADR 0026)
//!
//! Process-wide Prometheus primitives for the OAuth2/OIDC provider, exposed
//! as the [`OAUTH2_METRICS`] static (same pattern as
//! [`crate::token::metrics::TOKEN_METRICS`]).
//!
//! **Cardinality guardrail:** `domain_id` is bounded by the domains of the
//! deployment and `client_id` (only on the refresh-reuse counter) by the
//! registered clients; `user_id` is never a label. Callers must only pass a
//! `domain_id` or `client_id` that was resolved server side: the unauthenticated
//! `/token` path segment is attacker controlled and must not be used as is.
//! Every other label value comes from a fixed set (see the `*_label` helpers).

use std::sync::LazyLock;

use openstack_keystone_telemetry::metrics::{
    self, CounterVec, GaugeVec, HistogramVec, LATENCY_BUCKETS, Label, Meter,
};

/// Process-wide OAuth2 provider metrics.
pub struct Oauth2Metrics {
    token_requests_total: CounterVec<3>,
    token_issue_duration_seconds: HistogramVec<1>,
    refresh_reuse_detected_total: CounterVec<2>,
    device_polls_total: CounterVec<1>,
    device_grants_started_total: CounterVec<0>,
    authorize_requests_total: CounterVec<1>,
    login_attempts_total: CounterVec<2>,
    signing_key_rotations_total: CounterVec<2>,
    signing_key_age_seconds: GaugeVec<1>,
    janitor_purged_total: CounterVec<1>,
    janitor_errors_total: CounterVec<0>,
    janitor_last_run_timestamp_seconds: GaugeVec<1>,
    revocations_total: CounterVec<1>,
}

impl Oauth2Metrics {
    /// Create the instruments on `meter`.
    pub fn new(meter: &Meter) -> Self {
        Self {
            token_requests_total: CounterVec::new(
                meter,
                "keystone_oauth2_token_requests_total",
                "OAuth2 /token requests by domain, grant type and outcome.",
                ["domain_id", "grant_type", "outcome"],
            ),
            token_issue_duration_seconds: HistogramVec::new(
                meter,
                "keystone_oauth2_token_issue_duration_seconds",
                "OAuth2 /token request latency by grant type.",
                ["grant_type"],
                &LATENCY_BUCKETS,
            ),
            refresh_reuse_detected_total: CounterVec::new(
                meter,
                "keystone_oauth2_refresh_reuse_detected_total",
                "Refresh token reuse detections (breach signal).",
                ["domain_id", "client_id"],
            ),
            device_polls_total: CounterVec::new(
                meter,
                "keystone_oauth2_device_polls_total",
                "Device code polls at /token by outcome.",
                ["outcome"],
            ),
            device_grants_started_total: CounterVec::new(
                meter,
                "keystone_oauth2_device_grants_started_total",
                "Device authorization grants started.",
                [],
            ),
            authorize_requests_total: CounterVec::new(
                meter,
                "keystone_oauth2_authorize_requests_total",
                "OAuth2 /authorize requests by outcome.",
                ["outcome"],
            ),
            login_attempts_total: CounterVec::new(
                meter,
                "keystone_oauth2_login_attempts_total",
                "OAuth2 browser login attempts by outcome and factor.",
                ["outcome", "factor"],
            ),
            signing_key_rotations_total: CounterVec::new(
                meter,
                "keystone_oauth2_signing_key_rotations_total",
                "OAuth2 signing key rotations by domain and kind.",
                ["domain_id", "kind"],
            ),
            signing_key_age_seconds: GaugeVec::new(
                meter,
                "keystone_oauth2_signing_key_age_seconds",
                "Age of the primary OAuth2 signing key per domain.",
                ["domain_id"],
            ),
            janitor_purged_total: CounterVec::new(
                meter,
                "keystone_oauth2_janitor_purged_total",
                "Records purged by the OAuth2 janitors by kind.",
                ["kind"],
            ),
            janitor_errors_total: CounterVec::new(
                meter,
                "keystone_oauth2_janitor_errors_total",
                "Errors hit by the OAuth2 janitors.",
                [],
            ),
            janitor_last_run_timestamp_seconds: GaugeVec::new(
                meter,
                "keystone_oauth2_janitor_last_run_timestamp_seconds",
                "Unix time of the last completed OAuth2 janitor sweep by janitor.",
                ["janitor"],
            ),
            revocations_total: CounterVec::new(
                meter,
                "keystone_oauth2_revocations_total",
                "Refresh token families revoked by reason.",
                ["reason"],
            ),
        }
    }

    /// Count one `/token` request.
    pub fn record_token_request(&self, domain_id: &str, grant_type: &str, outcome: &'static str) {
        self.token_requests_total.inc([
            Label::bounded(domain_id),
            grant_type_label(grant_type).into(),
            outcome.into(),
        ]);
    }

    /// Record the latency of one `/token` request.
    pub fn record_token_duration(&self, grant_type: &str, seconds: f64) {
        self.token_issue_duration_seconds
            .record(seconds, [grant_type_label(grant_type).into()]);
    }

    /// Count one detected refresh token reuse.
    pub fn record_refresh_reuse(&self, domain_id: &str, client_id: &str) {
        self.refresh_reuse_detected_total
            .inc([Label::bounded(domain_id), Label::bounded(client_id)]);
    }

    /// Count one device code poll. `outcome` is one of `pending`,
    /// `slow_down`, `authorized`, `denied`, `expired`, `invalid`.
    pub fn record_device_poll(&self, outcome: &'static str) {
        self.device_polls_total.inc([outcome.into()]);
    }

    /// Count one started device authorization grant.
    pub fn record_device_grant_started(&self) {
        self.device_grants_started_total.inc([]);
    }

    /// Count one `/authorize` request.
    pub fn record_authorize(&self, outcome: &'static str) {
        self.authorize_requests_total.inc([outcome.into()]);
    }

    /// Count one browser login attempt.
    pub fn record_login_attempt(&self, outcome: &'static str, factor: &'static str) {
        self.login_attempts_total
            .inc([outcome.into(), factor.into()]);
    }

    /// Count one signing key rotation. `kind` is one of `normal`,
    /// `emergency`, `local_emergency`, `automatic`.
    pub fn record_key_rotation(&self, domain_id: &str, kind: &'static str) {
        self.signing_key_rotations_total
            .inc([Label::bounded(domain_id), kind.into()]);
    }

    /// Set the age of a domain's primary signing key.
    pub fn set_signing_key_age(&self, domain_id: &str, seconds: i64) {
        self.signing_key_age_seconds
            .set(seconds, [Label::bounded(domain_id)]);
    }

    /// Count records purged by a janitor. `kind` is the janitor record kind
    /// or `retired_key` / `pruned_jti`.
    pub fn record_janitor_purged(&self, kind: &str, n: u64) {
        self.janitor_purged_total.add(n, [Label::bounded(kind)]);
    }

    /// Count janitor errors.
    pub fn record_janitor_errors(&self, n: u64) {
        self.janitor_errors_total.add(n, []);
    }

    /// Stamp a completed janitor sweep (Unix seconds). `janitor` is one of
    /// `key`, `session`.
    pub fn set_janitor_last_run(&self, janitor: &'static str, unix_seconds: i64) {
        self.janitor_last_run_timestamp_seconds
            .set(unix_seconds, [janitor.into()]);
    }

    /// Count revoked refresh token families. `reason` is a fixed
    /// `RefreshTokenRevocationReason` name. Only operator and client
    /// revocations made through the API are counted; the number is the one
    /// the revoking call reports, so a client selector also counts families
    /// that were already revoked.
    pub fn record_revocations(&self, reason: &'static str, n: u64) {
        self.revocations_total.add(n, [Label::fixed(reason)]);
    }
}

/// Process-wide [`Oauth2Metrics`] instance.
pub static OAUTH2_METRICS: LazyLock<Oauth2Metrics> =
    LazyLock::new(|| Oauth2Metrics::new(&metrics::meter()));

/// Map a requested `grant_type` to a fixed label value; anything a client
/// invents collapses into `unsupported`.
pub fn grant_type_label(grant_type: &str) -> &'static str {
    match grant_type {
        "client_credentials" => "client_credentials",
        "authorization_code" => "authorization_code",
        "refresh_token" => "refresh_token",
        "urn:ietf:params:oauth:grant-type:token-exchange" => "token_exchange",
        "urn:ietf:params:oauth:grant-type:device_code" => "device_code",
        _ => "unsupported",
    }
}

#[cfg(test)]
mod tests {
    use openstack_keystone_telemetry::metrics::MetricsPipeline;

    use super::*;

    fn fixture() -> (MetricsPipeline, Oauth2Metrics) {
        let pipeline = MetricsPipeline::new();
        let metrics = Oauth2Metrics::new(&pipeline.meter());
        (pipeline, metrics)
    }

    #[test]
    fn token_requests_are_labeled() {
        let (pipeline, m) = fixture();
        m.record_token_request("d1", "refresh_token", "success");
        m.record_token_request("d1", "bogus", "invalid_grant");
        m.record_token_duration("refresh_token", 0.01);
        let text = pipeline.render();
        assert!(text.contains(
            "keystone_oauth2_token_requests_total{domain_id=\"d1\",grant_type=\"refresh_token\",outcome=\"success\"} 1\n"
        ));
        assert!(text.contains("grant_type=\"unsupported\",outcome=\"invalid_grant\""));
        assert!(text.contains(
            "keystone_oauth2_token_issue_duration_seconds_count{grant_type=\"refresh_token\"} 1\n"
        ));
    }

    #[test]
    fn refresh_reuse_carries_client_but_never_user() {
        let (pipeline, m) = fixture();
        m.record_refresh_reuse("d1", "c1");
        let text = pipeline.render();
        assert!(text.contains(
            "keystone_oauth2_refresh_reuse_detected_total{client_id=\"c1\",domain_id=\"d1\"} 1\n"
        ) || text.contains(
            "keystone_oauth2_refresh_reuse_detected_total{domain_id=\"d1\",client_id=\"c1\"} 1\n"
        ));
        assert!(!text.contains("user_id"));
    }

    #[test]
    fn device_and_authorize_counters() {
        let (pipeline, m) = fixture();
        m.record_device_poll("pending");
        m.record_device_grant_started();
        m.record_authorize("login_required");
        m.record_login_attempt("failure", "password");
        let text = pipeline.render();
        assert!(text.contains("keystone_oauth2_device_polls_total{outcome=\"pending\"} 1\n"));
        assert!(text.contains("keystone_oauth2_device_grants_started_total 1\n"));
        assert!(
            text.contains(
                "keystone_oauth2_authorize_requests_total{outcome=\"login_required\"} 1\n"
            )
        );
        assert!(text.contains("keystone_oauth2_login_attempts_total"));
    }

    #[test]
    fn key_and_janitor_series() {
        let (pipeline, m) = fixture();
        m.record_key_rotation("d1", "automatic");
        m.set_signing_key_age("d1", 3600);
        m.record_janitor_purged("refresh", 3);
        m.record_janitor_errors(2);
        m.set_janitor_last_run("key", 1_700_000_000);
        m.record_revocations("operator", 4);
        let text = pipeline.render();
        assert!(text.contains("keystone_oauth2_signing_key_age_seconds{domain_id=\"d1\"} 3600\n"));
        assert!(text.contains("keystone_oauth2_janitor_purged_total{kind=\"refresh\"} 3\n"));
        assert!(text.contains("keystone_oauth2_janitor_errors_total 2\n"));
        assert!(text.contains(
            "keystone_oauth2_janitor_last_run_timestamp_seconds{janitor=\"key\"} 1700000000\n"
        ));
        assert!(text.contains("keystone_oauth2_revocations_total{reason=\"operator\"} 4\n"));
        assert!(text.contains("signing_key_rotations_total"));
    }
}
