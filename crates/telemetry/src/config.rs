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

//! `[otel]` and `[oslo_middleware_tracing]` configuration (ADR 0040).
//!
//! Options that exist in both sections are `Option`s so "not set" can be told
//! from "set to the default": the native `[otel]` value wins, then the alias,
//! then the built-in default. The alias drives traces only, as in
//! `oslo.middleware`; metrics are enabled through `[otel]` alone.

use std::time::Duration;

use oslo_config::{ConfigError, ConfigSection, SectionBag, register_section};
use secrecy::SecretString;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

/// Default OTLP/HTTP endpoint (the `oslo.middleware` default).
const DEFAULT_HTTP_ENDPOINT: &str = "http://localhost:4318";
/// Default OTLP/gRPC endpoint.
const DEFAULT_GRPC_ENDPOINT: &str = "http://localhost:4317";
/// Default `service.name` resource attribute.
const DEFAULT_SERVICE_NAME: &str = "keystone";
/// Default exporter timeout.
const DEFAULT_TIMEOUT_SECS: f64 = 10.0;
/// Default metric export interval.
const DEFAULT_METRICS_INTERVAL_SECS: f64 = 60.0;

/// OTLP transport.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
pub enum OtlpProtocol {
    /// OTLP over HTTP with protobuf bodies (the default).
    #[default]
    #[serde(rename = "http/protobuf")]
    HttpProtobuf,
    /// OTLP over gRPC. Needs the `otlp-grpc` cargo feature at build time.
    #[serde(rename = "grpc")]
    Grpc,
}

/// Trace sampler.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SamplerKind {
    /// Follow the remote parent's decision, `sampling_rate` for root spans.
    #[default]
    ParentBasedRatio,
    /// `sampling_rate` for every span, ignoring the remote parent.
    Ratio,
    /// Sample everything.
    AlwaysOn,
    /// Sample nothing.
    AlwaysOff,
}

/// Most verbose span level exported (spans below it are not sent).
///
/// Most driver-level `#[instrument]` spans are `debug`, so the default keeps
/// the export to request-level and coarse operation spans.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SpanLevel {
    /// Only `error` spans.
    Error,
    /// `warn` and above.
    Warn,
    /// `info` and above (default).
    #[default]
    Info,
    /// `debug` and above.
    Debug,
    /// Everything.
    Trace,
}

/// `[otel]`: native OpenTelemetry configuration.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct OtelConfig {
    /// Master switch for the OTLP pipeline (default `false`).
    pub enabled: Option<bool>,
    /// Export traces. Defaults to `enabled` (or the alias' `enabled`).
    pub traces_enabled: Option<bool>,
    /// Export metrics. Defaults to `enabled`.
    pub metrics_enabled: Option<bool>,
    /// OTLP endpoint. For HTTP the signal path (`/v1/traces`, `/v1/metrics`)
    /// is appended. Default `http://localhost:4318` (`:4317` for gRPC).
    pub endpoint: Option<String>,
    /// `http/protobuf` (default) or `grpc`.
    pub protocol: Option<OtlpProtocol>,
    /// Extra exporter headers as `name=value,name2=value2`. May carry
    /// credentials, so it is never logged.
    pub headers: Option<SecretString>,
    /// Exporter timeout in seconds (default 10).
    pub timeout: Option<f64>,
    /// gRPC only, as in `oslo.middleware`: connect without TLS even to an
    /// `https` endpoint. Ignored for `http/protobuf`, where the URL scheme
    /// decides. Development only.
    pub insecure: Option<bool>,
    /// `service.name` resource attribute (default `keystone`).
    pub service_name: Option<String>,
    /// Extra resource attributes as `key=value,key2=value2`.
    pub resource_attributes: Option<String>,
    /// Trace sampler (default `parent_based_ratio`).
    pub sampler: Option<SamplerKind>,
    /// Sampling ratio in `0.0..=1.0` (default `1.0`).
    pub sampling_rate: Option<f64>,
    /// Most verbose span level exported (default `info`).
    pub span_level: Option<SpanLevel>,
    /// Metric export interval in seconds (default 60).
    pub metrics_interval: Option<f64>,
    /// Add `openstack.user_id`, `openstack.project_id` and
    /// `openstack.domain_id` to request spans. Off by default: spans leave
    /// the host.
    pub include_user_ids: Option<bool>,
    /// Add `client.address` (the caller's IP) to request spans. Off by
    /// default: it is personal data and spans leave the host.
    pub include_client_address: Option<bool>,
    /// Also emit the pre-stable `http.method`, `http.url` and
    /// `http.status_code` attribute names `oslo.middleware` uses.
    pub legacy_http_attributes: Option<bool>,
    /// Echo `traceparent` in HTTP responses, as `oslo.middleware` does.
    pub response_traceparent: Option<bool>,
}

impl ConfigSection for OtelConfig {
    const NAME: &'static str = "otel";

    fn validate_with(&self, sections: &SectionBag) -> Result<(), ConfigError> {
        let alias = sections
            .get::<OsloMiddlewareTracingConfig>()
            .cloned()
            .unwrap_or_default();
        resolve(self, &alias)?;
        Ok(())
    }
}

// Optional: telemetry is off unless configured.
register_section!(OtelConfig, default);

/// `[oslo_middleware_tracing]`: alias for the options of
/// `oslo_middleware.tracing.TracingMiddleware`. Traces only.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct OsloMiddlewareTracingConfig {
    /// Alias of `[otel] enabled` (traces).
    pub enabled: Option<bool>,
    /// Alias of `[otel] endpoint`.
    pub otlp_endpoint: Option<String>,
    /// Alias of `[otel] protocol`.
    pub otlp_protocol: Option<OtlpProtocol>,
    /// Alias of `[otel] service_name`.
    pub service_name: Option<String>,
    /// Alias of `[otel] sampling_rate`.
    pub sampling_rate: Option<f64>,
    /// Alias of `[otel] insecure`.
    pub insecure: Option<bool>,
}

impl OsloMiddlewareTracingConfig {
    /// Whether any option of the alias section is set.
    fn is_set(&self) -> bool {
        self.enabled.is_some()
            || self.otlp_endpoint.is_some()
            || self.otlp_protocol.is_some()
            || self.service_name.is_some()
            || self.sampling_rate.is_some()
            || self.insecure.is_some()
    }
}

impl ConfigSection for OsloMiddlewareTracingConfig {
    const NAME: &'static str = "oslo_middleware_tracing";
}

register_section!(OsloMiddlewareTracingConfig, default);

/// Invalid telemetry configuration.
#[derive(Debug, Error)]
pub enum TelemetryConfigError {
    /// `endpoint` is not an `http`/`https` URL.
    #[error("[otel] endpoint {0:?} is not a valid http(s) URL")]
    Endpoint(String),
    /// `sampling_rate` is outside `0.0..=1.0`.
    #[error("sampling_rate must be within 0.0..=1.0, got {0}")]
    SamplingRate(f64),
    /// A duration option is not a positive, finite number of seconds.
    #[error("{option} must be a positive number of seconds, got {value}")]
    Duration {
        /// Option name.
        option: &'static str,
        /// Offending value.
        value: f64,
    },
    /// `service_name` is empty.
    #[error("service_name must not be empty")]
    ServiceName,
    /// A `name=value` list has an entry without a name or a `=`.
    #[error("{option} must be a comma separated list of name=value, bad entry at position {index}")]
    KeyValue {
        /// Option name.
        option: &'static str,
        /// Zero based position of the bad entry (the value is not echoed: it
        /// can be a credential).
        index: usize,
    },
}

/// The effective, validated telemetry settings.
#[derive(Clone, Debug)]
pub struct TelemetrySettings {
    /// Export traces.
    pub traces_enabled: bool,
    /// Export metrics.
    pub metrics_enabled: bool,
    /// OTLP endpoint (without the signal path).
    pub endpoint: Url,
    /// OTLP transport.
    pub protocol: OtlpProtocol,
    /// Exporter headers; values are secrets.
    pub headers: Vec<(String, SecretString)>,
    /// Exporter timeout.
    pub timeout: Duration,
    /// Connect over gRPC without TLS (ignored for `http/protobuf`).
    pub insecure: bool,
    /// `service.name`.
    pub service_name: String,
    /// Extra resource attributes.
    pub resource_attributes: Vec<(String, String)>,
    /// Trace sampler.
    pub sampler: SamplerKind,
    /// Sampling ratio, `0.0..=1.0`.
    pub sampling_rate: f64,
    /// Most verbose span level exported.
    pub span_level: SpanLevel,
    /// Metric export interval.
    pub metrics_interval: Duration,
    /// Add user, project and domain ids to request spans.
    pub include_user_ids: bool,
    /// Add the caller's IP to request spans.
    pub include_client_address: bool,
    /// Also emit the pre-stable HTTP attribute names.
    pub legacy_http_attributes: bool,
    /// Echo `traceparent` in responses.
    pub response_traceparent: bool,
}

/// Result of [`resolve`].
#[derive(Clone, Debug)]
pub struct Resolved {
    /// `None` when neither traces nor metrics are enabled.
    pub settings: Option<TelemetrySettings>,
    /// Notes for the operator about the alias section (to be logged once the
    /// subscriber is installed).
    pub warnings: Vec<String>,
}

/// Merge `[otel]` with the `[oslo_middleware_tracing]` alias and validate it.
///
/// Precedence per option: `[otel]`, then the alias, then the default. The
/// whole configuration is validated even when telemetry is disabled, so a
/// typo fails the load instead of surfacing when somebody turns it on.
pub fn resolve(
    otel: &OtelConfig,
    alias: &OsloMiddlewareTracingConfig,
) -> Result<Resolved, TelemetryConfigError> {
    let mut warnings = Vec::new();
    if alias.is_set() {
        warnings.push(
            "[oslo_middleware_tracing] is an alias of [otel] (traces only); prefer [otel]"
                .to_string(),
        );
    }
    let mut merged = |name: &str, native_set: bool, alias_set: bool, differs: bool| {
        if native_set && alias_set && differs {
            warnings.push(format!(
                "{name} is set in both [otel] and [oslo_middleware_tracing] with different \
                 values; [otel] wins"
            ));
        }
    };

    let enabled = otel.enabled.or(alias.enabled).unwrap_or(false);
    merged(
        "enabled",
        otel.enabled.is_some(),
        alias.enabled.is_some(),
        otel.enabled != alias.enabled,
    );
    let traces_enabled = otel.traces_enabled.unwrap_or(enabled);
    // The alias never turns metrics on.
    let metrics_enabled = otel
        .metrics_enabled
        .unwrap_or(otel.enabled.unwrap_or(false));

    let protocol = otel.protocol.or(alias.otlp_protocol).unwrap_or_default();
    merged(
        "protocol",
        otel.protocol.is_some(),
        alias.otlp_protocol.is_some(),
        otel.protocol != alias.otlp_protocol,
    );

    let endpoint_str = otel
        .endpoint
        .clone()
        .or_else(|| alias.otlp_endpoint.clone())
        .unwrap_or_else(|| match protocol {
            OtlpProtocol::HttpProtobuf => DEFAULT_HTTP_ENDPOINT.to_string(),
            OtlpProtocol::Grpc => DEFAULT_GRPC_ENDPOINT.to_string(),
        });
    merged(
        "endpoint",
        otel.endpoint.is_some(),
        alias.otlp_endpoint.is_some(),
        otel.endpoint != alias.otlp_endpoint,
    );
    let endpoint = Url::parse(&endpoint_str)
        .ok()
        .filter(|u| matches!(u.scheme(), "http" | "https") && u.has_host())
        .ok_or_else(|| TelemetryConfigError::Endpoint(endpoint_str.clone()))?;

    let service_name = otel
        .service_name
        .clone()
        .or_else(|| alias.service_name.clone())
        .unwrap_or_else(|| DEFAULT_SERVICE_NAME.to_string());
    merged(
        "service_name",
        otel.service_name.is_some(),
        alias.service_name.is_some(),
        otel.service_name != alias.service_name,
    );
    if service_name.trim().is_empty() {
        return Err(TelemetryConfigError::ServiceName);
    }

    let sampling_rate = otel.sampling_rate.or(alias.sampling_rate).unwrap_or(1.0);
    merged(
        "sampling_rate",
        otel.sampling_rate.is_some(),
        alias.sampling_rate.is_some(),
        otel.sampling_rate != alias.sampling_rate,
    );
    if !(0.0..=1.0).contains(&sampling_rate) {
        return Err(TelemetryConfigError::SamplingRate(sampling_rate));
    }

    let insecure = otel.insecure.or(alias.insecure).unwrap_or(false);
    merged(
        "insecure",
        otel.insecure.is_some(),
        alias.insecure.is_some(),
        otel.insecure != alias.insecure,
    );

    if insecure && protocol == OtlpProtocol::HttpProtobuf {
        warnings.push(
            "insecure only applies to the grpc protocol; for http/protobuf the endpoint scheme \
             selects TLS"
                .to_string(),
        );
    }

    let timeout = seconds("timeout", otel.timeout.unwrap_or(DEFAULT_TIMEOUT_SECS))?;
    let metrics_interval = seconds(
        "metrics_interval",
        otel.metrics_interval
            .unwrap_or(DEFAULT_METRICS_INTERVAL_SECS),
    )?;

    let headers = match &otel.headers {
        Some(raw) => {
            use secrecy::ExposeSecret;
            key_values("headers", raw.expose_secret())?
                .into_iter()
                .map(|(k, v)| (k, SecretString::from(v)))
                .collect()
        }
        None => Vec::new(),
    };
    let resource_attributes = match &otel.resource_attributes {
        Some(raw) => key_values("resource_attributes", raw)?,
        None => Vec::new(),
    };

    let settings = (traces_enabled || metrics_enabled).then_some(TelemetrySettings {
        traces_enabled,
        metrics_enabled,
        endpoint,
        protocol,
        headers,
        timeout,
        insecure,
        service_name,
        resource_attributes,
        sampler: otel.sampler.unwrap_or_default(),
        sampling_rate,
        span_level: otel.span_level.unwrap_or_default(),
        metrics_interval,
        include_user_ids: otel.include_user_ids.unwrap_or(false),
        include_client_address: otel.include_client_address.unwrap_or(false),
        legacy_http_attributes: otel.legacy_http_attributes.unwrap_or(false),
        response_traceparent: otel.response_traceparent.unwrap_or(false),
    });
    Ok(Resolved { settings, warnings })
}

/// A positive, finite number of seconds as a [`Duration`].
fn seconds(option: &'static str, value: f64) -> Result<Duration, TelemetryConfigError> {
    if value.is_finite() && value > 0.0 {
        Duration::try_from_secs_f64(value)
            .map_err(|_| TelemetryConfigError::Duration { option, value })
    } else {
        Err(TelemetryConfigError::Duration { option, value })
    }
}

/// Parse `name=value,name2=value2`. Empty entries are skipped; an entry with
/// no name or no `=` is an error that names its position only, never its
/// content (header values can be credentials).
fn key_values(
    option: &'static str,
    raw: &str,
) -> Result<Vec<(String, String)>, TelemetryConfigError> {
    raw.split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .enumerate()
        .map(|(index, entry)| {
            entry
                .split_once('=')
                .map(|(k, v)| (k.trim(), v.trim()))
                .filter(|(k, _)| !k.is_empty())
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or(TelemetryConfigError::KeyValue { option, index })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use secrecy::ExposeSecret;

    use super::*;

    fn otel(json: &str) -> OtelConfig {
        serde_json::from_str(json).unwrap()
    }

    fn alias(json: &str) -> OsloMiddlewareTracingConfig {
        serde_json::from_str(json).unwrap()
    }

    fn resolved(otel_json: &str, alias_json: &str) -> Resolved {
        resolve(&otel(otel_json), &alias(alias_json)).unwrap()
    }

    #[test]
    fn disabled_by_default() {
        let r = resolve(
            &OtelConfig::default(),
            &OsloMiddlewareTracingConfig::default(),
        )
        .unwrap();
        assert!(r.settings.is_none());
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn native_defaults() {
        let s = resolved(r#"{"enabled": true}"#, "{}").settings.unwrap();
        assert!(s.traces_enabled && s.metrics_enabled);
        assert_eq!(s.endpoint.as_str(), "http://localhost:4318/");
        assert_eq!(s.protocol, OtlpProtocol::HttpProtobuf);
        assert_eq!(s.service_name, "keystone");
        assert_eq!(s.sampler, SamplerKind::ParentBasedRatio);
        assert_eq!(s.span_level, SpanLevel::Info);
        assert_eq!(s.sampling_rate, 1.0);
        assert_eq!(s.timeout, Duration::from_secs(10));
        assert_eq!(s.metrics_interval, Duration::from_secs(60));
        assert!(!s.insecure && !s.include_user_ids && !s.include_client_address);
        assert!(!s.legacy_http_attributes && !s.response_traceparent);
        assert!(s.headers.is_empty() && s.resource_attributes.is_empty());
    }

    #[test]
    fn grpc_default_endpoint_uses_the_grpc_port() {
        let s = resolved(r#"{"enabled": true, "protocol": "grpc"}"#, "{}")
            .settings
            .unwrap();
        assert_eq!(s.endpoint.as_str(), "http://localhost:4317/");
    }

    #[test]
    fn alias_enables_traces_only() {
        let r = resolved(
            "{}",
            r#"{"enabled": true, "otlp_endpoint": "http://tempo:4318",
                "otlp_protocol": "http/protobuf", "service_name": "keystone-api",
                "sampling_rate": 0.25, "insecure": true}"#,
        );
        let s = r.settings.unwrap();
        assert!(s.traces_enabled);
        assert!(!s.metrics_enabled, "the alias never enables metrics");
        assert_eq!(s.endpoint.as_str(), "http://tempo:4318/");
        assert_eq!(s.service_name, "keystone-api");
        assert_eq!(s.sampling_rate, 0.25);
        assert!(s.insecure);
        // The alias note, and `insecure` is meaningless for http/protobuf.
        assert_eq!(r.warnings.len(), 2, "{:?}", r.warnings);
        assert!(r.warnings[0].contains("alias"));
        assert!(r.warnings[1].starts_with("insecure only applies"));
    }

    #[test]
    fn native_wins_over_the_alias_and_warns() {
        let r = resolved(
            r#"{"enabled": true, "endpoint": "https://collector:4318",
                "service_name": "native", "sampling_rate": 0.5}"#,
            r#"{"otlp_endpoint": "http://tempo:4318", "service_name": "alias",
                "sampling_rate": 0.1}"#,
        );
        let s = r.settings.unwrap();
        assert_eq!(s.endpoint.as_str(), "https://collector:4318/");
        assert_eq!(s.service_name, "native");
        assert_eq!(s.sampling_rate, 0.5);
        for option in ["endpoint", "service_name", "sampling_rate"] {
            assert!(
                r.warnings.iter().any(|w| w.starts_with(option)),
                "missing warning for {option}: {:?}",
                r.warnings
            );
        }
    }

    #[test]
    fn same_value_in_both_sections_does_not_conflict() {
        let r = resolved(
            r#"{"enabled": true, "service_name": "same"}"#,
            r#"{"service_name": "same"}"#,
        );
        assert!(!r.warnings.iter().any(|w| w.starts_with("service_name")));
    }

    #[test]
    fn explicit_native_disable_beats_alias_enable() {
        let r = resolved(r#"{"enabled": false}"#, r#"{"enabled": true}"#);
        assert!(r.settings.is_none());
        assert!(r.warnings.iter().any(|w| w.starts_with("enabled")));
    }

    #[test]
    fn traces_and_metrics_switches_are_independent() {
        let s = resolved(r#"{"enabled": true, "metrics_enabled": false}"#, "{}")
            .settings
            .unwrap();
        assert!(s.traces_enabled && !s.metrics_enabled);
        let s = resolved(r#"{"enabled": true, "traces_enabled": false}"#, "{}")
            .settings
            .unwrap();
        assert!(!s.traces_enabled && s.metrics_enabled);
    }

    #[test]
    fn headers_and_resource_attributes_are_parsed() {
        let s = resolved(
            r#"{"enabled": true, "headers": "authorization=Bearer abc, x-tenant=a=b",
                "resource_attributes": "deployment.environment=prod,,region=eu"}"#,
            "{}",
        )
        .settings
        .unwrap();
        assert_eq!(s.headers.len(), 2);
        assert_eq!(s.headers[0].0, "authorization");
        assert_eq!(s.headers[0].1.expose_secret(), "Bearer abc");
        assert_eq!(s.headers[1].1.expose_secret(), "a=b");
        assert_eq!(
            s.resource_attributes,
            vec![
                ("deployment.environment".to_string(), "prod".to_string()),
                ("region".to_string(), "eu".to_string())
            ]
        );
        // Secrets must not show up in Debug output.
        assert!(!format!("{s:?}").contains("Bearer abc"));
    }

    #[test]
    fn invalid_values_are_rejected_even_when_disabled() {
        let bad = |otel_json: &str| resolve(&otel(otel_json), &Default::default()).unwrap_err();
        assert!(matches!(
            bad(r#"{"endpoint": "ftp://x"}"#),
            TelemetryConfigError::Endpoint(_)
        ));
        assert!(matches!(
            bad(r#"{"endpoint": "not a url"}"#),
            TelemetryConfigError::Endpoint(_)
        ));
        assert!(matches!(
            bad(r#"{"sampling_rate": 1.5}"#),
            TelemetryConfigError::SamplingRate(_)
        ));
        assert!(matches!(
            bad(r#"{"sampling_rate": -0.1}"#),
            TelemetryConfigError::SamplingRate(_)
        ));
        assert!(matches!(
            bad(r#"{"timeout": 0}"#),
            TelemetryConfigError::Duration {
                option: "timeout",
                ..
            }
        ));
        assert!(matches!(
            bad(r#"{"metrics_interval": -5}"#),
            TelemetryConfigError::Duration {
                option: "metrics_interval",
                ..
            }
        ));
        assert!(matches!(
            bad(r#"{"service_name": "  "}"#),
            TelemetryConfigError::ServiceName
        ));
        assert!(matches!(
            bad(r#"{"headers": "ok=1,broken"}"#),
            TelemetryConfigError::KeyValue {
                option: "headers",
                index: 1
            }
        ));
        assert!(matches!(
            bad(r#"{"resource_attributes": "=novalue"}"#),
            TelemetryConfigError::KeyValue {
                option: "resource_attributes",
                index: 0
            }
        ));
    }

    #[test]
    fn key_value_error_does_not_echo_the_value() {
        let err = resolve(
            &otel(r#"{"headers": "authorization Bearer hunter2"}"#),
            &Default::default(),
        )
        .unwrap_err();
        assert!(!err.to_string().contains("hunter2"));
    }

    #[test]
    fn insecure_with_http_protobuf_is_flagged_as_ignored() {
        let r = resolved(r#"{"enabled": true, "insecure": true}"#, "{}");
        assert!(
            r.warnings
                .iter()
                .any(|w| w.starts_with("insecure only applies"))
        );
        let r = resolved(
            r#"{"enabled": true, "insecure": true, "protocol": "grpc"}"#,
            "{}",
        );
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn client_address_is_opt_in() {
        let s = resolved(r#"{"enabled": true, "include_client_address": true}"#, "{}")
            .settings
            .unwrap();
        assert!(s.include_client_address);
        assert!(!s.include_user_ids, "independent of include_user_ids");
    }

    #[test]
    fn span_level_is_parsed() {
        let s = resolved(r#"{"enabled": true, "span_level": "debug"}"#, "{}")
            .settings
            .unwrap();
        assert_eq!(s.span_level, SpanLevel::Debug);
        assert!(serde_json::from_str::<OtelConfig>(r#"{"span_level": "loud"}"#).is_err());
    }

    #[test]
    fn unknown_protocol_and_sampler_fail_to_parse() {
        assert!(serde_json::from_str::<OtelConfig>(r#"{"protocol": "udp"}"#).is_err());
        assert!(serde_json::from_str::<OtelConfig>(r#"{"sampler": "sometimes"}"#).is_err());
        assert!(
            serde_json::from_str::<OsloMiddlewareTracingConfig>(r#"{"otlp_protocol": "grpc"}"#)
                .is_ok()
        );
    }
}
