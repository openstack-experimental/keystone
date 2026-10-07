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

//! Tracing subscriber setup: stderr, optional systemd journal, optional
//! rotating file appender, and (with the `otel` feature and `[otel]`
//! configured) the OpenTelemetry span exporter (ADR 0040).

use std::io;

use color_eyre::eyre::Result;
use tracing_appender::non_blocking::NonBlockingBuilder;
use tracing_error::ErrorLayer;
use tracing_subscriber::{
    Layer,
    filter::{LevelFilter, Targets},
    prelude::*,
};

#[cfg(feature = "otel")]
use openstack_keystone_telemetry::SpanLevel;
use openstack_keystone_telemetry::{OsloMiddlewareTracingConfig, OtelConfig, Resolved, resolve};
#[cfg(feature = "otel")]
use tracing_subscriber::filter::{FilterExt as _, filter_fn};

use crate::server::request_span::SERVER_SPAN_TARGET;

/// The running OTLP pipeline; uninhabited when the `otel` feature is off.
#[cfg(feature = "otel")]
pub type TelemetryHandle = openstack_keystone_telemetry::TelemetryGuard;
/// The running OTLP pipeline; uninhabited when the `otel` feature is off.
#[cfg(not(feature = "otel"))]
pub type TelemetryHandle = std::convert::Infallible;

/// Everything that must outlive the subscriber.
pub struct Guards {
    /// Flushes buffered file log lines when dropped.
    _file: Option<tracing_appender::non_blocking::WorkerGuard>,
    /// The OTLP pipeline, when one is exporting.
    telemetry: Option<TelemetryHandle>,
    /// The merged `[otel]` / `[oslo_middleware_tracing]` configuration.
    pub resolved: Option<Resolved>,
    /// Why the OTLP pipeline could not be started (startup continues
    /// without it: telemetry never blocks the service).
    pub telemetry_error: Option<String>,
}

impl Guards {
    /// Whether spans and metrics are being exported.
    pub fn exporting(&self) -> bool {
        self.telemetry.is_some()
    }

    /// Flush and stop the exporters. The SDK blocks while it drains its
    /// queues, so this runs on a blocking thread.
    pub async fn shutdown(self) {
        #[cfg(not(feature = "otel"))]
        let _ = self;
        #[cfg(feature = "otel")]
        if let Some(mut telemetry) = self.telemetry {
            match tokio::task::spawn_blocking(move || telemetry.shutdown()).await {
                Ok(errors) => {
                    for err in errors {
                        tracing::warn!("telemetry: {err}");
                    }
                }
                Err(err) => tracing::warn!("telemetry: shutdown task failed: {err}"),
            }
        }
    }
}

/// Whether the OpenTelemetry layer may see this callsite.
///
/// Spans only: an event inside a span becomes an OTel span event carrying all
/// its fields, which would ship log lines (the access log's raw URI, error
/// bodies) off the host. Events stay in the log sinks. The `request` span is
/// the log-only span `TraceLayer` makes, with `client.addr` and the raw `uri`
/// as fields that the exporter would send; `http.server` replaces it.
#[cfg(feature = "otel")]
fn exportable(meta: &tracing::Metadata<'_>) -> bool {
    meta.is_span() && meta.name() != "request"
}

/// Most verbose span level the OTLP layer admits.
#[cfg(feature = "otel")]
fn span_level_filter(level: SpanLevel) -> LevelFilter {
    match level {
        SpanLevel::Error => LevelFilter::ERROR,
        SpanLevel::Warn => LevelFilter::WARN,
        SpanLevel::Info => LevelFilter::INFO,
        SpanLevel::Debug => LevelFilter::DEBUG,
        SpanLevel::Trace => LevelFilter::TRACE,
    }
}

/// Shared target-level allow-list for every log sink.
///
/// `default` is the fallback level for Keystone's own spans/events; `deps` is
/// the level applied to the chatty third-party crates (`h2`, `rustls`,
/// `tower`, `openraft`, `lsm_tree`). The Cranelift/Wasmtime and `hyper_util`
/// targets are always pinned to `ERROR`, and `tower_http` always to `INFO`,
/// regardless of sink.
fn deps_targets(default: LevelFilter, deps: LevelFilter) -> Targets {
    Targets::new()
        .with_default(default)
        .with_target("cranelift_codegen", LevelFilter::ERROR)
        .with_target("wasmtime_internal_cranelift", LevelFilter::ERROR)
        .with_target("wasmtime", LevelFilter::ERROR)
        .with_target("h2", deps)
        .with_target("rustls", deps)
        .with_target("tower", deps)
        .with_target("tower_http", LevelFilter::INFO)
        .with_target("openraft", deps)
        .with_target("lsm_tree", deps)
        .with_target("hyper_util", LevelFilter::ERROR)
}

/// [`deps_targets`] for the log sinks: the OpenTelemetry `http.server` span is
/// export-only and would only add noise to the log lines' span context.
fn log_targets(default: LevelFilter, deps: LevelFilter) -> Targets {
    deps_targets(default, deps).with_target(SERVER_SPAN_TARGET, LevelFilter::OFF)
}

/// Initialize the tracing subscriber registry (stderr, optionally a native
/// systemd journal writer, and optionally a rotating file appender) based on
/// CLI verbosity and the loaded config.
///
/// Returns the [`Guards`]. The caller must keep them alive for the process
/// lifetime — dropping the file guard stops buffered log lines from being
/// flushed — and call [`Guards::shutdown`] on the way out to flush spans.
pub fn init(verbose: u8, cfg: &crate::config::LoadedConfig) -> Result<Guards> {
    // `-v`/`-vv` only affect stderr; file and journald levels are driven by
    // `cfg.default.debug`.
    let stderr_default = match verbose {
        0 => LevelFilter::WARN,
        1 => LevelFilter::INFO,
        2 => LevelFilter::DEBUG,
        _ => LevelFilter::TRACE,
    };
    let stderr_deps = match verbose {
        0 => LevelFilter::ERROR,
        1 => LevelFilter::WARN,
        2 => LevelFilter::INFO,
        _ => LevelFilter::DEBUG,
    };
    let file_level = if cfg.default.debug {
        LevelFilter::DEBUG
    } else {
        LevelFilter::INFO
    };

    let mut log_layers = Vec::new();

    // Built before the subscriber exists, so a failure here can only be
    // reported once logging is up (see `Guards::telemetry_error`).
    let (resolved, telemetry, telemetry_error) = init_telemetry(cfg);

    if cfg.default.use_stderr {
        log_layers.push(
            tracing_subscriber::fmt::layer()
                .with_writer(io::stderr)
                .with_filter(log_targets(stderr_default, stderr_deps))
                .boxed(),
        );
    }

    if cfg.default.use_journal {
        match tracing_journald::layer() {
            Ok(journald_layer) => {
                log_layers.push(
                    journald_layer
                        .with_filter(log_targets(file_level, file_level))
                        .boxed(),
                );
            }
            Err(err) => {
                // The subscriber isn't installed yet, so fall back to stderr
                // directly for this one diagnostic.
                eprintln!(
                    "Failed to connect to the systemd journal socket, use_journal logging disabled: {err}"
                );
            }
        }
    }

    let mut guard = None;
    if let Some(log_dir) = &cfg.default.log_dir {
        let file_appender = build_file_appender(log_dir, &cfg.default);
        // Non-blocking, but never lossy: events must not be dropped when the
        // worker thread can't keep up. The guard must outlive the registry
        // so buffered lines get flushed.
        let (non_blocking, file_guard) = NonBlockingBuilder::default()
            .lossy(false)
            .finish(file_appender);
        guard = Some(file_guard);

        log_layers.push(
            tracing_subscriber::fmt::layer()
                .with_ansi(false) // no colors in the log file
                .with_writer(non_blocking)
                .with_filter(log_targets(file_level, file_level))
                .boxed(),
        );
    }

    #[cfg(feature = "otel")]
    if let (Some(handle), Some(settings)) = (
        &telemetry,
        resolved.as_ref().and_then(|r| r.settings.as_ref()),
    ) && let Some(layer) = handle.tracing_layer()
    {
        // Own filter: only request-level and coarse operation spans leave the
        // process (see `[otel] span_level`); driver DEBUG spans stay local.
        log_layers.push(
            layer
                .with_filter(
                    deps_targets(span_level_filter(settings.span_level), LevelFilter::ERROR)
                        .and(filter_fn(exportable)),
                )
                .boxed(),
        );
    }

    tracing_subscriber::registry()
        .with(ErrorLayer::default())
        .with(log_layers)
        .init();

    Ok(Guards {
        _file: guard,
        telemetry,
        resolved,
        telemetry_error,
    })
}

/// Resolve the telemetry configuration and, if it asks for export and this
/// build can, start the OTLP pipeline.
fn init_telemetry(
    cfg: &crate::config::LoadedConfig,
) -> (Option<Resolved>, Option<TelemetryHandle>, Option<String>) {
    let view = cfg.view();
    let (Some(otel), Some(alias)) = (
        view.section::<OtelConfig>(),
        view.section::<OsloMiddlewareTracingConfig>(),
    ) else {
        return (None, None, None);
    };
    // Validated at load time (`OtelConfig::validate_with`).
    let resolved = match resolve(otel, alias) {
        Ok(resolved) => resolved,
        Err(err) => return (None, None, Some(err.to_string())),
    };

    #[cfg(feature = "otel")]
    if let Some(settings) = &resolved.settings {
        return match openstack_keystone_telemetry::init(settings, env!("CARGO_PKG_VERSION")) {
            Ok(handle) => (Some(resolved), Some(handle), None),
            Err(err) => (Some(resolved), None, Some(err.to_string())),
        };
    }
    (Some(resolved), None, None)
}

/// Build the file-log appender for `[DEFAULT] log_dir`, honoring the
/// `oslo_log`-mirroring rotation options (`log_rotation_type`,
/// `log_rotate_interval_type`, `max_logfile_count`) documented on
/// [`crate::config::DefaultSection`].
///
/// Called before the tracing subscriber is installed by [`init`], so
/// diagnostics here use `eprintln!` directly rather than the `tracing`
/// macros.
fn build_file_appender(
    log_dir: &std::path::Path,
    default: &crate::config::DefaultSection,
) -> tracing_appender::rolling::RollingFileAppender {
    use crate::config::{LogRotateIntervalType, LogRotationType};
    use tracing_appender::rolling::{RollingFileAppender, Rotation};

    let rotation = match default.log_rotation_type {
        LogRotationType::None => Rotation::NEVER,
        LogRotationType::Interval => {
            if !matches!(default.log_rotate_interval, None | Some(1)) {
                eprintln!(
                    "log_rotate_interval={} is not supported (rotation only ever \
                     happens on a single {:?} unit boundary); ignoring the configured value",
                    default.log_rotate_interval.unwrap_or(1),
                    default.log_rotate_interval_type
                );
            }
            match default.log_rotate_interval_type {
                LogRotateIntervalType::Minutes => Rotation::MINUTELY,
                LogRotateIntervalType::Hours => Rotation::HOURLY,
                LogRotateIntervalType::Days | LogRotateIntervalType::Midnight => Rotation::DAILY,
            }
        }
    };

    let mut builder = RollingFileAppender::builder()
        .rotation(rotation)
        .filename_prefix("keystone")
        .filename_suffix("log");
    if let Some(max_logfile_count) = default.max_logfile_count {
        builder = builder.max_log_files(max_logfile_count);
    }

    builder.build(log_dir).unwrap_or_else(|err| {
        eprintln!(
            "Failed to build the rotating log file appender ({err}); falling back to a \
             single non-rotating log file"
        );
        tracing_appender::rolling::never(log_dir, "keystone.log")
    })
}

#[cfg(test)]
#[cfg(feature = "otel")]
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tracing_subscriber::layer::{Context, SubscriberExt as _};
    use tracing_subscriber::{Layer, Registry};

    use super::*;

    /// Records what reaches it.
    #[derive(Clone, Default)]
    struct Seen {
        events: Arc<AtomicUsize>,
        spans: Arc<Mutex<Vec<String>>>,
    }

    impl<S> Layer<S> for Seen
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        fn on_new_span(
            &self,
            attrs: &tracing::span::Attributes<'_>,
            _: &tracing::span::Id,
            _: Context<'_, S>,
        ) {
            self.spans
                .lock()
                .unwrap()
                .push(attrs.metadata().name().to_string());
        }

        fn on_event(&self, _: &tracing::Event<'_>, _: Context<'_, S>) {
            self.events.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn only_spans_other_than_the_log_only_request_span_are_exported() {
        let exported = Seen::default();
        let logged = Seen::default();
        let subscriber = Registry::default()
            .with(exported.clone().with_filter(
                deps_targets(LevelFilter::INFO, LevelFilter::ERROR).and(filter_fn(exportable)),
            ))
            .with(
                logged
                    .clone()
                    .with_filter(log_targets(LevelFilter::INFO, LevelFilter::ERROR)),
            );
        tracing::subscriber::with_default(subscriber, || {
            let request = tracing::info_span!("request", uri = "/v3/users/secret");
            let _request = request.enter();
            let server = tracing::info_span!(target: SERVER_SPAN_TARGET, "http.server");
            let _server = server.enter();
            let driver = tracing::info_span!("driver_call");
            let _driver = driver.enter();
            tracing::info!(http_uri = "/v3/users/secret", "finished processing request");
            tracing::error!("something failed");
        });

        // `http.server` and the driver span are exported; the `request` span
        // and every event are not.
        assert_eq!(
            *exported.spans.lock().unwrap(),
            vec!["http.server".to_string(), "driver_call".to_string()]
        );
        assert_eq!(exported.events.load(Ordering::Relaxed), 0);
        // The log sinks keep the events and the `request` span, but not the
        // export-only span.
        assert_eq!(logged.events.load(Ordering::Relaxed), 2);
        assert_eq!(
            *logged.spans.lock().unwrap(),
            vec!["request".to_string(), "driver_call".to_string()]
        );
    }
}
