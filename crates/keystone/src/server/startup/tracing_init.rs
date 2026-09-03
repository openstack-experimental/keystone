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
//! rotating file appender.

use std::io;

use color_eyre::eyre::Result;
use tracing_appender::non_blocking::NonBlockingBuilder;
use tracing_error::ErrorLayer;
use tracing_subscriber::{
    Layer,
    filter::{LevelFilter, Targets},
    prelude::*,
};

use crate::config::Config;

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

/// Initialize the tracing subscriber registry (stderr, optionally a native
/// systemd journal writer, and optionally a rotating file appender) based on
/// CLI verbosity and the loaded config.
///
/// Returns the file-appender's `WorkerGuard`, if file logging is enabled.
/// The caller must keep this alive for the process lifetime — dropping it
/// stops buffered log lines from being flushed.
pub fn init(
    verbose: u8,
    cfg: &Config,
) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
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

    if cfg.default.use_stderr {
        log_layers.push(
            tracing_subscriber::fmt::layer()
                .with_writer(io::stderr)
                .with_filter(deps_targets(stderr_default, stderr_deps))
                .boxed(),
        );
    }

    if cfg.default.use_journal {
        match tracing_journald::layer() {
            Ok(journald_layer) => {
                log_layers.push(
                    journald_layer
                        .with_filter(deps_targets(file_level, file_level))
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
                .with_filter(deps_targets(file_level, file_level))
                .boxed(),
        );
    }

    tracing_subscriber::registry()
        .with(ErrorLayer::default())
        .with(log_layers)
        .init();

    Ok(guard)
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
