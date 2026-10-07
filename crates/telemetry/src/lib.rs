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

//! # OpenTelemetry support (ADR 0040)
//!
//! OTLP is a first-class output for traces and metrics. This crate owns the
//! configuration of that pipeline:
//!
//! - `[otel]` ([`OtelConfig`]), the native section;
//! - `[oslo_middleware_tracing]` ([`OsloMiddlewareTracingConfig`]), an alias
//!   accepting the options of `oslo_middleware.tracing.TracingMiddleware` so an
//!   existing `keystone.conf` keeps working.
//!
//! [`resolve`] merges the two (native options win) and validates the result
//! into [`TelemetrySettings`]. The SDK setup itself (providers, exporters,
//! shutdown flush) is added behind the `otel` cargo feature in a following
//! change; parsing and validating the configuration never depends on it, so a
//! build without the feature still rejects a malformed section.

pub mod config;
#[cfg(feature = "sdk")]
mod propagation;
#[cfg(feature = "sdk")]
mod sdk;

pub use config::{
    OsloMiddlewareTracingConfig, OtelConfig, OtlpProtocol, Resolved, SamplerKind, SpanLevel,
    TelemetryConfigError, TelemetrySettings, resolve,
};

#[cfg(feature = "sdk")]
pub use propagation::{inject_traceparent, set_remote_parent};
#[cfg(feature = "sdk")]
pub use sdk::{TelemetryGuard, TelemetryInitError, TelemetryShutdownError, init};

/// Whether this build can export OTLP (the `otel` cargo feature).
pub const OTLP_COMPILED: bool = cfg!(feature = "sdk");

/// Linkage anchor — see ADR-0018 and ADR-0039. Referenced by the `keystone`
/// crate's `build.rs`-generated `_ANCHORS` static so the linker keeps the
/// `inventory::submit!` section registrations of this crate.
#[allow(dead_code)]
pub fn anchor() {}
