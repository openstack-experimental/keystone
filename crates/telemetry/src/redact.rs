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
//! Keeps personal data out of exported spans unless `[otel] include_user_ids`
//! is on (ADR 0040).
//!
//! The HTTP root span declares its id fields only when opted in. The provider
//! and driver spans record the ids they were called with at `debug` level,
//! and a span field cannot be switched off at runtime, so the exporter strips
//! those attributes instead. They stay in the process (local logs).

use std::fmt;
use std::future::Future;
use std::time::Duration;

use opentelemetry_sdk::Resource;
use opentelemetry_sdk::error::OTelSdkResult;
use opentelemetry_sdk::trace::{SpanData, SpanExporter};

/// Attribute names (the last dot-separated segment) that identify a person or
/// their tenancy, or can carry such values.
///
/// `params` is the `Debug` form of a list filter, which holds names and ids.
const PERSONAL_KEYS: [&str; 5] = ["user_id", "project_id", "domain_id", "user_name", "params"];

/// Whether the attribute `key` is personal data.
pub(crate) fn is_personal(key: &str) -> bool {
    let name = key.rsplit('.').next().unwrap_or(key);
    PERSONAL_KEYS.contains(&name)
}

/// A span exporter that removes personal attributes before it hands a batch
/// to the wrapped exporter. With `keep` set it passes batches through.
pub(crate) struct PersonalDataFilter<E> {
    inner: E,
    keep: bool,
}

impl<E> PersonalDataFilter<E> {
    pub(crate) fn new(inner: E, keep: bool) -> Self {
        Self { inner, keep }
    }
}

impl<E> fmt::Debug for PersonalDataFilter<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersonalDataFilter")
            .field("keep", &self.keep)
            .finish_non_exhaustive()
    }
}

impl<E: SpanExporter> SpanExporter for PersonalDataFilter<E> {
    fn export(&self, mut batch: Vec<SpanData>) -> impl Future<Output = OTelSdkResult> + Send {
        if !self.keep {
            for span in &mut batch {
                span.attributes.retain(|kv| !is_personal(kv.key.as_str()));
            }
        }
        self.inner.export(batch)
    }

    fn shutdown_with_timeout(&self, timeout: Duration) -> OTelSdkResult {
        self.inner.shutdown_with_timeout(timeout)
    }

    fn force_flush(&self) -> OTelSdkResult {
        self.inner.force_flush()
    }

    fn set_resource(&mut self, resource: &Resource) {
        self.inner.set_resource(resource);
    }
}

#[cfg(test)]
mod tests {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SimpleSpanProcessor};
    use tracing_subscriber::prelude::*;

    use super::*;

    /// Export one span carrying every kind of attribute through the filter.
    fn exported_keys(keep: bool) -> Vec<String> {
        let memory = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_span_processor(SimpleSpanProcessor::new(PersonalDataFilter::new(
                memory.clone(),
                keep,
            )))
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("test")));
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::debug_span!(
                "provider.identity.list_users",
                user_id = "u",
                project_id = "p",
                domain_id = "d",
                user_name = "alice",
                params = "UserListParameters { name: Some(\"alice\") }",
                openstack.user_id = "u",
                group_id = "g",
            );
            drop(span.entered());
        });
        let spans = memory.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 1);
        let mut keys: Vec<String> = spans[0]
            .attributes
            .iter()
            .map(|kv| kv.key.to_string())
            // Attributes tracing-opentelemetry adds on its own.
            .filter(|k| {
                k != "target"
                    && ["code.", "thread.", "busy", "idle"]
                        .iter()
                        .all(|prefix| !k.starts_with(prefix))
            })
            .collect();
        keys.sort();
        keys
    }

    #[test]
    fn personal_attributes_are_stripped_by_default() {
        assert_eq!(exported_keys(false), ["group_id"]);
    }

    #[test]
    fn personal_attributes_are_kept_when_opted_in() {
        let keys = exported_keys(true);
        for key in [
            "user_id",
            "project_id",
            "domain_id",
            "user_name",
            "params",
            "openstack.user_id",
            "group_id",
        ] {
            assert!(keys.iter().any(|k| k == key), "{key} missing in {keys:?}");
        }
    }

    #[test]
    fn matches_the_last_segment_only() {
        assert!(is_personal("openstack.project_id"));
        assert!(!is_personal("openstack.request_id"));
        assert!(!is_personal("group_id"));
        assert!(!is_personal("user_agent.original"));
    }
}
