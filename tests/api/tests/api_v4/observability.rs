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
//! Live OpenTelemetry checks (ADR 0040, issue #720).
//!
//! Runs against the server started by `tools/start-api.sh` and a real Jaeger
//! that receives its OTLP export:
//!
//! 1. A request carrying a sampled W3C `traceparent` produces a span of that
//!    trace, found in Jaeger by trace id and named `{method} {route}`.
//! 2. `GET /metrics` on the metrics listener counts the same request under the
//!    route template.
//!
//! The test skips when `JAEGER_QUERY_URL` is unset, i.e. everywhere except the
//! CI job that starts Jaeger and sets `KEYSTONE_TEST_OTLP_ENDPOINT` so that
//! `tools/start-api.sh` enables `[otel]`. For a manual run:
//!
//! ```text
//! docker run --rm -p 4318:4318 -p 16686:16686 jaegertracing/jaeger:2.9.0
//! KEYSTONE_TEST_OTLP_ENDPOINT=http://127.0.0.1:4318 \
//! JAEGER_QUERY_URL=http://127.0.0.1:16686 \
//!   cargo nextest run --profile api -p test_api --test integration_api_v4 observability
//! ```
//!
//! `KEYSTONE_URL` and `KEYSTONE_METRICS_URL` (default `http://127.0.0.1:8099`)
//! locate the server.

use std::env;
use std::time::{Duration, Instant};

use eyre::{Result, WrapErr, bail};
use reqwest::{Client, StatusCode};
use serde_json::Value;
use uuid::Uuid;

/// The unauthenticated route used: the 401 is enough to produce a span and a
/// counter, and needs no fixtures.
const ROUTE: &str = "/v3/users";
/// How long to wait for the batched span export to reach Jaeger.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(60);

/// Span names of the trace `trace_id` in Jaeger, or `None` while it is not
/// stored (yet).
async fn trace_span_names(
    client: &Client,
    jaeger: &str,
    trace_id: &str,
) -> Result<Option<Vec<String>>> {
    let rsp = client
        .get(format!("{jaeger}/api/traces/{trace_id}"))
        .send()
        .await
        .wrap_err("querying Jaeger")?;
    if rsp.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let body: Value = rsp.error_for_status()?.json().await?;
    let names: Vec<String> = body["data"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|trace| trace["spans"].as_array().into_iter().flatten())
        .filter_map(|span| span["operationName"].as_str().map(str::to_owned))
        .collect();
    Ok((!names.is_empty()).then_some(names))
}

#[tokio::test]
async fn test_request_is_traced_and_counted() -> Result<()> {
    let Ok(jaeger) = env::var("JAEGER_QUERY_URL") else {
        eprintln!(
            "skipping live OpenTelemetry test: JAEGER_QUERY_URL is not set (see the module \
             documentation)"
        );
        return Ok(());
    };
    let jaeger = jaeger.trim_end_matches('/');
    let keystone = env::var("KEYSTONE_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".into());
    let metrics =
        env::var("KEYSTONE_METRICS_URL").unwrap_or_else(|_| "http://127.0.0.1:8099".into());
    let client = Client::new();

    let trace_id = Uuid::new_v4().simple().to_string();
    let span_id = &Uuid::new_v4().simple().to_string()[..16];
    let rsp = client
        .get(format!("{}{ROUTE}", keystone.trim_end_matches('/')))
        .header("traceparent", format!("00-{trace_id}-{span_id}-01"))
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::UNAUTHORIZED);

    let expected = format!("GET {ROUTE}");
    let deadline = Instant::now() + EXPORT_TIMEOUT;
    loop {
        match trace_span_names(&client, jaeger, &trace_id).await? {
            Some(names) if names.contains(&expected) => break,
            found if Instant::now() >= deadline => {
                bail!("no span `{expected}` of trace {trace_id} in Jaeger, found: {found:?}")
            }
            _ => tokio::time::sleep(Duration::from_secs(1)).await,
        }
    }

    let text = client
        .get(format!("{}/metrics", metrics.trim_end_matches('/')))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let series =
        format!("keystone_http_requests_total{{method=\"GET\",route=\"{ROUTE}\",status=\"401\"}}");
    assert!(
        text.contains(&series),
        "{series} missing from /metrics:\n{text}"
    );
    Ok(())
}
