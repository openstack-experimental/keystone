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
//! # Access log middleware
//!
//! `tower_http::trace::DefaultOnResponse` logs a static "finished processing
//! request" message and puts `uri`/`x_request_id`/etc. as separate `tracing`
//! span fields. `tracing_subscriber::fmt` (stderr/file) flattens those fields
//! into the rendered line, but `tracing_journald::Layer` stores them as
//! distinct journal fields (`F_URI`, `F_X_REQUEST_ID`, ...) rather than
//! folding them into `MESSAGE`. Log collectors that only index `MESSAGE`
//! (e.g. journald-backed Graylog inputs) then can't search by URI or request
//! id.
//!
//! This middleware must run inside the `TraceLayer` span (layered after
//! it) so it replaces `TraceLayer`'s `on_response` and emits one line with
//! method/uri/request id/status/latency baked directly into the message
//! text, not just as structured fields.

use std::time::Instant;

use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;

pub async fn log_request(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().path().to_string();
    let request_id = req
        .headers()
        .get("x-openstack-request-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
        .unwrap_or_else(|| "-".to_owned());

    let start = Instant::now();
    let response = next.run(req).await;
    let status = response.status();
    let latency_us = start.elapsed().as_micros();

    tracing::info!(
        %method,
        %uri,
        %request_id,
        %status,
        latency_us,
        "finished processing request: {method} {uri} id={request_id} status={status} latency_us={latency_us}"
    );

    response
}
