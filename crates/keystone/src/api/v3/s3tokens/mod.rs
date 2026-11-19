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
//! `/v3/s3tokens` API (ADR 0019 §5): validate an S3 string-to-sign signature
//! and describe the identity behind it. Unlike `/v3/ec2tokens` no usable
//! token (`X-Subject-Token`) is handed out.

use utoipa_axum::{router::OpenApiRouter, routes};

use crate::keystone::ServiceState;

mod create;
pub mod types;

pub(super) fn openapi_router() -> OpenApiRouter<ServiceState> {
    OpenApiRouter::new().routes(routes!(create::create))
}
