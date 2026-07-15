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
//! Live-server `GET /v4/oauth2/{domain_id}/jwks/revocation` (ADR 0026 §3,
//! §11). Unauthenticated by design -- relying parties must be able to
//! fetch it without a Keystone token.

use eyre::Result;
use reqwest::StatusCode;
use tracing_test::traced_test;

use test_api::oauth2::get_jwks_revocation;

#[tokio::test]
#[traced_test]
async fn test_jwks_revocation_is_reachable_without_authentication() -> Result<()> {
    // `default` is guaranteed to exist (bootstrap domain) and to have
    // signing keys provisioned (`tools/start-api.sh` polls for this before
    // signaling readiness), so this hits a real, populated domain rather
    // than exercising the `NotFound` path.
    let (status, _body) = get_jwks_revocation("default").await?;
    assert_eq!(status, StatusCode::OK);
    Ok(())
}
