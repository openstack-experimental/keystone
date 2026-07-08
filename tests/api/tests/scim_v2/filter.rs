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
//! Live-HTTP `GET .../Users?filter=...` (ADR 0024 §5.B), the counterpart of
//! `crates/keystone/src/scim/filter.rs`'s grammar unit tests: driven through
//! the real `list` handler and query-string encoding end to end.

use eyre::Result;
use reqwest::StatusCode;
use tracing_test::traced_test;
use uuid::Uuid;

use test_api::scim::{ScimListResponse, ScimUser, ScimUserWrite, expect_ok};

use super::common::provision_scim_realm;

#[tokio::test]
#[traced_test]
async fn test_filter_by_username_eq() -> Result<()> {
    let provisioned = provision_scim_realm().await?;
    let username = format!("scim-user-{}", Uuid::new_v4().simple());
    let other_username = format!("scim-user-{}", Uuid::new_v4().simple());

    expect_ok::<ScimUser>(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(&username))
            .await?,
    )
    .await?;
    expect_ok::<ScimUser>(
        provisioned
            .client
            .create_user(&ScimUserWrite::new(&other_username))
            .await?,
    )
    .await?;

    let query = format!(
        "filter={}",
        urlencoding_filter(&format!(r#"userName eq "{username}""#))
    );
    let listed: ScimListResponse<ScimUser> =
        expect_ok(provisioned.client.list_users(&query).await?).await?;

    assert_eq!(listed.resources.len(), 1);
    assert_eq!(listed.resources[0].user_name, username);

    provisioned.cleanup().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_filter_rejects_attribute_outside_grammar() -> Result<()> {
    let provisioned = provision_scim_realm().await?;

    let query = format!("filter={}", urlencoding_filter(r#"password eq "whatever""#));
    let rsp = provisioned.client.list_users(&query).await?;
    assert_eq!(rsp.status, StatusCode::BAD_REQUEST);
    assert_eq!(rsp.error()?.scim_type.as_deref(), Some("invalidFilter"));

    provisioned.cleanup().await?;
    Ok(())
}

/// Minimal query-string escaping for a SCIM filter expression -- avoids
/// pulling in a URL-encoding crate just for a handful of characters
/// (`"`, ` `) that appear in RFC 7644 filter literals.
fn urlencoding_filter(raw: &str) -> String {
    raw.replace(' ', "%20").replace('"', "%22")
}
