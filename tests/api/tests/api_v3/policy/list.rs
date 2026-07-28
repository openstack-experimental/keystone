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

use std::sync::Arc;

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::v3::policy::*;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::guard::ResourceGuard;
use test_api::policy::{create_policy, list_policies, list_policies_by_type};

/// Mirrors tempest's `test_list_policies`: several created policies must all
/// appear in the unfiltered collection.
#[tokio::test]
#[traced_test]
async fn test_list_includes_created_policies() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);

    let mut guards = Vec::new();
    for _ in 0..3 {
        guards.push(
            create_policy(
                &tc,
                PolicyCreateBuilder::default()
                    .blob(format!("BlobName-{}", Uuid::new_v4().simple()))
                    .r#type(format!("PolicyType-{}", Uuid::new_v4().simple()))
                    .build()?,
            )
            .await?,
        );
    }

    let all = list_policies(&tc).await?;
    for guard in &guards {
        assert!(
            all.iter().any(|p| p.id == guard.id),
            "created policy {} must appear in the unfiltered list",
            guard.id
        );
    }

    for guard in guards {
        guard.delete().await?;
    }
    Ok(())
}

/// `?type=` is an exact-match filter.
#[tokio::test]
#[traced_test]
async fn test_list_filters_by_type() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let unique_type = format!("application/{}", Uuid::new_v4().simple());

    let wanted = create_policy(
        &tc,
        PolicyCreateBuilder::default()
            .blob("wanted")
            .r#type(unique_type.clone())
            .build()?,
    )
    .await?;
    let other = create_policy(
        &tc,
        PolicyCreateBuilder::default()
            .blob("other")
            .r#type("text/plain")
            .build()?,
    )
    .await?;

    let filtered = list_policies_by_type(&tc, unique_type.clone()).await?;
    assert!(filtered.iter().any(|p| p.id == wanted.id));
    assert!(
        filtered.iter().all(|p| p.r#type == unique_type),
        "only the requested media type may be returned"
    );
    assert!(!filtered.iter().any(|p| p.id == other.id));

    // A prefix must not match.
    let prefix = list_policies_by_type(&tc, "application").await?;
    assert!(
        !prefix.iter().any(|p| p.id == wanted.id),
        "type filtering must be exact, not a prefix match"
    );

    wanted.delete().await?;
    other.delete().await?;
    Ok(())
}
