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

use openstack_keystone_api_types::v3::user::*;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::guard::ResourceGuard;
use test_api::identity::user::{UserListRequest, create_user, list_users};

/// `GET /v3/users?enabled=<bool>` returns only users with a matching flag.
#[tokio::test]
#[traced_test]
async fn test_list_filter_by_enabled() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let suffix = Uuid::new_v4().simple();

    let enabled_user = create_user(
        &tc,
        UserCreateBuilder::default()
            .name(format!("usr_en_{suffix}"))
            .domain_id("default")
            .enabled(true)
            .build()?,
    )
    .await?;
    let disabled_user = create_user(
        &tc,
        UserCreateBuilder::default()
            .name(format!("usr_dis_{suffix}"))
            .domain_id("default")
            .enabled(false)
            .build()?,
    )
    .await?;

    // Tempest sends Python-style capitalised booleans, so cover both
    // spellings.
    for (query, want_enabled) in [
        ("true", true),
        ("false", false),
        ("True", true),
        ("False", false),
    ] {
        let users = list_users(
            &tc,
            UserListRequest {
                domain_id: Some("default".to_string()),
                enabled: Some(query.to_string()),
                ..Default::default()
            },
        )
        .await?;
        assert!(
            users.iter().all(|u| u.enabled == want_enabled),
            "enabled={query}: every returned user must be enabled={want_enabled}"
        );
        let ids: Vec<&str> = users.iter().map(|u| u.id.as_str()).collect();
        let (present, absent) = if want_enabled {
            (&enabled_user.id, &disabled_user.id)
        } else {
            (&disabled_user.id, &enabled_user.id)
        };
        assert!(ids.contains(&present.as_str()), "enabled={query}");
        assert!(!ids.contains(&absent.as_str()), "enabled={query}");
    }

    enabled_user.delete().await?;
    disabled_user.delete().await?;
    Ok(())
}
