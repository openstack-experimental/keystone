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

use openstack_keystone_api_types::v3::trust::*;
use openstack_keystone_api_types::v3::user::UserCreateBuilder;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::guard::ResourceGuard;
use test_api::identity::user::create_user;
use test_api::trust::{create_trust, show_trust};

use super::TrustorSession;

#[tokio::test]
#[traced_test]
async fn test_delete_trust() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let trustor = TrustorSession::provision(&tc, "default").await?;

    let trustee = create_user(
        &tc,
        UserCreateBuilder::default()
            .name(Uuid::new_v4().simple().to_string())
            .domain_id("default")
            .enabled(true)
            .build()?,
    )
    .await?;

    let trust = create_trust(
        &trustor.session,
        TrustCreate {
            id: None,
            trustor_user_id: trustor.user.id.clone(),
            trustee_user_id: trustee.id.clone(),
            project_id: None,
            impersonation: false,
            expires_at: None,
            remaining_uses: None,
            redelegated_trust_id: None,
            redelegation_count: None,
            roles: Vec::new(),
            extra: None,
        },
    )
    .await?;
    let trust_id = trust.id.clone();

    trust.delete().await?;

    let result = show_trust(&tc, &trust_id).await;
    assert!(result.is_err(), "trust must be gone after deletion");

    trustee.delete().await?;
    trustor.cleanup().await?;
    Ok(())
}
