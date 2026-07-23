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
//! Test listing trusts.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::trust::{TrustCreateBuilder, TrustListParameters};

use crate::common::get_state;
use crate::create_domain;
use crate::create_user;
use crate::trust::create_trust;

#[traced_test]
#[tokio::test]
async fn test_list() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let trustor = create_user!(state, domain.id.clone())?;
    let trustee = create_user!(state, domain.id.clone())?;

    let t1 = create_trust(
        &state,
        TrustCreateBuilder::default()
            .trustor_user_id(trustor.id.clone())
            .trustee_user_id(trustee.id.clone())
            .impersonation(false)
            .build()?,
    )
    .await?;
    let t2 = create_trust(
        &state,
        TrustCreateBuilder::default()
            .trustor_user_id(trustor.id.clone())
            .trustee_user_id(trustee.id.clone())
            .impersonation(false)
            .build()?,
    )
    .await?;

    let trusts = state
        .provider
        .get_trust_provider()
        .list_trusts(
            &ExecutionContext::internal(&state),
            &TrustListParameters::default(),
        )
        .await?;

    let ids: Vec<&str> = trusts.iter().map(|t| t.id.as_str()).collect();
    assert!(ids.contains(&t1.id.as_str()));
    assert!(ids.contains(&t2.id.as_str()));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_excludes_deleted_by_default() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let trustor = create_user!(state, domain.id.clone())?;
    let trustee = create_user!(state, domain.id.clone())?;

    let trust = create_trust(
        &state,
        TrustCreateBuilder::default()
            .trustor_user_id(trustor.id.clone())
            .trustee_user_id(trustee.id.clone())
            .impersonation(false)
            .build()?,
    )
    .await?;
    let trust_id = trust.id.clone();
    trust.cleanup().await;

    let trusts = state
        .provider
        .get_trust_provider()
        .list_trusts(
            &ExecutionContext::internal(&state),
            &TrustListParameters::default(),
        )
        .await?;
    assert!(!trusts.iter().any(|t| t.id == trust_id));

    let trusts_with_deleted = state
        .provider
        .get_trust_provider()
        .list_trusts(
            &ExecutionContext::internal(&state),
            &TrustListParameters {
                include_deleted: Some(true),
                ..Default::default()
            },
        )
        .await?;
    assert!(trusts_with_deleted.iter().any(|t| t.id == trust_id));
    Ok(())
}
