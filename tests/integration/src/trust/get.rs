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
//! Test fetching a single trust.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::trust::TrustCreateBuilder;

use crate::common::get_state;
use crate::create_domain;
use crate::create_user;
use crate::trust::create_trust;

#[traced_test]
#[tokio::test]
async fn test_get() -> Result<()> {
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

    let fetched = state
        .provider
        .get_trust_provider()
        .get_trust(&ExecutionContext::internal(&state), &trust.id)
        .await?;

    assert!(fetched.is_some());
    let fetched = fetched.unwrap();
    assert_eq!(fetched.id, trust.id);
    assert_eq!(fetched.trustor_user_id, trustor.id);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_not_found() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let fetched = state
        .provider
        .get_trust_provider()
        .get_trust(&ExecutionContext::internal(&state), "does-not-exist")
        .await?;
    assert!(fetched.is_none());
    Ok(())
}
