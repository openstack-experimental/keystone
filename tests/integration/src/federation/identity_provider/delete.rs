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
//! Test identity provider deletion.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core::federation::FederationProviderError;

use super::idp;
use crate::common::get_state;
use crate::create_domain;
use crate::federation::create_identity_provider;

/// Delete removes the identity provider; second delete is not found.
#[traced_test]
#[tokio::test]
async fn test_delete() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let fed = state.provider.get_federation_provider();
    let ctx = ExecutionContext::internal(&state);

    let created = create_identity_provider(&state, idp(Some(&domain.id), None, true)).await?;
    fed.delete_identity_provider(&ctx, &created.id).await?;
    assert!(
        fed.get_identity_provider(&ctx, &created.id)
            .await?
            .is_none()
    );

    let res = fed.delete_identity_provider(&ctx, &created.id).await;
    assert!(
        matches!(
            res,
            Err(FederationProviderError::IdentityProviderNotFound(_))
        ),
        "{res:?}"
    );
    Ok(())
}
