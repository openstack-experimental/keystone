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
//! Test identity provider retrieval.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;

use super::{idp, unique};
use crate::common::get_state;
use crate::create_domain;
use crate::federation::create_identity_provider;

/// Get returns the created data, and `None` for unknown id.
#[traced_test]
#[tokio::test]
async fn test_get() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let fed = state.provider.get_federation_provider();
    let ctx = ExecutionContext::internal(&state);

    let issuer = format!("https://{}.example.com", unique());
    let created =
        create_identity_provider(&state, idp(Some(&domain.id), Some(&issuer), true)).await?;
    let got = fed
        .get_identity_provider(&ctx, &created.id)
        .await?
        .ok_or_else(|| eyre::eyre!("idp missing"))?;
    assert_eq!(created.id, got.id);
    assert_eq!(created.name, got.name);
    assert_eq!(Some(domain.id.clone()), got.domain_id);
    assert_eq!(Some(issuer.clone()), got.bound_issuer);
    assert!(got.enabled);

    // Global (no domain) IdP is read back with an empty domain.
    let global = create_identity_provider(&state, idp(None, None, false)).await?;
    let got = fed
        .get_identity_provider(&ctx, &global.id)
        .await?
        .ok_or_else(|| eyre::eyre!("global idp missing"))?;
    assert_eq!(None, got.domain_id);
    assert_eq!(None, got.bound_issuer);
    assert!(!got.enabled);

    assert!(fed.get_identity_provider(&ctx, "missing").await?.is_none());
    Ok(())
}
