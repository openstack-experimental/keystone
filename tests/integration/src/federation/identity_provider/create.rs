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
//! Test identity provider creation.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::federation::IdentityProviderCreate;

use crate::common::get_state;
use crate::create_domain;
use crate::federation::create_identity_provider;

/// Every identity provider creation also upserts a shared, table-global
/// `mapping` row (id `dummy`) used by the legacy v3 federation protocol
/// entries, via `INSERT ... ON CONFLICT (id) DO NOTHING`. The row is
/// created by the first identity provider and every subsequent one must
/// hit -- and tolerate -- that conflict instead of surfacing it as a
/// creation failure.
///
/// Regression test for a bug where `on_conflict(..).do_nothing_on(..)`
/// combined with sea-orm's `RETURNING`-based insert path turned "no rows
/// returned because of the conflict" into a hard `DbErr::RecordNotInserted`,
/// making every identity provider creation after the first one fail with a
/// 500. Fixed by using `on_conflict_do_nothing_on`, whose `TryInsert::exec`
/// maps that outcome to `TryInsertResult::Conflicted` instead of an error.
#[traced_test]
#[tokio::test]
async fn test_create_second_identity_provider_does_not_fail_on_shared_legacy_row() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    let first = create_identity_provider(
        &state,
        IdentityProviderCreate {
            name: uuid::Uuid::new_v4().simple().to_string(),
            domain_id: Some(domain.id.clone()),
            ..Default::default()
        },
    )
    .await?;
    assert!(!first.id.is_empty());

    // This is the call that used to 500 once the "dummy" mapping row
    // already existed from the first creation above.
    let second = create_identity_provider(
        &state,
        IdentityProviderCreate {
            name: uuid::Uuid::new_v4().simple().to_string(),
            domain_id: Some(domain.id.clone()),
            ..Default::default()
        },
    )
    .await?;
    assert!(!second.id.is_empty());
    assert_ne!(first.id, second.id);

    Ok(())
}

/// Supplied fields are stored and readable back; an explicit id is honoured
/// and cannot be reused.
#[traced_test]
#[tokio::test]
async fn test_create_persists_fields() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let fed = state.provider.get_federation_provider();
    let ctx = ExecutionContext::internal(&state);
    let id = uuid::Uuid::new_v4().simple().to_string();
    let issuer = format!("https://{id}.example.com");

    let created = create_identity_provider(
        &state,
        IdentityProviderCreate {
            id: Some(id.clone()),
            name: id.clone(),
            domain_id: Some(domain.id.clone()),
            enabled: true,
            bound_issuer: Some(issuer.clone()),
            oidc_client_id: Some("client".into()),
            oidc_scopes: Some(vec!["openid".into(), "email".into()]),
            ..Default::default()
        },
    )
    .await?;
    assert_eq!(id, created.id);

    let got = fed
        .get_identity_provider(&ctx, &id)
        .await?
        .ok_or_else(|| eyre::eyre!("idp missing"))?;
    assert_eq!(id, got.name);
    assert_eq!(Some(domain.id.clone()), got.domain_id);
    assert!(got.enabled);
    assert_eq!(Some(issuer), got.bound_issuer);
    assert_eq!(Some("client".to_string()), got.oidc_client_id);
    assert_eq!(
        Some(vec!["openid".to_string(), "email".to_string()]),
        got.oidc_scopes
    );

    let dup = fed
        .create_identity_provider(
            &ctx,
            IdentityProviderCreate {
                id: Some(id.clone()),
                name: uuid::Uuid::new_v4().simple().to_string(),
                ..Default::default()
            },
        )
        .await;
    assert!(dup.is_err(), "{dup:?}");
    Ok(())
}
