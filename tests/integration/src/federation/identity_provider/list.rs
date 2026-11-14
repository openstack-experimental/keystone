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
//! Test identity provider listing.

use std::collections::HashSet;

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::ListPagination;
use openstack_keystone_core_types::federation::IdentityProviderListParameters;

use super::{idp, unique};
use crate::common::get_state;
use crate::create_domain;
use crate::federation::create_identity_provider;

/// List filters: name, bound_issuer, domain_ids (incl. global) and paging.
#[traced_test]
#[tokio::test]
async fn test_list_filters() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let d1 = create_domain!(state)?;
    let d2 = create_domain!(state)?;
    let fed = state.provider.get_federation_provider();
    let ctx = ExecutionContext::internal(&state);
    let issuer = format!("https://{}.example.com", unique());

    let a = create_identity_provider(&state, idp(Some(&d1.id), Some(&issuer), true)).await?;
    let b = create_identity_provider(&state, idp(Some(&d1.id), None, true)).await?;
    let c = create_identity_provider(&state, idp(Some(&d2.id), None, true)).await?;
    let g = create_identity_provider(&state, idp(None, None, true)).await?;

    let ids = |v: Vec<openstack_keystone_core_types::federation::IdentityProvider>| {
        v.into_iter().map(|i| i.id).collect::<HashSet<_>>()
    };
    let list = |p: IdentityProviderListParameters| {
        let fed = &fed;
        let ctx = &ctx;
        async move { fed.list_identity_providers(ctx, &p).await }
    };

    let all = ids(list(IdentityProviderListParameters::default()).await?);
    for i in [&a.id, &b.id, &c.id, &g.id] {
        assert!(all.contains(i));
    }

    let by_name = ids(list(IdentityProviderListParameters {
        name: Some(b.name.clone()),
        ..Default::default()
    })
    .await?);
    assert_eq!(HashSet::from([b.id.clone()]), by_name);

    let by_iss = ids(list(IdentityProviderListParameters {
        bound_issuer: Some(issuer.clone()),
        ..Default::default()
    })
    .await?);
    assert_eq!(HashSet::from([a.id.clone()]), by_iss);

    let by_d1 = ids(list(IdentityProviderListParameters {
        domain_ids: Some(HashSet::from([Some(d1.id.clone())])),
        ..Default::default()
    })
    .await?);
    assert_eq!(HashSet::from([a.id.clone(), b.id.clone()]), by_d1);

    let d2_and_global = ids(list(IdentityProviderListParameters {
        domain_ids: Some(HashSet::from([Some(d2.id.clone()), None])),
        ..Default::default()
    })
    .await?);
    assert_eq!(HashSet::from([c.id.clone(), g.id.clone()]), d2_and_global);

    // The provider contract is "up to limit + 1 rows" (one extra row lets the
    // API layer tell whether another page exists).
    let page = list(IdentityProviderListParameters {
        domain_ids: Some(HashSet::from([Some(d1.id.clone())])),
        pagination: ListPagination {
            limit: Some(1),
            ..Default::default()
        },
        ..Default::default()
    })
    .await?;
    assert_eq!(2, page.len());

    // Marker is exclusive: the page after the first entry holds the rest.
    let first = page[0].id.clone();
    let next = list(IdentityProviderListParameters {
        domain_ids: Some(HashSet::from([Some(d1.id.clone())])),
        pagination: ListPagination {
            limit: Some(10),
            marker: Some(first.clone()),
            ..Default::default()
        },
        ..Default::default()
    })
    .await?;
    assert_eq!(1, next.len());
    assert_ne!(first, next[0].id);

    // Exact boundary: asking for as many rows as exist returns no more.
    let exact = list(IdentityProviderListParameters {
        domain_ids: Some(HashSet::from([Some(d1.id.clone())])),
        pagination: ListPagination {
            limit: Some(2),
            ..Default::default()
        },
        ..Default::default()
    })
    .await?;
    assert_eq!(2, exact.len());

    // Reverse paging: marker is exclusive and rows precede it, ascending.
    let mut d1_ids = vec![a.id.clone(), b.id.clone()];
    d1_ids.sort();
    let prev = list(IdentityProviderListParameters {
        domain_ids: Some(HashSet::from([Some(d1.id.clone())])),
        pagination: ListPagination {
            limit: Some(10),
            marker: Some(d1_ids[1].clone()),
            page_reverse: true,
        },
        ..Default::default()
    })
    .await?;
    assert_eq!(
        vec![d1_ids[0].clone()],
        prev.into_iter().map(|i| i.id).collect::<Vec<_>>()
    );
    Ok(())
}
