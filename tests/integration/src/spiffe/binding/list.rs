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
//! Test SPIFFE bindings.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::spiffe::SpiffeApi;
use openstack_keystone_core_types::spiffe::*;

use super::create_binding;

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_list() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain2 = create_domain!(state)?;

    let binding1 = create_binding(
        &state,
        SpiffeBindingCreate {
            authorizations: None,
            domain_id: domain.id.clone(),
            svid: "spiffe://example.com/foo".into(),
            is_system: false,
            user_id: None,
        },
    )
    .await?;
    let binding2 = create_binding(
        &state,
        SpiffeBindingCreate {
            authorizations: None,
            domain_id: domain.id.clone(),
            svid: "spiffe://example.com/bar".into(),
            is_system: false,
            user_id: None,
        },
    )
    .await?;
    let binding3 = create_binding(
        &state,
        SpiffeBindingCreate {
            authorizations: None,
            domain_id: domain2.id.clone(),
            svid: "spiffe://example.com/baz".into(),
            is_system: false,
            user_id: None,
        },
    )
    .await?;

    let res = state
        .provider
        .get_spiffe_provider()
        .list_bindings(&state, &SpiffeBindingListParameters::default())
        .await?;
    assert!(res.contains(&binding1));
    assert!(res.contains(&binding2));
    assert!(res.contains(&binding3));
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_list_domain() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let domain2 = create_domain!(state)?;

    let binding1 = create_binding(
        &state,
        SpiffeBindingCreate {
            authorizations: None,
            domain_id: domain.id.clone(),
            svid: "spiffe://example.com/foo".into(),
            is_system: false,
            user_id: None,
        },
    )
    .await?;
    let binding2 = create_binding(
        &state,
        SpiffeBindingCreate {
            authorizations: None,
            domain_id: domain.id.clone(),
            svid: "spiffe://example.com/bar".into(),
            is_system: false,
            user_id: None,
        },
    )
    .await?;
    let binding3 = create_binding(
        &state,
        SpiffeBindingCreate {
            authorizations: None,
            domain_id: domain2.id.clone(),
            svid: "spiffe://example.com/baz".into(),
            is_system: false,
            user_id: None,
        },
    )
    .await?;

    let res = state
        .provider
        .get_spiffe_provider()
        .list_bindings(
            &state,
            &SpiffeBindingListParameters {
                domain_id: Some(domain.id.clone()),
                ..Default::default()
            },
        )
        .await?;
    assert!(res.contains(&binding1));
    assert!(res.contains(&binding2));
    assert!(!res.contains(&binding3));
    let res = state
        .provider
        .get_spiffe_provider()
        .list_bindings(
            &state,
            &SpiffeBindingListParameters {
                domain_id: Some("missing".into()),
                ..Default::default()
            },
        )
        .await?;
    assert!(!res.contains(&binding1));
    assert!(!res.contains(&binding2));
    assert!(!res.contains(&binding3));
    Ok(())
}
