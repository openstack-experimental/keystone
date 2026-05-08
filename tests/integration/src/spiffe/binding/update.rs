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
//! Test k8s auth config.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::spiffe::SpiffeApi;
use openstack_keystone_core_types::spiffe::*;

use super::create_binding;
use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_update() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;

    let authz = vec![SpiffeAuthorization::Project {
        project_id: "pid".into(),
        role_ids: Some(vec!["r1".into()]),
    }];
    let sot = SpiffeBindingCreate {
        authorizations: Some(authz),
        domain_id: domain.id.clone(),
        svid: "spiffe://example.com/foo".into(),
        is_system: false,
        user_id: Some("uid".into()),
    };
    let binding = create_binding(&state, sot.clone()).await?;

    let authz2 = vec![SpiffeAuthorization::Project {
        project_id: "pid2".into(),
        role_ids: Some(vec!["r2".into()]),
    }];
    let req = SpiffeBindingUpdate {
        authorizations: Some(authz2.clone()),
    };
    let res = state
        .provider
        .get_spiffe_provider()
        .update_binding(&state, &binding.svid, req)
        .await?;
    assert_eq!(sot.svid, res.svid);
    assert_eq!(authz2, res.authorizations.unwrap());
    assert_eq!(sot.domain_id, res.domain_id);
    assert_eq!(sot.is_system, res.is_system);
    assert_eq!(sot.user_id, res.user_id);

    Ok(())
}
