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

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_delete() -> Result<()> {
    let (state, _) = get_state().await?;
    let domain = create_domain!(state)?;
    let sot = SpiffeBindingCreate {
        authorizations: None,
        domain_id: domain.id.clone(),
        svid: "spiffe://example.com/foo".into(),
        is_system: false,
        user_id: Some("uid".into()),
    };
    let res = state
        .provider
        .get_spiffe_provider()
        .create_binding(&state, sot.clone())
        .await?;

    state
        .provider
        .get_spiffe_provider()
        .delete_binding(&state, &res.svid)
        .await?;
    Ok(())
}
