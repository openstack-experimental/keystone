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
//! Test get group functionality.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;

use crate::common::get_state;
use crate::{create_domain, create_group};

#[tokio::test]
#[traced_test]
async fn test_get() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let group = create_group!(state, domain.id.clone())?;

    let fetched = state
        .provider
        .get_identity_provider()
        .get_group(&ExecutionContext::internal(&state), &group.id)
        .await?
        .expect("group found");
    assert_eq!(fetched.id, group.id);
    assert_eq!(fetched.name, group.name);
    assert_eq!(fetched.domain_id, group.domain_id);
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_get_not_found() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let result = state
        .provider
        .get_identity_provider()
        .get_group(&ExecutionContext::internal(&state), "missing")
        .await?;
    assert!(result.is_none(), "a missing group returns None");
    Ok(())
}
