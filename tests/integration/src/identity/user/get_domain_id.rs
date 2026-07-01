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
//! Test get_user_domain_id functionality.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone::identity::IdentityApi;

use crate::common::get_state;
use crate::{create_domain, create_user};

#[tokio::test]
#[traced_test]
async fn test_get_user_domain_id() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;
    let user = create_user!(state, domain.id.clone())?;

    let domain_id = state
        .provider
        .get_identity_provider()
        .get_user_domain_id(&state, &user.id)
        .await?;
    assert_eq!(domain_id, domain.id, "domain id matches the user's domain");
    Ok(())
}
