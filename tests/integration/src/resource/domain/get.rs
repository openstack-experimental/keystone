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
//! Test domain get.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone::resource::ResourceApi;

use crate::common::get_state;
use crate::create_domain;

#[traced_test]
#[tokio::test]
async fn test_get_domain() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    let res = state
        .provider
        .get_resource_provider()
        .get_domain(&state, &domain.id)
        .await?
        .expect("domain should be there");
    assert_eq!(res.id, domain.id);
    assert_eq!(res.name, domain.name);
    assert_eq!(res.enabled, domain.enabled);
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_get_domain_missing() -> Result<()> {
    let (state, _tmp) = get_state().await?;

    assert!(
        state
            .provider
            .get_resource_provider()
            .get_domain(&state, &uuid::Uuid::new_v4().to_string())
            .await?
            .is_none()
    );
    Ok(())
}
