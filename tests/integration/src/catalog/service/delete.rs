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
//! Test deleting a service.

use std::collections::HashMap;

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_core::auth::ExecutionContext;
use openstack_keystone_core_types::catalog::ServiceCreate;

use crate::common::get_state;

#[traced_test]
#[tokio::test]
async fn test_delete() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let provider = state.provider.get_catalog_provider();

    let service = provider
        .create_service(
            &ExecutionContext::internal(&state),
            ServiceCreate {
                enabled: true,
                extra: HashMap::new(),
                id: Some("del-svc".to_string()),
                r#type: Some("compute".to_string()),
            },
        )
        .await?;

    provider
        .delete_service(&ExecutionContext::internal(&state), &service.id)
        .await?;

    let fetched = provider
        .get_service(&ExecutionContext::internal(&state), &service.id)
        .await?;
    assert!(fetched.is_none(), "service should be gone after delete");
    Ok(())
}
