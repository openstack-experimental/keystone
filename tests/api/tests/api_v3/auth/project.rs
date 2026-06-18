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

use std::sync::Arc;

use eyre::Result;

use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::auth::project::*;

#[tokio::test]
async fn test_list_user_projects() -> Result<()> {
    let test_client = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let projects = list_auth_projects(&test_client).await?;
    assert!(!projects.is_empty());
    Ok(())
}
