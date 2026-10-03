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
//! Test the enforcement model discovery.

use eyre::Result;
use tracing_test::traced_test;

use openstack_keystone_config::LimitEnforcementModel;

use super::exec;
use crate::common::{get_state, get_state_with_config};

#[traced_test]
#[tokio::test]
async fn test_flat() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let model = state
        .provider
        .get_limit_provider()
        .get_limit_model(&exec(&state))
        .await?;
    assert_eq!("flat", model.name);
    assert!(!model.description.is_empty());
    Ok(())
}

#[traced_test]
#[tokio::test]
async fn test_strict_two_level() -> Result<()> {
    let (state, _tmp) = get_state_with_config(|cfg| {
        cfg.limit.enforcement_model = LimitEnforcementModel::StrictTwoLevel;
    })
    .await?;
    let model = state
        .provider
        .get_limit_provider()
        .get_limit_model(&exec(&state))
        .await?;
    assert_eq!("strict_two_level", model.name);
    Ok(())
}
