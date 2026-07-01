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
//! Test create group functionality.

use eyre::Result;
use tracing_test::traced_test;

use crate::common::get_state;
use crate::{create_domain, create_group};

#[tokio::test]
#[traced_test]
async fn test_create() -> Result<()> {
    let (state, _tmp) = get_state().await?;
    let domain = create_domain!(state)?;

    let group = create_group!(state, domain.id.clone())?;

    assert!(!group.id.is_empty(), "an id was generated");
    assert!(!group.name.is_empty());
    assert_eq!(group.domain_id, domain.id);
    Ok(())
}
