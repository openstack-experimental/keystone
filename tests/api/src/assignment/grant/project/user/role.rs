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

mod check;
mod grant;

use eyre::Result;
use reqwest::StatusCode;

use crate::common::*;

pub async fn check_grant<
    P: AsRef<str> + std::fmt::Display,
    U: AsRef<str> + std::fmt::Display,
    R: AsRef<str> + std::fmt::Display,
>(
    tc: &TestClient,
    project_id: P,
    user_id: U,
    role_id: R,
) -> Result<bool> {
    let rsp = tc
        .client
        .head(tc.base_url.join(&format!(
            "v3/projects/{}/users/{}/roles/{}",
            project_id, user_id, role_id
        ))?)
        .send()
        .await?;
    Ok(rsp.status() == StatusCode::NO_CONTENT)
}

pub async fn add_project_grant<
    P: AsRef<str> + std::fmt::Display,
    U: AsRef<str> + std::fmt::Display,
    R: AsRef<str> + std::fmt::Display,
>(
    tc: &TestClient,
    project_id: P,
    user_id: U,
    role_id: R,
) -> Result<()> {
    let rsp = tc
        .client
        .put(tc.base_url.join(&format!(
            "v3/projects/{}/users/{}/roles/{}",
            project_id, user_id, role_id
        ))?)
        .send()
        .await?;
    assert_eq!(rsp.status(), StatusCode::NO_CONTENT);
    Ok(())
}
