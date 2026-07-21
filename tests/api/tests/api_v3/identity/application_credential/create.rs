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
use crate::api_v3::identity::application_credential::list::get_project_scoped_client;
use eyre::Result;
use openstack_keystone_api_types::v3::application_credential::application_credential::*;
use secrecy::ExposeSecret;
use test_api::guard::ResourceGuard;
use test_api::identity::application_credential::create_application_credential;
use tracing_test::traced_test;

#[tokio::test]
#[traced_test]
async fn test_create() -> Result<()> {
    let tc = get_project_scoped_client().await?;
    let user_id = tc
        .get_auth_info()
        .ok_or_else(|| eyre::eyre!("no auth info available"))?
        .token
        .user
        .id;

    let cred = create_application_credential(
        &tc,
        &user_id,
        ApplicationCredentialCreateBuilder::default()
            .name("test-cred")
            .roles(vec![])
            .build()?,
    )
    .await?;

    assert_eq!(cred.name, "test-cred");
    assert!(!cred.secret.expose_secret().is_empty());
    assert_eq!(cred.user_id, user_id);

    cred.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_create_with_description() -> Result<()> {
    let tc = get_project_scoped_client().await?;
    let user_id = tc
        .get_auth_info()
        .ok_or_else(|| eyre::eyre!("no auth info available"))?
        .token
        .user
        .id;

    let cred = create_application_credential(
        &tc,
        &user_id,
        ApplicationCredentialCreateBuilder::default()
            .name("test-cred")
            .description("my description")
            .roles(vec![])
            .build()?,
    )
    .await?;

    assert_eq!(cred.description, Some("my description".to_string()));

    cred.delete().await?;
    Ok(())
}
