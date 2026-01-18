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

use eyre::Result;
use tracing_test::traced_test;
use url::Url;
use uuid::Uuid;

use webauthn_authenticator_rs::WebauthnAuthenticator;
use webauthn_authenticator_rs::softtoken::SoftToken;

use openstack_keystone::api::v3::user::types::UserCreate;

use super::*;
use crate::identity::user::*;

#[tokio::test]
#[traced_test]
async fn test_register_auth() -> Result<()> {
    let mut test_client = TestClient::default()?;
    test_client.auth_admin().await?;

    let user_create = UserCreate {
        name: Uuid::new_v4().to_string(),
        domain_id: "default".into(),
        ..Default::default()
    };
    let user = create_user(&test_client, user_create).await?;

    let authenticator_backend = SoftToken::new(true)?.0;
    let mut authenticator = WebauthnAuthenticator::new(authenticator_backend);
    let origin = Url::parse("http://localhost:8080")?;

    register_user_passkey(
        &test_client,
        &user.id,
        origin.clone(),
        &mut authenticator,
        Some("softkey"),
    )
    .await?;

    let _new_auth = test_client
        .auth_passkey(&user.id, origin.clone(), &mut authenticator)
        .await?;

    Ok(())
}
