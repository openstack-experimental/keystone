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

//! The token format must match the provider the live server was started
//! with (`KEYSTONE_TEST_TOKEN_PROVIDER`, consumed by `tools/start-api.sh`,
//! default `fernet`). The whole live suite runs against either provider, so
//! this pins down which one it actually exercised.

use std::env;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use eyre::{OptionExt, Result, bail};
use secrecy::ExposeSecret;
use serde_json::Value;

use openstack_keystone_api_types::v3::auth::token::*;

use test_api::auth::token::check_token;
use test_api::common::*;

#[tokio::test]
async fn test_token_format_matches_provider() -> Result<()> {
    let mut client = TestClient::new()?;
    client.auth_admin().await?;
    let token = client
        .token
        .as_ref()
        .ok_or_eyre("the admin client must be authenticated")?
        .expose_secret()
        .to_string();

    match env::var("KEYSTONE_TEST_TOKEN_PROVIDER")
        .unwrap_or_else(|_| "fernet".into())
        .as_str()
    {
        "fernet" => {
            assert!(
                !token.contains('.'),
                "fernet token must not be a JWS compact serialization"
            );
        }
        "jws" => {
            let mut parts = token.split('.');
            let header = parts.next().ok_or_eyre("JWS token has no header")?;
            if parts.count() != 2 {
                bail!("JWS token must have exactly three segments");
            }
            let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header)?)?;
            assert_eq!(header["alg"], "ES256", "unexpected JWS header: {header}");
        }
        other => bail!("unsupported KEYSTONE_TEST_TOKEN_PROVIDER: {other}"),
    }

    // Whatever the format, the token must validate against the same server.
    let rsp: TokenResponse = check_token(&client, client.token.as_ref().ok_or_eyre("no token")?)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(rsp.token.user.name.as_deref(), Some("admin"));
    Ok(())
}
