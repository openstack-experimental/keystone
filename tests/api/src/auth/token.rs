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

use axum::http::HeaderValue;
use eyre::Result;
use secrecy::{ExposeSecret, SecretString};

mod password;
mod revoke;
mod token;
mod validate;

use crate::common::*;

/// Perform token check request.
pub async fn check_token(
    tc: &TestClient,
    subject_token: &SecretString,
) -> Result<reqwest::Response> {
    let mut hdr = HeaderValue::from_str(subject_token.expose_secret())?;
    hdr.set_sensitive(true);
    Ok(tc
        .client
        .get(tc.base_url.join("v3/auth/tokens")?)
        .header("x-subject-token", hdr)
        .send()
        .await?)
}
