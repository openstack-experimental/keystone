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
//! # Keystone configuration
//!
//! Parsing of the Keystone configuration file implementation.
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use url::Url;

/// WebauthN configuration.
#[derive(Clone, Debug, Deserialize)]
pub struct WebauthnSection {
    /// Driver.
    #[serde(default = "default_raft")]
    pub driver: String,
    /// Enable WebauthN support.
    #[serde(default)]
    pub enabled: bool,
    /// Secret HMAC key used to derive deterministic decoy credential IDs for
    /// authentication start requests naming users that do not exist or have
    /// no registered passkeys. This hides whether an account exists (user
    /// enumeration prevention). Any sufficiently random string (16+
    /// characters) is suitable. The key must stay stable across restarts and
    /// be identical on all nodes of a deployment; otherwise decoy credential
    /// IDs change between requests, which lets a caller distinguish decoys
    /// from real credentials. When unset, a random per-process key is
    /// generated at startup (adequate only for single-node deployments).
    #[serde(default)]
    pub fake_credential_hmac_key: Option<SecretString>,
    /// The relying party configuration for the WebauthN.
    #[serde(default, flatten)]
    pub relying_party: Option<RelyingParty>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RelyingParty {
    /// The relying party ID. `relying_party_id` is what Credentials
    /// (Authenticators) bind themselves to - `relying_party_id` can NOT be
    /// changed without breaking all of users' associated credentials in the
    /// future! `relying_party_id` must be an effective domain of
    /// `relying_party_origin`. This means that if you are hosting `https://idm.example.com`,
    /// `relying_party_id` must be `idm.example.com`, `example.com`
    /// or `com`.
    #[serde(rename = "relying_party_id")]
    pub id: String,

    /// The relying party name. This may be shown to the user.
    #[serde(default, rename = "relying_party_name")]
    pub name: Option<String>,

    /// The relying party origin url. It must contain the scheme (i.e. `http://localhost`.
    #[serde(rename = "relying_party_origin")]
    pub origin: Url,
}

impl Default for WebauthnSection {
    fn default() -> Self {
        Self {
            driver: default_raft(),
            enabled: false,
            fake_credential_hmac_key: None,
            relying_party: None,
        }
    }
}

fn default_raft() -> String {
    "raft".to_string()
}
