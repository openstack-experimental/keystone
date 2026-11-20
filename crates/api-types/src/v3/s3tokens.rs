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
//! `POST /v3/s3tokens` wire types (ADR 0019 §5).

use serde::{Deserialize, Serialize};

/// The `credentials` object of an S3 token validation request: the S3
/// string-to-sign plus the client signature over it.
#[derive(Clone, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct S3SignatureCredentials {
    /// The EC2 access key identifying the credential record.
    #[serde(default)]
    pub access: Option<String>,

    /// The client-computed signature to verify.
    #[serde(default)]
    pub signature: Option<String>,

    /// URL-safe base64 of the S3 string-to-sign.
    #[serde(default)]
    pub token: Option<String>,
}

// The signature is never printed.
impl std::fmt::Debug for S3SignatureCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3SignatureCredentials")
            .field("access", &self.access)
            .finish_non_exhaustive()
    }
}

/// `POST /v3/s3tokens` request body. Python Keystone accepts the object under
/// `credentials`, `credential` or `ec2Credentials`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct S3TokenAuthRequest {
    /// The signed request description.
    #[serde(alias = "credential", alias = "ec2Credentials")]
    pub credentials: S3SignatureCredentials,
}
