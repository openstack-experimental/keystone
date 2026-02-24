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
//! # K8s Auth configuration types.

use derive_builder::Builder;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::error::BuilderError;

/// K8s authentication request.
#[derive(Builder, Clone, Debug, Deserialize)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct K8sAuthRequest {
    pub configuration_id: String,

    pub jwt: SecretString,

    pub role_name: String,
}

/// K8s JWT claims.
#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct K8sClaims {
    pub(crate) aud: Vec<String>,
    pub(crate) exp: u64,
    pub(crate) sub: String,
}
