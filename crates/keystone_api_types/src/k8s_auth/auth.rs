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
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize, Serializer};
use utoipa::ToSchema;
use validator::Validate;

use crate::error::BuilderError;

/// K8s authentication request.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, ToSchema, Validate)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct K8sAuthRequest {
    //#[validate(length(max = 64))]
    //pub auth_instance_id: String,
    #[schema(value_type = String)]
    #[serde(serialize_with = "serialize_secret_string")]
    pub jwt: SecretString,

    #[validate(length(max = 255))]
    pub role_name: String,
}

fn serialize_secret_string<S>(secret: &SecretString, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(secret.expose_secret())
}
