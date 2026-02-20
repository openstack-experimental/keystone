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
use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use validator::Validate;

use crate::webauthn::WebauthnError;

/// User Entity.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize, ToSchema, Validate)]
#[schema(as = PasskeyUser)]
pub struct User {
    /// The user's id in base64 form. This MUST be a unique id, and must NOT
    /// contain personally identifying information, as this value can NEVER
    /// be changed. If in doubt, use a UUID.
    #[schema(value_type = String, format = Binary, content_encoding = "base64")]
    pub id: String,
    /// A detailed name for the account, such as an email address. This value
    /// can change, so must not be used as a primary key.
    #[validate(length(max = 255))]
    pub name: String,
    /// The user's preferred name for display. This value can change, so must
    /// not be used as a primary key.
    #[validate(length(max = 255))]
    pub display_name: String,
}

impl TryFrom<User> for webauthn_rs_proto::options::User {
    type Error = WebauthnError;
    fn try_from(value: User) -> Result<Self, Self::Error> {
        Ok(webauthn_rs_proto::options::User {
            id: URL_SAFE.decode(value.id)?.into(),
            name: value.name,
            display_name: value.display_name,
        })
    }
}

impl From<webauthn_rs_proto::options::User> for User {
    fn from(value: webauthn_rs_proto::options::User) -> Self {
        Self {
            id: URL_SAFE.encode(&value.id),
            name: value.name,
            display_name: value.display_name,
        }
    }
}
