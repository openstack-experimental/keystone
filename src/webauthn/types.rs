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

//! # WebAuthN Extension types

use derive_builder::Builder;
use serde::{Deserialize, Serialize};

mod provider;

pub use provider::WebauthnApi;

/// WebAuthN credential of a user.
#[derive(Builder, Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[builder(setter(strip_option, into))]
pub struct WebauthnCredential {
    /// The ID of the credential.
    pub credential_id: String,
    /// The description of the credential.
    pub description: Option<String>,
}
