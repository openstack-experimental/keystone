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

use derive_builder::Builder;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::BuilderError;

#[derive(Builder, Clone, Debug, Default, Deserialize, Eq, Hash, Serialize, PartialEq)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct Group {
    /// The description of the group.
    pub description: Option<String>,
    /// The ID of the domain.
    pub domain_id: String,
    /// Additional user properties
    #[builder(default)]
    pub extra: Option<Value>,
    /// The ID of the group.
    pub id: String,
    /// The user name. Must be unique within the owning domain.
    pub name: String,
}

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct GroupListParameters {
    /// Filter groups by the domain
    pub domain_id: Option<String>,
    /// Filter groups by the name attribute
    pub name: Option<String>,
}

#[derive(Builder, Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct GroupCreate {
    /// The description of the group.
    pub description: Option<String>,
    /// The ID of the domain.
    pub domain_id: String,
    /// Additional user properties
    #[builder(default)]
    pub extra: Option<Value>,
    /// The ID of the group.
    pub id: Option<String>,
    /// The user name. Must be unique within the owning domain.
    pub name: String,
}
