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

use crate::error::BuilderError;

/// K8s authentication request.
///
/// Identity and authorization are resolved by the unified mapping engine.
#[derive(Builder, Clone, Debug)]
#[builder(build_fn(error = "BuilderError"))]
#[builder(setter(strip_option, into))]
pub struct K8sAuthRequest {
    /// An ID of the auth provider.
    pub auth_instance_id: String,

    pub jwt: SecretString,

    /// Optional rule name hint for the mapping-engine path. When set, the
    /// mapping engine evaluates the named rule first; if it matches,
    /// authentication succeeds immediately. If the rule does not match,
    /// standard first-match-wins iteration proceeds.
    pub rule_name: Option<String>,
}
