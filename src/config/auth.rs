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
use serde::Deserialize;

use crate::config::common::csv;

/// Authentication configuration.
#[derive(Debug, Default, Deserialize, Clone)]
pub struct AuthProvider {
    /// Authentication methods to be enabled and used for token validation.
    #[serde(deserialize_with = "csv")]
    pub methods: Vec<String>,
}
