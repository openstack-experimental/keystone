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
//! # Token provider.
//!
//! A Keystone token is an alpha-numeric text string that enables access to
//! OpenStack APIs and resources. A token may be revoked at any time and is
//! valid for a finite duration. OpenStack Identity is an integration service
//! that does not aspire to be a full-fledged identity store and management
//! solution.

pub use openstack_keystone_core_types::token::*;

pub mod backend;
pub mod error;
pub mod hook;
#[cfg(any(test, feature = "mock"))]
mod provider_api;
pub mod service;

pub use error::TokenProviderError;
pub use hook::TokenHook;
#[cfg(any(test, feature = "mock"))]
pub use crate::mocks::MockTokenProvider;
pub use provider_api::TokenApi;
pub use service::TokenService;

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    use openstack_keystone_config::Config;

    pub(super) fn setup_config() -> Config {
        let keys_dir = tempdir().unwrap();
        // write fernet key used to generate tokens in python
        let file_path = keys_dir.path().join("0");
        let mut tmp_file = File::create(file_path).unwrap();
        write!(tmp_file, "BFTs1CIVIBLTP4GOrQ26VETrJ7Zwz1O4wbEcCQ966eM=").unwrap();

        let builder = config::Config::builder()
            .set_override(
                "auth.methods",
                "password,token,openid,application_credential",
            )
            .unwrap()
            .set_override("database.connection", "dummy")
            .unwrap();
        let mut config: Config = Config::try_from(builder).expect("can build a valid config");
        config.fernet_tokens.key_repository = keys_dir.keep();
        config
    }
}
