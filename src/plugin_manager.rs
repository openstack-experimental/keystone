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
//! # Plugin manager
//!
//! A driver, also known as a backend, is an important architectural component
//! of Keystone. It is an abstraction around the data access needed by a
//! particular subsystem. This pluggable implementation is not only how Keystone
//! implements its own data access, but how you can implement your own!
//!
//! The [PluginManager] is responsible for picking the proper backend driver for
//! the provider.
use std::collections::HashMap;

use crate::application_credential::backend::ApplicationCredentialBackend;
use crate::assignment::backend::AssignmentBackend;
use crate::catalog::backends::CatalogBackend;
use crate::federation::backend::FederationBackend;
use crate::identity::backends::IdentityBackend;
use crate::resource::types::ResourceBackend;
use crate::revoke::backend::RevokeBackend;

/// Plugin manager allowing to pass custom backend plugins implementing required
/// trait during the service start.
#[derive(Clone, Debug, Default)]
pub struct PluginManager {
    /// Application credentials backend plugin.
    application_credential_backends: HashMap<String, Box<dyn ApplicationCredentialBackend>>,
    /// Assignments backend plugin.
    assignment_backends: HashMap<String, Box<dyn AssignmentBackend>>,
    /// Catalog backend plugins.
    catalog_backends: HashMap<String, Box<dyn CatalogBackend>>,
    /// Federation backend plugins.
    federation_backends: HashMap<String, Box<dyn FederationBackend>>,
    /// Identity backend plugins.
    identity_backends: HashMap<String, Box<dyn IdentityBackend>>,
    /// Resource backend plugins.
    resource_backends: HashMap<String, Box<dyn ResourceBackend>>,
    /// Revoke backend plugins.
    revoke_backends: HashMap<String, Box<dyn RevokeBackend>>,
}

impl PluginManager {
    /// Register identity backend.
    pub fn register_identity_backend<S: AsRef<str>>(
        &mut self,
        name: S,
        plugin: Box<dyn IdentityBackend>,
    ) {
        self.identity_backends
            .insert(name.as_ref().to_string(), plugin);
    }

    /// Get registered application credential backend.
    #[allow(clippy::borrowed_box)]
    pub fn get_application_credential_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Option<&Box<dyn ApplicationCredentialBackend>> {
        self.application_credential_backends.get(name.as_ref())
    }

    /// Get registered assignment backend.
    #[allow(clippy::borrowed_box)]
    pub fn get_assignment_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Option<&Box<dyn AssignmentBackend>> {
        self.assignment_backends.get(name.as_ref())
    }

    /// Get registered catalog backend.
    #[allow(clippy::borrowed_box)]
    pub fn get_catalog_backend<S: AsRef<str>>(&self, name: S) -> Option<&Box<dyn CatalogBackend>> {
        self.catalog_backends.get(name.as_ref())
    }

    /// Get registered federation backend.
    #[allow(clippy::borrowed_box)]
    pub fn get_federation_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Option<&Box<dyn FederationBackend>> {
        self.federation_backends.get(name.as_ref())
    }

    /// Get registered identity backend.
    #[allow(clippy::borrowed_box)]
    pub fn get_identity_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Option<&Box<dyn IdentityBackend>> {
        self.identity_backends.get(name.as_ref())
    }

    /// Get registered resource backend.
    #[allow(clippy::borrowed_box)]
    pub fn get_resource_backend<S: AsRef<str>>(
        &self,
        name: S,
    ) -> Option<&Box<dyn ResourceBackend>> {
        self.resource_backends.get(name.as_ref())
    }

    /// Get registered revoke backend.
    #[allow(clippy::borrowed_box)]
    pub fn get_revoke_backend<S: AsRef<str>>(&self, name: S) -> Option<&Box<dyn RevokeBackend>> {
        self.revoke_backends.get(name.as_ref())
    }
}
