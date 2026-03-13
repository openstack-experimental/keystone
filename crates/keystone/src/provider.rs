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
//! # Provider manager
//!
//! Provider manager provides access to the individual service providers. This
//! gives an easy interact for passing overall manager down to the individual
//! providers that might need to call other providers while also allowing an
//! easy injection of mocked providers.
use std::sync::Arc;

use crate::plugin_manager::PluginManager;

pub use openstack_keystone_core::provider::*;

/// Register default drivers.
pub fn register_default_backend_plugins(plugin_manager: &mut PluginManager) {
    plugin_manager.register_application_credential_backend(
        "sql",
        Arc::new(crate::application_credential::backend::SqlBackend::default()),
    );
    plugin_manager.register_assignment_backend(
        "sql",
        Arc::new(crate::assignment::backend::SqlBackend::default()),
    );
    plugin_manager.register_catalog_backend(
        "sql",
        Arc::new(crate::catalog::backend::sql::SqlBackend::default()),
    );
    plugin_manager.register_federation_backend(
        "sql",
        Arc::new(crate::federation::backend::SqlBackend::default()),
    );
    plugin_manager.register_identity_backend(
        "sql",
        Arc::new(crate::identity::backend::sql::SqlBackend::default()),
    );
    plugin_manager.register_identity_mapping_backend(
        "sql",
        Arc::new(crate::identity_mapping::backend::sql::SqlBackend::default()),
    );
    plugin_manager.register_k8s_auth_backend(
        "sql",
        Arc::new(crate::k8s_auth::backend::sql::SqlBackend::default()),
    );
    plugin_manager.register_resource_backend(
        "sql",
        Arc::new(crate::resource::backend::sql::SqlBackend::default()),
    );
    plugin_manager.register_revoke_backend(
        "sql",
        Arc::new(crate::revoke::backend::sql::SqlBackend::default()),
    );
    plugin_manager.register_role_backend(
        "sql",
        Arc::new(crate::role::backend::sql::SqlBackend::default()),
    );
    plugin_manager.register_token_restriction_backend(
        "sql",
        Arc::new(crate::token::token_restriction::SqlBackend::default()),
    );
    plugin_manager.register_trust_backend(
        "sql",
        Arc::new(crate::trust::backend::sql::SqlBackend::default()),
    );
}
