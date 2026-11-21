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
//! # Projection caches of the identity driver
//!
//! Only non-secret, rarely changing projections of a user are cached, and only
//! for readers that state a [`Freshness`](openstack_keystone_core_types::freshness::Freshness)
//! tolerance:
//!
//! | Projection | Depends on | Notes |
//! |---|---|---|
//! | user options | `user_option` | `ignore_password_expiry`, `ignore_user_inactivity`, MFA rules |
//! | password expiry | `password` | the expiry of the latest password only |
//!
//! Never cached: the `user` row (`enabled`, `last_active_at`), the local
//! user authentication counters and every secret, in particular the
//! password hash. Authentication reads them straight from the database.

use openstack_keystone_core::projection_cache::ProjectionCache;
use openstack_keystone_core_types::identity::UserOptions;

use crate::password::PasswordExpiry;

/// Tables the user options depend on.
pub const OPTION_TABLES: &[&str] = &["user_option"];

/// Tables the password expiry depends on.
///
/// Not `local_user`: it is rewritten by every failed login (see
/// [`table_watermark::IDENTITY_TABLES`](openstack_keystone_core::table_watermark::IDENTITY_TABLES)),
/// and the local user of a user is read on every request anyway.
pub const PASSWORD_EXPIRY_TABLES: &[&str] = &["password"];

/// Entries per cache.
const CAPACITY: usize = 10_000;

/// The projection caches of one identity driver instance.
pub struct UserCaches {
    /// Options of a user by user ID.
    pub options: ProjectionCache<UserOptions>,
    /// Expiry of the latest password by user ID.
    pub password_expiry: ProjectionCache<PasswordExpiry>,
}

impl Default for UserCaches {
    fn default() -> Self {
        Self {
            options: ProjectionCache::new(OPTION_TABLES, CAPACITY),
            password_expiry: ProjectionCache::new(PASSWORD_EXPIRY_TABLES, CAPACITY),
        }
    }
}

impl UserCaches {
    /// Forget the projections of one user: this replica wrote to the user,
    /// its options or its password and must see the result immediately.
    pub fn invalidate_user(&self, user_id: &str) {
        self.options.invalidate_key(user_id);
        self.password_expiry.invalidate_key(user_id);
    }
}
