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
//! # Token revocation provider.
//!
//! Token revocation may be implemented in different ways, but in most cases
//! would be represented by the presence of the revocation or the invalidation
//! record matching the certain token parameters.
//!
//! Default backend is the [`sql`](crate::revoke::backend::sql) and uses the
//! database [table](crate::db::entity::revocation_event::Model) for storing the
//! revocation events. They have their own expiration.
//!
//! Tokens are not invalidated by saving the exact value, but rather by saving
//! certain attributes of the token.
//!
//! Following attributes are used for matching of the regular fernet token:
//!
//!   - `audit_id`
//!   - `domain_id`
//!   - `expires_at`
//!   - `project_id`
//!   - `user_id`
//!
//! Additionally the `token.issued_at` is compared to be lower than the
//! `issued_before` field of the revocation record.
pub use openstack_keystone_core::revoke::*;
pub mod backend;
