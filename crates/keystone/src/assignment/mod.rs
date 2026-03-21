// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
//! # Assignments provider
//!
//! Assignments provider implements RBAC concept of granting an actor set of
//! roles on the target. An actor could be a user or a group of users, in which
//! case such roles are granted implicitly to the all users which are the member
//! of the group. The target is the domain, project or the system.
//!
//! Keystone implements few additional features for the role assignments:
//!
//! ## Role inference
//!
//! Roles in Keystone may imply other roles building an inference chain. For
//! example a role `manager` can imply the `member` role, which in turn implies
//! the `reader` role. As such with a single assignment of the `manager` role
//! the user will automatically get `manager`, `member` and `reader` roles. This
//! helps limiting number of necessary direct assignments.
//!
//! ## Target assignment inheritance
//!
//! Keystone adds `inherited` parameter to the assignment of the role on the
//! target. In such case an assignment actor gets this role assignment
//! (including role inference) on the whole subtree targets excluding the target
//! itself. This way for an assignment on the domain level the actor
//! will get the role on the every project of the domain, but not the domain
//! itself.
pub use openstack_keystone_core::assignment::*;
