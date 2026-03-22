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

//! # Identity provider
//!
//! Following identity concepts are covered by the identity provider:
//!
//! ## Group
//!
//! An Identity service API v3 entity. Groups are a collection of users
//! owned by a domain. A group role, granted to a domain or project, applies to
//! all users in the group. Adding or removing users to or from a group grants
//! or revokes their role and authentication to the associated domain or
//! project.
//!
//! ## User
//!
//! A digital representation of a person, system, or service that uses
//! OpenStack cloud services. The Identity service validates that incoming
//! requests are made by the user who claims to be making the call. Users have a
//! login and can access resources by using assigned tokens. Users can be
//! directly assigned to a particular project and behave as if they are
//! contained in that project.
pub use openstack_keystone_core::identity::*;
