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
//! # Resource provider
//!
//! Following Keystone concepts are covered by the provider:
//!
//! ## Domain
//!
//! An Identity service API v3 entity. Domains are a collection of projects and
//! users that define administrative boundaries for managing Identity entities.
//! Domains can represent an individual, company, or operator-owned space. They
//! expose administrative activities directly to system users. Users can be
//! granted the administrator role for a domain. A domain administrator can
//! create projects, users, and groups in a domain and assign roles to users and
//! groups in a domain.
//!
//! ## Project
//!
//! A container that groups or isolates resources or identity objects. Depending
//! on the service operator, a project might map to a customer, account,
//! organization, or tenant.
pub use openstack_keystone_core::resource::*;
