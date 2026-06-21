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
//! # Catalog provider
//!
//! Catalog provider takes care of returning the list of the service endpoints
//! that the API user is able to use according to the valid authentication.
//!
//! Following Keystone concepts are covered:
//!
//! ## Endpoint
//!
//! A network-accessible address, usually a URL, through which you can access a
//! service. If you are using an extension for templates, you can create an
//! endpoint template that represents the templates of all consumable services
//! that are available across the regions.
//!
//! ## Service
//!
//! An OpenStack service, such as Compute (nova), Object Storage (swift), or
//! Image service (glance), that provides one or more endpoints through which
//! users can access resources and perform operations.

pub mod backend;
pub mod error;
pub mod hook;
#[cfg(any(test, feature = "mock"))]
mod mock;
mod provider_api;
pub mod service;

pub use error::CatalogProviderError;
pub use hook::CatalogHook;
#[cfg(any(test, feature = "mock"))]
pub use mock::MockCatalogProvider;
pub use provider_api::CatalogApi;
pub use service::CatalogService;
