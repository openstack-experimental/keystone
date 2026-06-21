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
//! # Kubernetes authentication.

mod auth;
pub mod backend;
mod client;
pub mod error;
pub mod hook;
#[cfg(any(test, feature = "mock"))]
mod provider_api;
pub mod service;

pub use client::K8sHttpClient;
pub use error::K8sAuthProviderError;
pub use hook::K8sAuthHook;
#[cfg(any(test, feature = "mock"))]
pub use crate::mocks::MockK8sAuthProvider;
pub use openstack_keystone_core_types::k8s_auth::*;
pub use provider_api::K8sAuthApi;
pub use service::K8sAuthService;
