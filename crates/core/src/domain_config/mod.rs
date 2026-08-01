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

//! # Domain configuration provider
//!
//! Per-domain overrides of the identity backend configuration, letting an
//! operator onboard a domain with its own LDAP directory without restarting
//! the service.
//!
//! A domain's configuration is a small set of options grouped into `identity`
//! and `ldap`; a domain that has none falls back to the global configuration.
//! Options are addressed at three granularities — the whole configuration, a
//! single group, or a single option — which is why the backend trait carries a
//! method triple for each verb.

pub mod backend;
pub mod error;

pub use backend::DomainConfigBackend;
pub use error::DomainConfigProviderError;
