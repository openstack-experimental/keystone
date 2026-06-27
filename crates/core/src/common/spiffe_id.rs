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
//! # Thin SPIFFE ID representation
//!
//! Decouples the core crate from the `spiffe` crate. Listeners in the server
//! crate parse the full `spiffe::SpiffeId` from TLS peer certificates and
//! convert it into this type before inserting it into request extensions.

use std::fmt;

/// A parsed SPIFFE ID carrying the full URI and its trust domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpiffeId {
    /// Full SPIFFE URI, e.g. `spiffe://example.org/workload`.
    pub id: String,
    /// Trust domain extracted from the URI, e.g. `example.org`.
    pub trust_domain: String,
}

impl SpiffeId {
    /// Parse a SPIFFE URI of the form `spiffe://<trust-domain>[/path]`.
    ///
    /// Returns `None` if the URI does not start with `spiffe://` or the trust
    /// domain segment is empty.
    pub fn new(uri: &str) -> Option<Self> {
        let without_scheme = uri.strip_prefix("spiffe://")?;
        let trust_domain = without_scheme
            .split('/')
            .next()
            .filter(|s| !s.is_empty())?
            .to_string();
        Some(Self {
            id: uri.to_string(),
            trust_domain,
        })
    }

    /// Returns the full SPIFFE URI.
    pub fn as_str(&self) -> &str {
        &self.id
    }

    /// Returns the trust domain of this SPIFFE ID.
    pub fn trust_domain_name(&self) -> &str {
        &self.trust_domain
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.id)
    }
}
