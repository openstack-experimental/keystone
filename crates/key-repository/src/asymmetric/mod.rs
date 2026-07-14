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
//! # Asymmetric (ES256/RS256) key repository (ADR 0026 §3, §10 Phase 0/1)
//!
//! Parallel to the crate's existing symmetric Fernet [`crate::KeyRepository`]:
//! generalized to asymmetric keypairs, generic over a role-keyed
//! [`AsymmetricKeySource`] rather than an integer-indexed one, since
//! ES256/RS256 signing keys follow a Primary/Previous/Pending model
//! (ADR 0026 §3), not a flat N-key ring.
pub mod filesystem;
mod keygen;
mod kid;
mod repository;
mod source;

pub use filesystem::FilesystemAsymmetricKeySource;
pub use keygen::generate_keypair;
pub use kid::derive_kid;
pub use repository::{ActiveKeys, AsymmetricKeyRepository};
pub use source::{AsymmetricKeySource, KeyMaterial, KeyRole, SigningAlgorithm};
