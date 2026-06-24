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
//! # Keystone distributed storage cryptographic primitives
//!
//! Implements the cryptographic barrier described in ADR 0016-v2 §2:
//!
//! * **Key Encryption Key (KEK):** provided by [`kek::KekProvider`].
//!   Development mode uses [`kek::EnvKek`]; production uses
//!   [`kek::Pkcs11KekStub`] (stub — full HSM integration is a future phase).
//!
//! * **Data Encryption Key (DEK) hierarchy:** [`dek::DekEpoch`] holds the
//!   current epoch version and its HKDF-derived sub-keys ([`dek::LogDek`],
//!   [`dek::StateDek`]).
//!
//! * **Encryption helpers:** [`cipher`] provides `log_encrypt` / `log_decrypt`
//!   for Raft log entries and `state_encrypt` / `state_decrypt` for Fjall
//!   state machine records.
//!
//! * **Nonce management:** [`nonce::NonceManager`] maintains a durable,
//!   crash-safe monotonic counter for log-entry nonces (ADR §2.2, F1).
//!
//! ## Security properties enforced
//!
//! * All tags are 16 bytes (full GCM tag length). Truncated tags are
//!   prohibited (ADR §2.2).
//! * Key material types intentionally omit `Debug` / `Display` to prevent
//!   accidental logging.
//! * `#[deny(clippy::mem_forget)]` prevents accidental drop bypass.

#![deny(clippy::mem_forget)]

pub mod cipher;
pub mod dek;
pub mod error;
pub mod kek;
pub mod nonce;

pub use cipher::{log_decrypt, log_encrypt, state_decrypt, state_encrypt};
pub use dek::{DekEpoch, LogDek, StateDek, generate_dek};
pub use error::CryptoError;
pub use kek::{EnvKek, KekProvider, Pkcs11KekStub};
pub use nonce::{NonceManager, NoncePersistence};
