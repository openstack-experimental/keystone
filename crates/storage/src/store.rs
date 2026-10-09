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
//! # Persistence layer.
//!
//! - [`bootstrap`]: [`new`] builds the log store and state machine over one
//!   shared Fjall database.
//! - [`log_store`]: the Raft log.
//! - [`state_machine`]: the encrypted state machine.

pub mod bootstrap;
pub mod log_store;
pub mod state_machine;

pub use bootstrap::new;
