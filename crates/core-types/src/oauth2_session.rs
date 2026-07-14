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
//! # OAuth2 browser session state (ADR 0026 §10 Phase 4)
//!
//! Stateful records backing the `authorization_code` grant's interactive
//! flow: the pre-authentication browser session created at
//! `GET /authorize`, the single-use authorization code minted on consent,
//! and the `refresh_token` family tree (ADR 0026 §2, §9).

mod error;
mod resource;

pub use error::*;
pub use resource::*;
