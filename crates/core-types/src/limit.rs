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
//! # Unified limits provider
//!
//! Registered limits (service wide defaults) and limits (per project/domain
//! overrides) as known from the Python Keystone "Unified Limits" API.
mod error;
mod limit;
mod model;
mod registered_limit;

pub use error::*;
pub use limit::*;
pub use model::*;
pub use registered_limit::*;
