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
//! Token provider types.

mod application_credential;
mod common;
mod domain_scoped;
mod federation_domain_scoped;
mod federation_project_scoped;
mod federation_unscoped;
mod project_scoped;
mod restricted;
mod system_scoped;
mod trust;
mod unscoped;

pub use application_credential::*;
pub use domain_scoped::*;
pub use federation_domain_scoped::*;
pub use federation_project_scoped::*;
pub use federation_unscoped::*;
pub use project_scoped::*;
pub use restricted::*;
pub use system_scoped::*;
pub use trust::*;
pub use unscoped::*;
