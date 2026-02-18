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
//! # Database migrations
pub use sea_orm_migration::prelude::*;

mod m20250301_000001_passkey;
mod m20250414_000001_idp;
mod m20251005_131042_token_restriction;
mod m20260217_164934_k8;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250301_000001_passkey::Migration),
            Box::new(m20250414_000001_idp::Migration),
            Box::new(m20251005_131042_token_restriction::Migration),
            Box::new(m20260217_164934_k8::Migration),
        ]
    }
}
