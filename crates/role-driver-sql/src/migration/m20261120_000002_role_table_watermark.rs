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
//! Install the table version watermark triggers of the role tables.
use sea_orm_migration::prelude::*;

use openstack_keystone_core::table_watermark::{self, ROLE_TABLES};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        table_watermark::install_migration(manager, ROLE_TABLES).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        table_watermark::uninstall_migration(manager, ROLE_TABLES).await
    }
}
