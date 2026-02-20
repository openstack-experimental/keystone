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

use sea_orm::ConnectionTrait;
use sea_orm::entity::*;

use crate::db::entity::federated_user;
use crate::error::DbContextExt;
use crate::identity::IdentityProviderError;

#[tracing::instrument(skip_all)]
pub async fn create<A, C>(
    db: &C,
    federation: A,
) -> Result<federated_user::Model, IdentityProviderError>
where
    A: Into<federated_user::ActiveModel>,
    C: ConnectionTrait,
{
    Ok(federation
        .into()
        .insert(db)
        .await
        .context("persisting federated user data")?)
}

#[cfg(test)]
mod tests {}
