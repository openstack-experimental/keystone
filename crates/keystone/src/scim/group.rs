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
//! # `/SCIM/v2/{domain_id}/Groups` (ADR 0024 §3, §4, §6.B, §7)

use axum::{Router, routing::get};

use openstack_keystone_core::keystone::ServiceState;

mod create;
mod delete;
mod list;
mod membership;
mod show;
mod update;

/// `Groups` sub-router, nested at `/{domain_id}/Groups` in [`super::router`].
pub fn router() -> Router<ServiceState> {
    Router::new()
        .route("/", get(list::list).post(create::create))
        .route(
            "/{id}",
            get(show::show).put(update::update).delete(delete::delete),
        )
}
