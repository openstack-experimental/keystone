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

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

pub use openstack_keystone_api_types::v3::role::*;

use crate::role::types;

impl From<types::Role> for Role {
    fn from(value: types::Role) -> Self {
        Self {
            id: value.id,
            domain_id: value.domain_id,
            name: value.name,
            description: value.description,
            extra: value.extra,
        }
    }
}

impl IntoResponse for types::Role {
    fn into_response(self) -> Response {
        (
            StatusCode::OK,
            Json(RoleResponse {
                role: Role::from(self),
            }),
        )
            .into_response()
    }
}

impl From<RoleListParameters> for types::RoleListParameters {
    fn from(value: RoleListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            name: value.name,
        }
    }
}

impl From<RoleCreate> for types::RoleCreate {
    fn from(value: RoleCreate) -> Self {
        Self {
            description: value.description,
            domain_id: value.domain_id,
            extra: value.extra,
            id: None,
            name: value.name,
        }
    }
}
