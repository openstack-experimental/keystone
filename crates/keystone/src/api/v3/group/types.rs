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

pub use openstack_keystone_api_types::v3::group::*;

use crate::identity::types;

impl From<types::Group> for Group {
    fn from(value: types::Group) -> Self {
        Self {
            id: value.id,
            domain_id: value.domain_id,
            name: value.name,
            description: value.description,
            extra: value.extra,
        }
    }
}

impl From<GroupCreateRequest> for types::GroupCreate {
    fn from(value: GroupCreateRequest) -> Self {
        let group = value.group;
        Self {
            id: None,
            name: group.name,
            domain_id: group.domain_id,
            extra: group.extra,
            description: group.description,
        }
    }
}

impl IntoResponse for types::Group {
    fn into_response(self) -> Response {
        (
            StatusCode::OK,
            Json(GroupResponse {
                group: Group::from(self),
            }),
        )
            .into_response()
    }
}

impl From<GroupListParameters> for types::GroupListParameters {
    fn from(value: GroupListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            name: value.name,
        }
    }
}
