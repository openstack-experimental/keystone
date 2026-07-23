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
//! v3 group CRUD helpers, generated with [`crate::macros::crud_endpoint`].

use openstack_keystone_api_types::v3::group::*;

use crate::macros::crud_endpoint;

crud_endpoint! {
    create {
        request = GroupCreateApiRequest,
        func = create_group,
        path = "groups",
        body_key = "group",
        create_type = GroupCreate,
        model = Group,
        response_key = "group",
        service = Identity,
        api_version = (3, 0),
    }
    show {
        request = GroupShowApiRequest,
        func = get_group,
        path = "groups",
        model = Group,
        response_key = "group",
        service = Identity,
        api_version = (3, 0),
    }
    update {
        request = GroupUpdateApiRequest,
        func = update_group,
        path = "groups",
        body_key = "group",
        update_type = GroupUpdate,
        model = Group,
        response_key = "group",
        service = Identity,
        api_version = (3, 0),
    }
    list {
        request = GroupListRequest,
        func = list_groups,
        path = "groups",
        model = Group,
        response_key = "groups",
        service = Identity,
        api_version = (3, 0),
        query = [domain_id, name],
    }
    delete {
        request = GroupDeleteApiRequest,
        func = delete_group,
        path = "groups",
        model = Group,
        service = Identity,
        api_version = (3, 0),
    }
}
