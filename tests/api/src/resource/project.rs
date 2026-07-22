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
//! v3 project CRUD helpers, generated with [`crate::macros::crud_endpoint`].

use openstack_keystone_api_types::v3::project::*;

use crate::macros::crud_endpoint;

crud_endpoint! {
    create {
        request = ProjectCreateRequest,
        func = create_project,
        path = "projects",
        body_key = "project",
        create_type = ProjectCreate,
        model = Project,
        response_key = "project",
        service = Identity,
        api_version = (3, 0),
    }
    show {
        request = ProjectShowRequest,
        func = get_project,
        path = "projects",
        model = Project,
        response_key = "project",
        service = Identity,
        api_version = (3, 0),
    }
    update {
        request = ProjectUpdateRequest,
        func = update_project,
        path = "projects",
        body_key = "project",
        update_type = ProjectUpdate,
        model = Project,
        response_key = "project",
        service = Identity,
        api_version = (3, 0),
    }
    list {
        request = ProjectListRequest,
        func = list_projects,
        path = "projects",
        model = ProjectShort,
        response_key = "projects",
        service = Identity,
        api_version = (3, 0),
        query = [domain_id, ids, name],
    }
    delete {
        request = ProjectDeleteRequest,
        func = delete_project,
        path = "projects",
        model = Project,
        service = Identity,
        api_version = (3, 0),
    }
}
