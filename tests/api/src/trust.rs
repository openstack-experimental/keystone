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
//! v3 trust CRUD helpers, generated with [`crate::macros::crud_endpoint`].
//!
//! Trusts are immutable server-side (no PATCH), so only create/show/list/
//! delete are generated.

use openstack_keystone_api_types::v3::trust::*;

use crate::macros::crud_endpoint;

crud_endpoint! {
    create {
        request = TrustCreateRequestApi,
        func = create_trust,
        path = "OS-TRUST/trusts",
        body_key = "trust",
        create_type = TrustCreate,
        model = Trust,
        response_key = "trust",
        service = Identity,
        api_version = (3, 0),
    }
    show {
        request = TrustShowRequest,
        func = show_trust,
        path = "OS-TRUST/trusts",
        model = Trust,
        response_key = "trust",
        service = Identity,
        api_version = (3, 0),
    }
    list {
        request = TrustListRequest,
        func = list_trusts,
        path = "OS-TRUST/trusts",
        model = Trust,
        response_key = "trusts",
        service = Identity,
        api_version = (3, 0),
        query = [include_deleted],
    }
    delete {
        request = TrustDeleteRequest,
        func = delete_trust,
        path = "OS-TRUST/trusts",
        model = Trust,
        service = Identity,
        api_version = (3, 0),
    }
}
