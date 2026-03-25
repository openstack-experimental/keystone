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
//! Keystone API types.
use openstack_keystone_core_types::catalog as provider_types;

use crate::catalog as api_types;

impl From<provider_types::Endpoint> for api_types::Endpoint {
    fn from(value: provider_types::Endpoint) -> Self {
        Self {
            id: value.id.clone(),
            interface: value.interface.clone(),
            url: value.url.clone(),
            region: value.region_id.clone(),
            region_id: value.region_id.clone(),
        }
    }
}
