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

pub use openstack_keystone_api_types::v3::credential::*;

impl crate::api::common::ResourceIdentifier for Credential {
    fn get_id(&self) -> String {
        self.id.clone()
    }
}

/// Marker for the *domain* credential so `collect_authorized_page` can advance
/// its marker over raw backend rows.
///
/// Deliberately implemented on the domain type rather than converting rows to
/// the API type before the per-item check: `credential_policy_input` must keep
/// receiving exactly the object it received before, so adopting the shared
/// page-filler changes no policy input.
impl crate::api::common::ResourceIdentifier
    for openstack_keystone_core_types::credential::Credential
{
    fn get_id(&self) -> String {
        self.id.clone()
    }
}
