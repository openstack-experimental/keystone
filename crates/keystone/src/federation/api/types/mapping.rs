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
//! Federated attribute mapping types.

use openstack_keystone_api_types::federation::mapping;

use crate::api::common::{QueryParameterPagination, ResourceIdentifier};

pub use mapping::Mapping;
pub use mapping::MappingCreate;
pub use mapping::MappingCreateRequest;
pub use mapping::MappingList;
pub use mapping::MappingListParameters;
pub use mapping::MappingResponse;
pub use mapping::MappingType;
pub use mapping::MappingUpdate;
pub use mapping::MappingUpdateRequest;

impl ResourceIdentifier for Mapping {
    fn get_id(&self) -> String {
        self.id.clone()
    }
}

impl QueryParameterPagination for MappingListParameters {
    fn get_limit(&self) -> Option<u64> {
        self.limit
    }

    fn set_marker(&mut self, marker: String) -> &mut Self {
        self.marker = Some(marker);
        self
    }
}
