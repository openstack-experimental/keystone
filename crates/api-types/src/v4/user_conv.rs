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

use openstack_keystone_core_types::identity as provider_types;

use crate::v4::user as api_types;

impl From<api_types::UserType> for provider_types::UserType {
    fn from(value: api_types::UserType) -> Self {
        match value {
            api_types::UserType::All => Self::All,
            api_types::UserType::Federated => Self::Federated,
            api_types::UserType::Local => Self::Local,
            api_types::UserType::NonLocal => Self::NonLocal,
            api_types::UserType::ServiceAccount => Self::ServiceAccount,
        }
    }
}

impl From<api_types::UserListParameters> for provider_types::UserListParameters {
    fn from(value: api_types::UserListParameters) -> Self {
        Self {
            domain_id: value.domain_id,
            name: value.name,
            unique_id: value.unique_id,
            user_type: value.user_type.map(Into::into),
        }
    }
}
