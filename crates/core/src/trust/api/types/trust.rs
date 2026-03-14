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
use crate::trust::types::Trust;

pub use openstack_keystone_api_types::trust as api_trust;

impl From<&Trust> for api_trust::TokenTrustRepr {
    fn from(value: &Trust) -> Self {
        Self {
            expires_at: value.expires_at,
            id: value.id.clone(),
            impersonation: value.impersonation,
            remaining_uses: value.remaining_uses,
            redelegated_trust_id: value.redelegated_trust_id.clone(),
            redelegation_count: value.redelegation_count,
            trustor_user: api_trust::TokenTrustUser {
                id: value.trustor_user_id.clone(),
            },
            trustee_user: api_trust::TokenTrustUser {
                id: value.trustee_user_id.clone(),
            },
        }
    }
}
