// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

use async_trait::async_trait;
use mockall::mock;

use openstack_keystone_core_types::assignment::*;

use crate::assignment::{AssignmentApi, AssignmentProviderError};
use crate::keystone::ServiceState;

mock! {
    pub AssignmentProvider {}

    #[async_trait]
    impl AssignmentApi for AssignmentProvider {
        async fn create_grant(
            &self,
            state: &ServiceState,
            params: AssignmentCreate,
        ) -> Result<Assignment, AssignmentProviderError>;

        async fn list_role_assignments(
            &self,
            state: &ServiceState,
            params: &RoleAssignmentListParameters,
        ) -> Result<Vec<Assignment>, AssignmentProviderError>;

        async fn revoke_grant(
            &self,
            state: &ServiceState,
            params: Assignment,
        ) -> Result<(), AssignmentProviderError>;
    }
}
