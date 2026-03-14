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

use crate::api::error::KeystoneApiError;
use crate::trust::TrustProviderError;

impl From<TrustProviderError> for KeystoneApiError {
    fn from(source: TrustProviderError) -> Self {
        match source {
            TrustProviderError::Conflict(x) => Self::Conflict(x),
            TrustProviderError::ExpirationImpossible => Self::forbidden(source),
            TrustProviderError::RedelegatedRolesNotAvailable => Self::forbidden(source),
            TrustProviderError::RedelegationDeepnessExceed { .. } => Self::forbidden(source),
            TrustProviderError::RemainingUsesExceed => Self::forbidden(source),
            other => Self::InternalError(other.to_string()),
        }
    }
}
