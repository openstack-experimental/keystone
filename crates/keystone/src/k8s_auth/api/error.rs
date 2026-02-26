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
use tracing::error;

use crate::api::error::KeystoneApiError;
use crate::k8s_auth::K8sAuthProviderError;

/// Convert `K8sAuthProviderError` error into the [HTTP](KeystoneApiError) with
/// the expected
impl From<K8sAuthProviderError> for KeystoneApiError {
    fn from(source: K8sAuthProviderError) -> Self {
        error!(
            "Error happened during request k8s_auth processing: {:#?}",
            source
        );
        match source {
            K8sAuthProviderError::AudienceMismatch => Self::forbidden(source),
            K8sAuthProviderError::CaCertificateUnknown => Self::forbidden(source),
            K8sAuthProviderError::AuthInstanceNotActive(..) => Self::forbidden(source),
            K8sAuthProviderError::AuthInstanceNotFound(x) => Self::NotFound {
                resource: "k8s auth configuration".into(),
                identifier: x,
            },
            K8sAuthProviderError::Conflict(x) => Self::Conflict(x),
            K8sAuthProviderError::FailedBoundServiceAccountName(..) => Self::forbidden(source),
            K8sAuthProviderError::FailedBoundServiceAccountNamespace(..) => Self::forbidden(source),
            K8sAuthProviderError::Jwt { .. } => Self::forbidden(source),
            K8sAuthProviderError::ExpiredToken => Self::forbidden(source),
            K8sAuthProviderError::InsecureAlgorithm => Self::forbidden(source),
            K8sAuthProviderError::InvalidToken => Self::forbidden(source),
            K8sAuthProviderError::RoleNotFound(x) => Self::NotFound {
                resource: "k8s auth role".into(),
                identifier: x,
            },
            K8sAuthProviderError::RoleNotActive(..) => Self::forbidden(source),
            K8sAuthProviderError::RoleInstanceOwnershipMismatch(..) => Self::forbidden(source),
            K8sAuthProviderError::TokenRestrictionNotFound(x) => Self::NotFound {
                resource: "token restriction".into(),
                identifier: x,
            },
            K8sAuthProviderError::UserNotFound(x) => Self::NotFound {
                resource: "user/service account".into(),
                identifier: x,
            },
            other => Self::InternalError(other.to_string()),
        }
    }
}
