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
//! OAuth2 signing key rotation API types (ADR 0026 §3).

use serde::{Deserialize, Serialize};

/// Request body for `POST /v4/oauth2/{domain_id}/rotate-signing-key`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RotateSigningKeyRequest {
    /// Stage an emergency (dual-control) rotation instead of committing
    /// immediately.
    #[serde(default)]
    pub emergency: bool,
    /// Stage a `--local-quorum-bypass` rotation (ADR 0028 §2): written only
    /// to this node's local emergency store, bypassing Raft/quorum
    /// entirely. Mutually exclusive with `emergency` (Raft-backed staging);
    /// when set, `emergency` is ignored. Requires `justification` and a
    /// node whose `[local_emergency]` guardrail currently permits it.
    #[serde(default)]
    pub local_quorum_bypass: bool,
    /// Required when `local_quorum_bypass` is set: the operator's reason
    /// for invoking the bypass, recorded with the candidate for audit.
    #[serde(default)]
    pub justification: Option<String>,
}

/// Response body for `POST /v4/oauth2/{domain_id}/rotate-signing-key`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RotateSigningKeyResponse {
    /// Set when `emergency` was `false`: the newly active `Primary` key's
    /// `kid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Set when `emergency` was `true`: pass this to
    /// `confirm-rotate-signing-key`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_rotation_id: Option<String>,
    /// Set when `emergency` was `true`: Unix epoch seconds after which the
    /// pending rotation auto-aborts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Set when `local_quorum_bypass` was `true`: the candidate's
    /// `rotation_id`, for later reconciliation once quorum returns.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_rotation_id: Option<String>,
}

/// Request body for `POST /v4/oauth2/{domain_id}/confirm-rotate-signing-key`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConfirmRotateSigningKeyRequest {
    /// The `pending_rotation_id` returned by `rotate-signing-key`.
    pub rotation_id: String,
    /// JTIs known to have been issued by the compromised key during the
    /// incident window, to add to the JTI revocation list (ADR 0026 §3).
    #[serde(default)]
    pub revoke_jtis: Vec<String>,
}

/// Response body for `POST /v4/oauth2/{domain_id}/confirm-rotate-signing-key`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ConfirmRotateSigningKeyResponse {
    /// The newly active `Primary` key's `kid`.
    pub kid: String,
}

/// Response body for `POST /v4/oauth2/{domain_id}/ensure-signing-key`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct EnsureSigningKeyResponse {
    /// The domain's `Primary` key's `kid` -- pre-existing if one was
    /// already provisioned, freshly generated otherwise.
    pub kid: String,
}

/// One node-local emergency rotation candidate (ADR 0028 §6).
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct LocalEmergencyCandidateSummary {
    /// Opaque identifier to pass to `reconcile-local-emergency-key`.
    pub rotation_id: String,
    /// Identity of the operator who staged this candidate.
    pub initiator: String,
    /// The operator-supplied justification recorded with the candidate.
    pub justification: String,
    /// Unix epoch seconds the candidate was created.
    pub created_at_unix: i64,
    /// `None` if staged on the node answering this request; `Some(node_id)`
    /// if it arrived via gossip from another node (ADR 0028 §5).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin_node_id: Option<u64>,
    /// Set if gossip detected a different active candidate for this domain
    /// on another node -- the operator must explicitly pick one side.
    pub conflicted: bool,
    /// Set once this candidate has lost reconciliation. Never reconcilable.
    pub revoked: bool,
}

/// Response body for
/// `GET /v4/oauth2/{domain_id}/local-emergency-candidates`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ListLocalEmergencyCandidatesResponse {
    /// Every candidate on this node for the requested domain (including
    /// revoked ones, for audit visibility).
    pub candidates: Vec<LocalEmergencyCandidateSummary>,
}

/// Request body for
/// `POST /v4/oauth2/{domain_id}/reconcile-local-emergency-key`.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ReconcileLocalEmergencyKeyRequest {
    /// The `rotation_id` of the node-local candidate to promote, from
    /// `GET .../local-emergency-candidates`. The operator's explicit choice
    /// when multiple (possibly conflicting) candidates exist (ADR 0028 §6).
    pub rotation_id: String,
}

/// Response body for
/// `POST /v4/oauth2/{domain_id}/reconcile-local-emergency-key`.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ReconcileLocalEmergencyKeyResponse {
    /// The newly active `Primary` key's `kid`.
    pub kid: String,
}
