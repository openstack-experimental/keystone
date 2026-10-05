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
//! # OAuth2 session audit events.

use std::sync::Arc;

use uuid::Uuid;

use cadf::{AuditDispatcher, CadfEventPayload, Initiator, Observer, OutcomeReason, Target};

use crate::cadf_hook::with_request_address;

/// Emit the best-effort `oauth2/refresh_family_revoked` CADF event when a
/// `refresh_token` family is revoked because its principal is no longer
/// valid (user deleted/disabled/moved or password changed, domain
/// disabled/deleted), so incident
/// forensics can correlate the tombstones by `family_id` and `reason`.
/// Best-effort `dispatch()`: unlike reuse detection this is not a breach
/// signal, it is the expected consequence of an administrative change.
pub fn emit_oauth2_refresh_family_revoked_event(
    dispatcher: &Arc<AuditDispatcher>,
    correlation_id: &str,
    initiator: Initiator,
    family_id: &str,
    reason: &str,
) {
    let node_id = dispatcher.node_id().to_string();
    let event_id = format!("{}:{}", node_id, Uuid::new_v4());
    let payload = CadfEventPayload::new(
        event_id,
        "1.1".to_string(),
        correlation_id.to_string(),
        chrono::Utc::now().to_rfc3339(),
        "oauth2/refresh_family_revoked".to_string(),
        "success".to_string(),
        Some(OutcomeReason::variant(reason)),
        with_request_address(initiator),
        Target {
            id: family_id.to_string(),
            type_uri: "data/security/keystone/oauth2_refresh_family".to_string(),
        },
        Observer {
            node_id: node_id.clone(),
            id: format!("service/security/keystone/{node_id}"),
        },
    );
    let event = payload.sign(dispatcher);
    dispatcher.dispatch(event);
}
