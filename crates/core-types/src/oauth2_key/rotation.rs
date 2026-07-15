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
//! # Signing key rotation DTOs (ADR 0026 §3)

/// Returned when an emergency rotation is staged: the confirming operator
/// needs `rotation_id`, and callers surface `expires_at` so they know the
/// dual-control confirmation window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRotationInfo {
    /// Opaque identifier the second operator passes to confirm the
    /// rotation.
    pub rotation_id: String,
    /// Unix epoch seconds after which this pending rotation auto-aborts.
    pub expires_at: i64,
}
