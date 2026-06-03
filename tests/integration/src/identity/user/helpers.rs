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
//! Shared helpers for user integration tests.

use chrono::{TimeDelta, Utc};

use openstack_keystone::keystone::ServiceState;

/// Assert that `password_expires_at` is approximately `now + days +/- 1 day
/// tolerance`.
pub fn assert_expires_at_approx(
    actual: Option<&chrono::DateTime<Utc>>,
    now: chrono::DateTime<Utc>,
    days: u64,
) {
    let dt = actual.expect("password_expires_at should be set");
    let expected = now + TimeDelta::days(days as i64);
    let diff = dt.signed_duration_since(expected).num_days().abs();
    assert!(diff <= 1, "expected ~{days}d from now, got {diff}d off");
}

/// Configure `password_expires_days` and/or `unique_last_password_count` on the
/// shared config for the duration of a test.
pub async fn setup_test_config(
    state: &ServiceState,
    password_expires_days: Option<u64>,
    unique_last_password_count: Option<u16>,
) {
    let mut cfg = state.config_manager.config.write().await;
    if let Some(v) = password_expires_days {
        cfg.security_compliance.password_expires_days = Some(v);
    }
    if let Some(v) = unique_last_password_count {
        cfg.security_compliance.unique_last_password_count = Some(v);
    }
}

/// Convenience wrapper to produce `Some(String)` for password/name fields.
pub fn pwd<S: Into<String>>(s: S) -> Option<String> {
    Some(s.into())
}
