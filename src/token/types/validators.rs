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

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use validator::ValidationError;

pub fn validate_audit_ids(audit_ids: &[String]) -> Result<(), ValidationError> {
    for audit_id in audit_ids {
        match BASE64_URL_SAFE_NO_PAD.decode(audit_id) {
            Ok(decoded) => {
                if decoded.is_empty() {
                    let mut err = ValidationError::new("invalid_audit_id");
                    err.message = Some("Audit ID cannot be empty".into());
                    return Err(err);
                }
            }
            Err(_) => {
                let mut err = ValidationError::new("invalid_audit_id");
                err.message = Some(
                    "Audit ID must be valid base64 URL-safe string without padding".into(),
                );
                return Err(err);
            }
        }
    }
    Ok(())
}

pub fn validate_future_datetime(expires_at: &DateTime<Utc>) -> Result<(), ValidationError> {
    if *expires_at <= Utc::now() {
        let mut err = ValidationError::new("expires_in_past");
        err.message = Some("Token expiration must be in the future".into());
        return Err(err);
    }
    Ok(())
}

pub fn validate_issued_datetime(issued_at: &DateTime<Utc>) -> Result<(), ValidationError> {
    if *issued_at > Utc::now() {
        let mut err = ValidationError::new("issued_in_future");
        err.message = Some("Token issued_at cannot be in the future".into());
        return Err(err);
    }
    Ok(())
}