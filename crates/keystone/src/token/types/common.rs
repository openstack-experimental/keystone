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

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use validator::ValidationError;

/// Validate audit_ids are valid URL-safe base64 strings without padding.
pub fn validate_audit_ids(audit_ids: &[String]) -> Result<(), ValidationError> {
    for audit_id in audit_ids {
        if audit_id.is_empty() {
            let mut err = ValidationError::new("empty_audit_id");
            err.message = Some("Audit ID cannot be empty".into());
            return Err(err);
        }

        // Use NO_PAD decoder to match Python's [:-2] behavior
        if URL_SAFE_NO_PAD.decode(audit_id).is_err() {
            let mut err = ValidationError::new("invalid_audit_id");
            err.message =
                Some(format!("Audit ID '{}' is not valid URL-safe base64", audit_id).into());
            return Err(err);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_audit_ids;
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

    #[test]
    fn test_validate_audit_ids_valid() {
        let valid_audit_ids = vec![
            // retrieved from github test
            "popWT1EoRVufGoLJttW_zw".to_string(),
            URL_SAFE_NO_PAD.encode(b"audit2"),
            URL_SAFE_NO_PAD.encode(b"some-longer-audit-id-123"),
        ];

        assert!(validate_audit_ids(&valid_audit_ids).is_ok());
    }

    #[test]
    fn test_validate_audit_ids_empty_string() {
        let invalid_audit_ids = vec![
            URL_SAFE_NO_PAD.encode(b"valid"),
            "".to_string(), // Empty string
        ];

        let result = validate_audit_ids(&invalid_audit_ids);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "empty_audit_id");
    }

    #[test]
    fn test_validate_audit_ids_invalid_base64() {
        let invalid_audit_ids = vec!["not-valid-base64!@#$%".to_string()];

        let result = validate_audit_ids(&invalid_audit_ids);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.code, "invalid_audit_id");
        assert!(err.message.unwrap().contains("not valid URL-safe base64"));
    }

    #[test]
    fn test_validate_audit_ids_mixed_valid_invalid() {
        let mixed_audit_ids = vec![
            URL_SAFE_NO_PAD.encode(b"valid1"),
            "invalid!@#".to_string(),
            URL_SAFE_NO_PAD.encode(b"valid2"),
        ];

        // Should fail on first invalid
        let result = validate_audit_ids(&mixed_audit_ids);
        assert!(result.is_err());
    }
}
