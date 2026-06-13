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
//! HMAC-SHA256 derivation for virtual user IDs.
//!
//! Derives deterministic virtual user IDs from workload and provider
//! identifiers using HMAC-SHA256 with a per-cluster salt. Identical principals
//! always resolve to the same `user_id` within a cluster, while cross-cluster
//! correlation is blocked by the per-cluster salt.
//!
//! Per ADR-0020 §7.2: `HMAC-SHA256(cluster_salt, workload_id || provider_id)`,
//! first 16 bytes formatted as a UUIDv4-compatible hex string.

use hmac::{Hmac, Mac};
use sha2::Sha256;

use openstack_keystone_core_types::mapping::IdentitySource;

use crate::mapping::error::MappingProviderError;

/// Derive a deterministic virtual user ID from workload and identity source.
///
/// # Parameters
/// - `salt`: The cluster-wide HMAC key (raw bytes).
/// - `workload_id`: The canonical workload identifier from the ingress adapter.
/// - `source`: The identity source that identified the workload.
///
/// # Returns
/// A 32-character dashless hex string derived from the first 16 bytes of the
/// HMAC-SHA256 digest (UUID-compatible, dashless to survive token
/// serialization).
///
/// # Errors
/// Returns `HmacDerivationFailed` if the salt is empty or the HMAC operation
/// fails.
pub fn derive_virtual_user_id(
    salt: &[u8],
    workload_id: &str,
    source: &IdentitySource,
) -> Result<String, MappingProviderError> {
    if salt.is_empty() {
        return Err(MappingProviderError::HmacDerivationFailed(
            "cluster_salt is empty".to_string(),
        ));
    }

    let source_key = source.to_string_key();
    let message = format!("{workload_id}:{source_key}");

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(salt).map_err(|_| {
        MappingProviderError::HmacDerivationFailed("invalid key length".to_string())
    })?;
    mac.update(message.as_bytes());
    let result = mac.finalize().into_bytes();

    let bytes = &result[..16];
    Ok(format!(
        "{:08x}{:04x}{:04x}{:04x}{:08x}{:04x}",
        u32::from_be_bytes(bytes[0..4].try_into().map_err(|_| {
            MappingProviderError::HmacDerivationFailed("byte slice conversion failed".to_string())
        })?),
        u16::from_be_bytes(bytes[4..6].try_into().map_err(|_| {
            MappingProviderError::HmacDerivationFailed("byte slice conversion failed".to_string())
        })?),
        u16::from_be_bytes(bytes[6..8].try_into().map_err(|_| {
            MappingProviderError::HmacDerivationFailed("byte slice conversion failed".to_string())
        })?),
        u16::from_be_bytes(bytes[8..10].try_into().map_err(|_| {
            MappingProviderError::HmacDerivationFailed("byte slice conversion failed".to_string())
        })?),
        u32::from_be_bytes(bytes[10..14].try_into().map_err(|_| {
            MappingProviderError::HmacDerivationFailed("byte slice conversion failed".to_string())
        })?),
        u16::from_be_bytes(bytes[14..16].try_into().map_err(|_| {
            MappingProviderError::HmacDerivationFailed("byte slice conversion failed".to_string())
        })?),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn salt() -> Vec<u8> {
        b"test-cluster-secret-salt-256bits!!!".to_vec()
    }

    fn federation_source() -> IdentitySource {
        IdentitySource::Federation {
            idp_id: "okta-prod".to_string(),
        }
    }

    fn k8s_source() -> IdentitySource {
        IdentitySource::K8s {
            cluster_id: "eks-prod-01".to_string(),
        }
    }

    fn spiffe_source() -> IdentitySource {
        IdentitySource::Spiffe {
            trust_domain: "prod.keystone.internal".to_string(),
        }
    }

    #[test]
    fn test_deterministic_same_input_same_output() {
        let source = federation_source();
        let id1 = derive_virtual_user_id(&salt(), "user-123", &source).unwrap();
        let id2 = derive_virtual_user_id(&salt(), "user-123", &source).unwrap();
        assert_eq!(id1, id2);
    }

    #[test]
    fn test_different_workload_different_output() {
        let source = federation_source();
        let id1 = derive_virtual_user_id(&salt(), "user-123", &source).unwrap();
        let id2 = derive_virtual_user_id(&salt(), "user-456", &source).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_different_source_different_output() {
        let id1 = derive_virtual_user_id(&salt(), "user-123", &federation_source()).unwrap();
        let id2 = derive_virtual_user_id(&salt(), "user-123", &k8s_source()).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_different_salt_different_output() {
        let source = federation_source();
        let id1 = derive_virtual_user_id(&salt(), "user-123", &source).unwrap();
        let other_salt = b"different-cluster-salt-for-testing".to_vec();
        let id2 = derive_virtual_user_id(&other_salt, "user-123", &source).unwrap();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_empty_salt_rejected() {
        let source = federation_source();
        let result = derive_virtual_user_id(&[], "user-123", &source);
        assert!(matches!(
            result,
            Err(MappingProviderError::HmacDerivationFailed(_))
        ));
    }

    #[test]
    fn test_all_source_types_produce_valid_uuid() {
        let workload = "user-123";
        for source in [federation_source(), k8s_source(), spiffe_source()] {
            let id = derive_virtual_user_id(&salt(), workload, &source).unwrap();
            assert_eq!(id.len(), 32);
            assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn test_k8s_source_key_format() {
        let source = k8s_source();
        assert_eq!(source.to_string_key(), "k8s:eks-prod-01");
    }

    #[test]
    fn test_spiffe_source_key_format() {
        let source = spiffe_source();
        assert_eq!(source.to_string_key(), "spiffe:prod.keystone.internal");
    }
}
