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
//! # OpenStack Keystone Raft driver for OAuth2 browser session state
//! (ADR 0026 §10 Phase 4, §9).
//!
//! Three record kinds, each a flat key-value entry (no wire wrapper type
//! needed -- unlike `oauth2-key-driver-raft`'s `KeyMaterial`, none of these
//! records hold a `SecretBox`):
//!
//! - `oauth2:session:v1:<session_id>` -- pre-auth browser session.
//! - `oauth2:authz_code:v1:<code>` -- single-use authorization code.
//! - `oauth2:refresh_token:v1:<token_id>` -- one node in a refresh token
//!   rotation family (`token_id` is a hash of the bearer value, never the
//!   bearer value itself).
//! - `oauth2:refresh_family_idx:v1:<family_id>:<token_id>` -- secondary index
//!   enabling family-wide fan-out (list/revoke) without a reverse scan over
//!   every refresh token in the store.
use async_trait::async_trait;
use serde::Serialize;
use serde::de::DeserializeOwned;

use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::oauth2_session::Oauth2SessionProviderError;
use openstack_keystone_core::oauth2_session::backend::Oauth2SessionBackend;
use openstack_keystone_core_types::oauth2_session::*;
use openstack_keystone_distributed_storage::{
    ApiStoreError as StoreError, Metadata, StorageApi, StoreDataEnvelope,
};

fn session_key(session_id: &str) -> String {
    format!("oauth2:session:v1:{session_id}")
}

fn code_key(code: &str) -> String {
    format!("oauth2:authz_code:v1:{code}")
}

fn refresh_key(token_id: &str) -> String {
    format!("oauth2:refresh_token:v1:{token_id}")
}

fn family_idx_key(family_id: &str, token_id: &str) -> String {
    format!("oauth2:refresh_family_idx:v1:{family_id}:{token_id}")
}

fn family_idx_prefix(family_id: &str) -> String {
    format!("oauth2:refresh_family_idx:v1:{family_id}:")
}

fn device_code_key(device_code: &str) -> String {
    format!("oauth2:device_code:v1:{device_code}")
}

fn device_user_code_key(user_code: &str) -> String {
    format!("oauth2:device_user_code:v1:{user_code}")
}

async fn put<T: Serialize>(
    storage: &dyn StorageApi,
    key: String,
    value: &T,
) -> Result<(), StoreError> {
    let envelope = StoreDataEnvelope {
        data: rmp_serde::to_vec(value)?,
        metadata: Metadata::new(),
    };
    storage.set_value(key, envelope, None, None).await?;
    Ok(())
}

async fn get<T: DeserializeOwned>(
    storage: &dyn StorageApi,
    key: &str,
) -> Result<Option<T>, StoreError> {
    let Some(envelope) = storage.get_by_key(key.as_bytes(), None).await? else {
        return Ok(None);
    };
    let typed: StoreDataEnvelope<T> = envelope.try_deserialize()?;
    Ok(Some(typed.data))
}

fn store_err(e: StoreError) -> Oauth2SessionProviderError {
    Oauth2SessionProviderError::raft(e)
}

/// Raft-backed [`Oauth2SessionBackend`].
///
/// Every trait method is a thin `ServiceState` -> `&dyn StorageApi`
/// extraction wrapper around an `_impl` method taking `&dyn StorageApi`
/// directly (mirrors `oauth2-key-driver-raft`'s `RaftOauth2KeyBackend`):
/// the `_impl` methods are what's unit tested directly against
/// `MockStorage`, since `openstack_keystone_core::tests::get_mocked_state`
/// does not expose a way to inject a storage backend into `ServiceState`.
#[derive(Default)]
pub struct RaftOauth2SessionBackend {}

impl RaftOauth2SessionBackend {
    fn storage<'a>(
        &self,
        state: &'a ServiceState,
    ) -> Result<&'a dyn StorageApi, Oauth2SessionProviderError> {
        state
            .storage
            .as_deref()
            .ok_or(Oauth2SessionProviderError::RaftNotAvailable)
    }

    async fn create_pre_auth_session_impl(
        &self,
        storage: &dyn StorageApi,
        data: PreAuthSessionCreate,
    ) -> Result<PreAuthSession, Oauth2SessionProviderError> {
        let record = PreAuthSession {
            session_id: data.session_id.clone(),
            domain_id: data.domain_id,
            client_id: data.client_id,
            redirect_uri: data.redirect_uri,
            scope: data.scope,
            state: data.state,
            code_challenge: data.code_challenge,
            code_challenge_method: data.code_challenge_method,
            nonce: data.nonce,
            server_side_session_secret: data.server_side_session_secret,
            user_id: None,
            auth_time: None,
            consent_granted: None,
            created_at: data.created_at,
            expires_at: data.expires_at,
        };
        put(storage, session_key(&data.session_id), &record)
            .await
            .map_err(store_err)?;
        Ok(record)
    }

    async fn get_pre_auth_session_impl(
        &self,
        storage: &dyn StorageApi,
        session_id: &str,
    ) -> Result<Option<PreAuthSession>, Oauth2SessionProviderError> {
        get(storage, &session_key(session_id))
            .await
            .map_err(store_err)
    }

    async fn mark_pre_auth_session_authenticated_impl(
        &self,
        storage: &dyn StorageApi,
        session_id: &str,
        user_id: &str,
        auth_time: i64,
    ) -> Result<PreAuthSession, Oauth2SessionProviderError> {
        let mut record: PreAuthSession = get(storage, &session_key(session_id))
            .await
            .map_err(store_err)?
            .ok_or_else(|| Oauth2SessionProviderError::NotFound(session_id.to_string()))?;
        record.user_id = Some(user_id.to_string());
        record.auth_time = Some(auth_time);
        put(storage, session_key(session_id), &record)
            .await
            .map_err(store_err)?;
        Ok(record)
    }

    async fn mark_pre_auth_session_consent_impl(
        &self,
        storage: &dyn StorageApi,
        session_id: &str,
        granted: bool,
    ) -> Result<PreAuthSession, Oauth2SessionProviderError> {
        let mut record: PreAuthSession = get(storage, &session_key(session_id))
            .await
            .map_err(store_err)?
            .ok_or_else(|| Oauth2SessionProviderError::NotFound(session_id.to_string()))?;
        record.consent_granted = Some(granted);
        put(storage, session_key(session_id), &record)
            .await
            .map_err(store_err)?;
        Ok(record)
    }

    async fn delete_pre_auth_session_impl(
        &self,
        storage: &dyn StorageApi,
        session_id: &str,
    ) -> Result<(), Oauth2SessionProviderError> {
        storage
            .remove(session_key(session_id), None)
            .await
            .map_err(store_err)?;
        Ok(())
    }

    async fn create_authorization_code_impl(
        &self,
        storage: &dyn StorageApi,
        data: AuthorizationCodeCreate,
    ) -> Result<AuthorizationCode, Oauth2SessionProviderError> {
        let record = AuthorizationCode {
            code: data.code.clone(),
            domain_id: data.domain_id,
            client_id: data.client_id,
            user_id: data.user_id,
            redirect_uri: data.redirect_uri,
            code_challenge: data.code_challenge,
            code_challenge_method: data.code_challenge_method,
            scope: data.scope,
            nonce: data.nonce,
            auth_time: data.auth_time,
            amr: data.amr,
            created_at: data.created_at,
            expires_at: data.expires_at,
        };
        put(storage, code_key(&data.code), &record)
            .await
            .map_err(store_err)?;
        Ok(record)
    }

    async fn take_authorization_code_impl(
        &self,
        storage: &dyn StorageApi,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, Oauth2SessionProviderError> {
        let key = code_key(code);
        // Get-then-remove, not a single atomic primitive: the `StorageApi`
        // surface has no CAS-on-read operation to build true atomicity on.
        // A concurrent double-redemption within the same instant could in
        // theory observe `Some` twice; accepted as a narrow, low-value
        // attack window (the presented code is already scoped to the exact
        // PKCE verifier and redirect_uri, so a race window here does not
        // itself grant anything beyond what the legitimate holder of the
        // code could already do once).
        let existing: Option<AuthorizationCode> = get(storage, &key).await.map_err(store_err)?;
        if existing.is_some() {
            storage.remove(key, None).await.map_err(store_err)?;
        }
        Ok(existing)
    }

    async fn create_refresh_token_impl(
        &self,
        storage: &dyn StorageApi,
        data: RefreshTokenCreate,
    ) -> Result<RefreshToken, Oauth2SessionProviderError> {
        let record = RefreshToken {
            token_id: data.token_id.clone(),
            family_id: data.family_id.clone(),
            parent_token_id: data.parent_token_id,
            domain_id: data.domain_id,
            client_id: data.client_id,
            user_id: data.user_id,
            scope: data.scope,
            issued_at: data.issued_at,
            spent_at: None,
            expires_at: data.expires_at,
        };
        put(storage, refresh_key(&data.token_id), &record)
            .await
            .map_err(store_err)?;
        put(
            storage,
            family_idx_key(&data.family_id, &data.token_id),
            &data.token_id,
        )
        .await
        .map_err(store_err)?;
        Ok(record)
    }

    async fn get_refresh_token_impl(
        &self,
        storage: &dyn StorageApi,
        token_id: &str,
    ) -> Result<Option<RefreshToken>, Oauth2SessionProviderError> {
        get(storage, &refresh_key(token_id))
            .await
            .map_err(store_err)
    }

    async fn mark_refresh_token_spent_impl(
        &self,
        storage: &dyn StorageApi,
        token_id: &str,
        spent_at: i64,
    ) -> Result<(), Oauth2SessionProviderError> {
        let mut record: RefreshToken = get(storage, &refresh_key(token_id))
            .await
            .map_err(store_err)?
            .ok_or_else(|| Oauth2SessionProviderError::NotFound(token_id.to_string()))?;
        record.spent_at = Some(spent_at);
        put(storage, refresh_key(token_id), &record)
            .await
            .map_err(store_err)?;
        Ok(())
    }

    async fn list_refresh_token_family_impl(
        &self,
        storage: &dyn StorageApi,
        family_id: &str,
    ) -> Result<Vec<RefreshToken>, Oauth2SessionProviderError> {
        let prefix = family_idx_prefix(family_id);
        let entries = storage
            .prefix(prefix.as_bytes(), None)
            .await
            .map_err(store_err)?;
        let mut out = Vec::new();
        for (_key, envelope) in entries {
            let typed: StoreDataEnvelope<String> = envelope.try_deserialize().map_err(store_err)?;
            if let Some(token) = get::<RefreshToken>(storage, &refresh_key(&typed.data))
                .await
                .map_err(store_err)?
            {
                out.push(token);
            }
        }
        out.sort_by_key(|t| t.issued_at);
        Ok(out)
    }

    async fn revoke_refresh_token_family_impl(
        &self,
        storage: &dyn StorageApi,
        family_id: &str,
    ) -> Result<(), Oauth2SessionProviderError> {
        let members = self
            .list_refresh_token_family_impl(storage, family_id)
            .await?;
        for member in members {
            storage
                .remove(refresh_key(&member.token_id), None)
                .await
                .map_err(store_err)?;
            storage
                .remove(family_idx_key(family_id, &member.token_id), None)
                .await
                .map_err(store_err)?;
        }
        Ok(())
    }

    async fn create_device_code_grant_impl(
        &self,
        storage: &dyn StorageApi,
        data: DeviceCodeGrantCreate,
    ) -> Result<DeviceCodeGrant, Oauth2SessionProviderError> {
        let record = DeviceCodeGrant {
            device_code: data.device_code.clone(),
            user_code: data.user_code.clone(),
            domain_id: data.domain_id,
            client_id: data.client_id,
            scope: data.scope,
            status: DeviceGrantStatus::Pending,
            user_id: None,
            auth_time: None,
            amr: Vec::new(),
            nonce: None,
            server_side_session_secret: data.server_side_session_secret,
            last_polled_at: None,
            created_at: data.created_at,
            expires_at: data.expires_at,
        };
        put(storage, device_code_key(&data.device_code), &record)
            .await
            .map_err(store_err)?;
        put(
            storage,
            device_user_code_key(&data.user_code),
            &data.device_code,
        )
        .await
        .map_err(store_err)?;
        Ok(record)
    }

    async fn get_device_code_grant_impl(
        &self,
        storage: &dyn StorageApi,
        device_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Oauth2SessionProviderError> {
        get(storage, &device_code_key(device_code))
            .await
            .map_err(store_err)
    }

    async fn get_device_code_grant_by_user_code_impl(
        &self,
        storage: &dyn StorageApi,
        user_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Oauth2SessionProviderError> {
        let Some(device_code) = get::<String>(storage, &device_user_code_key(user_code))
            .await
            .map_err(store_err)?
        else {
            return Ok(None);
        };
        self.get_device_code_grant_impl(storage, &device_code).await
    }

    async fn mark_device_code_grant_authenticated_impl(
        &self,
        storage: &dyn StorageApi,
        device_code: &str,
        user_id: &str,
        auth_time: i64,
        amr: Vec<String>,
    ) -> Result<DeviceCodeGrant, Oauth2SessionProviderError> {
        let mut record: DeviceCodeGrant = get(storage, &device_code_key(device_code))
            .await
            .map_err(store_err)?
            .ok_or_else(|| Oauth2SessionProviderError::NotFound(device_code.to_string()))?;
        record.user_id = Some(user_id.to_string());
        record.auth_time = Some(auth_time);
        record.amr = amr;
        put(storage, device_code_key(device_code), &record)
            .await
            .map_err(store_err)?;
        Ok(record)
    }

    async fn mark_device_code_grant_decision_impl(
        &self,
        storage: &dyn StorageApi,
        device_code: &str,
        status: DeviceGrantStatus,
    ) -> Result<DeviceCodeGrant, Oauth2SessionProviderError> {
        let mut record: DeviceCodeGrant = get(storage, &device_code_key(device_code))
            .await
            .map_err(store_err)?
            .ok_or_else(|| Oauth2SessionProviderError::NotFound(device_code.to_string()))?;
        record.status = status;
        put(storage, device_code_key(device_code), &record)
            .await
            .map_err(store_err)?;
        Ok(record)
    }

    async fn mark_device_code_grant_polled_impl(
        &self,
        storage: &dyn StorageApi,
        device_code: &str,
        polled_at: i64,
    ) -> Result<(), Oauth2SessionProviderError> {
        let mut record: DeviceCodeGrant = get(storage, &device_code_key(device_code))
            .await
            .map_err(store_err)?
            .ok_or_else(|| Oauth2SessionProviderError::NotFound(device_code.to_string()))?;
        record.last_polled_at = Some(polled_at);
        put(storage, device_code_key(device_code), &record)
            .await
            .map_err(store_err)
    }

    async fn take_device_code_grant_impl(
        &self,
        storage: &dyn StorageApi,
        device_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Oauth2SessionProviderError> {
        let existing: Option<DeviceCodeGrant> = get(storage, &device_code_key(device_code))
            .await
            .map_err(store_err)?;
        if let Some(record) = &existing {
            storage
                .remove(device_code_key(device_code), None)
                .await
                .map_err(store_err)?;
            storage
                .remove(device_user_code_key(&record.user_code), None)
                .await
                .map_err(store_err)?;
        }
        Ok(existing)
    }
}

#[async_trait]
impl Oauth2SessionBackend for RaftOauth2SessionBackend {
    async fn create_pre_auth_session(
        &self,
        state: &ServiceState,
        data: PreAuthSessionCreate,
    ) -> Result<PreAuthSession, Oauth2SessionProviderError> {
        self.create_pre_auth_session_impl(self.storage(state)?, data)
            .await
    }

    async fn get_pre_auth_session(
        &self,
        state: &ServiceState,
        session_id: &str,
    ) -> Result<Option<PreAuthSession>, Oauth2SessionProviderError> {
        self.get_pre_auth_session_impl(self.storage(state)?, session_id)
            .await
    }

    async fn mark_pre_auth_session_authenticated(
        &self,
        state: &ServiceState,
        session_id: &str,
        user_id: &str,
        auth_time: i64,
    ) -> Result<PreAuthSession, Oauth2SessionProviderError> {
        self.mark_pre_auth_session_authenticated_impl(
            self.storage(state)?,
            session_id,
            user_id,
            auth_time,
        )
        .await
    }

    async fn mark_pre_auth_session_consent(
        &self,
        state: &ServiceState,
        session_id: &str,
        granted: bool,
    ) -> Result<PreAuthSession, Oauth2SessionProviderError> {
        self.mark_pre_auth_session_consent_impl(self.storage(state)?, session_id, granted)
            .await
    }

    async fn delete_pre_auth_session(
        &self,
        state: &ServiceState,
        session_id: &str,
    ) -> Result<(), Oauth2SessionProviderError> {
        self.delete_pre_auth_session_impl(self.storage(state)?, session_id)
            .await
    }

    async fn create_authorization_code(
        &self,
        state: &ServiceState,
        data: AuthorizationCodeCreate,
    ) -> Result<AuthorizationCode, Oauth2SessionProviderError> {
        self.create_authorization_code_impl(self.storage(state)?, data)
            .await
    }

    async fn take_authorization_code(
        &self,
        state: &ServiceState,
        code: &str,
    ) -> Result<Option<AuthorizationCode>, Oauth2SessionProviderError> {
        self.take_authorization_code_impl(self.storage(state)?, code)
            .await
    }

    async fn create_refresh_token(
        &self,
        state: &ServiceState,
        data: RefreshTokenCreate,
    ) -> Result<RefreshToken, Oauth2SessionProviderError> {
        self.create_refresh_token_impl(self.storage(state)?, data)
            .await
    }

    async fn get_refresh_token(
        &self,
        state: &ServiceState,
        token_id: &str,
    ) -> Result<Option<RefreshToken>, Oauth2SessionProviderError> {
        self.get_refresh_token_impl(self.storage(state)?, token_id)
            .await
    }

    async fn mark_refresh_token_spent(
        &self,
        state: &ServiceState,
        token_id: &str,
        spent_at: i64,
    ) -> Result<(), Oauth2SessionProviderError> {
        self.mark_refresh_token_spent_impl(self.storage(state)?, token_id, spent_at)
            .await
    }

    async fn list_refresh_token_family(
        &self,
        state: &ServiceState,
        family_id: &str,
    ) -> Result<Vec<RefreshToken>, Oauth2SessionProviderError> {
        self.list_refresh_token_family_impl(self.storage(state)?, family_id)
            .await
    }

    async fn revoke_refresh_token_family(
        &self,
        state: &ServiceState,
        family_id: &str,
    ) -> Result<(), Oauth2SessionProviderError> {
        self.revoke_refresh_token_family_impl(self.storage(state)?, family_id)
            .await
    }

    async fn create_device_code_grant(
        &self,
        state: &ServiceState,
        data: DeviceCodeGrantCreate,
    ) -> Result<DeviceCodeGrant, Oauth2SessionProviderError> {
        self.create_device_code_grant_impl(self.storage(state)?, data)
            .await
    }

    async fn get_device_code_grant(
        &self,
        state: &ServiceState,
        device_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Oauth2SessionProviderError> {
        self.get_device_code_grant_impl(self.storage(state)?, device_code)
            .await
    }

    async fn get_device_code_grant_by_user_code(
        &self,
        state: &ServiceState,
        user_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Oauth2SessionProviderError> {
        self.get_device_code_grant_by_user_code_impl(self.storage(state)?, user_code)
            .await
    }

    async fn mark_device_code_grant_authenticated(
        &self,
        state: &ServiceState,
        device_code: &str,
        user_id: &str,
        auth_time: i64,
        amr: Vec<String>,
    ) -> Result<DeviceCodeGrant, Oauth2SessionProviderError> {
        self.mark_device_code_grant_authenticated_impl(
            self.storage(state)?,
            device_code,
            user_id,
            auth_time,
            amr,
        )
        .await
    }

    async fn mark_device_code_grant_decision(
        &self,
        state: &ServiceState,
        device_code: &str,
        status: DeviceGrantStatus,
    ) -> Result<DeviceCodeGrant, Oauth2SessionProviderError> {
        self.mark_device_code_grant_decision_impl(self.storage(state)?, device_code, status)
            .await
    }

    async fn mark_device_code_grant_polled(
        &self,
        state: &ServiceState,
        device_code: &str,
        polled_at: i64,
    ) -> Result<(), Oauth2SessionProviderError> {
        self.mark_device_code_grant_polled_impl(self.storage(state)?, device_code, polled_at)
            .await
    }

    async fn take_device_code_grant(
        &self,
        state: &ServiceState,
        device_code: &str,
    ) -> Result<Option<DeviceCodeGrant>, Oauth2SessionProviderError> {
        self.take_device_code_grant_impl(self.storage(state)?, device_code)
            .await
    }
}

/// Linkage anchor — see ADR-0018.
#[allow(dead_code)]
pub fn anchor() {}

#[cfg(test)]
mod tests {
    use super::*;
    use openstack_keystone_distributed_storage::mock::MockStorage;

    fn sample_session_create() -> PreAuthSessionCreate {
        PreAuthSessionCreate {
            session_id: "session-1".to_string(),
            domain_id: "domain-1".to_string(),
            client_id: "client-1".to_string(),
            redirect_uri: "https://rp.example/cb".to_string(),
            scope: vec!["openid".to_string()],
            state: "state-1".to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: "S256".to_string(),
            nonce: None,
            server_side_session_secret: "secret".to_string(),
            created_at: 1000,
            expires_at: 2000,
        }
    }

    #[tokio::test]
    async fn test_pre_auth_session_create_get_roundtrip() {
        let backend = RaftOauth2SessionBackend::default();
        let storage = MockStorage::default();

        let created = backend
            .create_pre_auth_session_impl(&storage, sample_session_create())
            .await
            .unwrap();
        let fetched = backend
            .get_pre_auth_session_impl(&storage, "session-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(created, fetched);
        assert!(fetched.user_id.is_none());
    }

    #[tokio::test]
    async fn test_mark_pre_auth_session_authenticated_and_consent() {
        let backend = RaftOauth2SessionBackend::default();
        let storage = MockStorage::default();
        backend
            .create_pre_auth_session_impl(&storage, sample_session_create())
            .await
            .unwrap();

        let authenticated = backend
            .mark_pre_auth_session_authenticated_impl(&storage, "session-1", "user-1", 1500)
            .await
            .unwrap();
        assert_eq!(authenticated.user_id.as_deref(), Some("user-1"));
        assert_eq!(authenticated.auth_time, Some(1500));

        let consented = backend
            .mark_pre_auth_session_consent_impl(&storage, "session-1", true)
            .await
            .unwrap();
        assert_eq!(consented.consent_granted, Some(true));
    }

    #[tokio::test]
    async fn test_delete_pre_auth_session_removes_it() {
        let backend = RaftOauth2SessionBackend::default();
        let storage = MockStorage::default();
        backend
            .create_pre_auth_session_impl(&storage, sample_session_create())
            .await
            .unwrap();

        backend
            .delete_pre_auth_session_impl(&storage, "session-1")
            .await
            .unwrap();
        let fetched = backend
            .get_pre_auth_session_impl(&storage, "session-1")
            .await
            .unwrap();
        assert!(fetched.is_none());
    }

    fn sample_code_create() -> AuthorizationCodeCreate {
        AuthorizationCodeCreate {
            code: "code-1".to_string(),
            domain_id: "domain-1".to_string(),
            client_id: "client-1".to_string(),
            user_id: "user-1".to_string(),
            redirect_uri: "https://rp.example/cb".to_string(),
            code_challenge: "challenge".to_string(),
            code_challenge_method: "S256".to_string(),
            scope: vec!["openid".to_string()],
            nonce: None,
            auth_time: 1000,
            amr: vec!["pwd".to_string()],
            created_at: 1000,
            expires_at: 1060,
        }
    }

    #[tokio::test]
    async fn test_authorization_code_is_single_use() {
        let backend = RaftOauth2SessionBackend::default();
        let storage = MockStorage::default();
        backend
            .create_authorization_code_impl(&storage, sample_code_create())
            .await
            .unwrap();

        let first = backend
            .take_authorization_code_impl(&storage, "code-1")
            .await
            .unwrap();
        assert!(first.is_some());

        let second = backend
            .take_authorization_code_impl(&storage, "code-1")
            .await
            .unwrap();
        assert!(second.is_none());
    }

    fn sample_refresh_create(token_id: &str, family_id: &str) -> RefreshTokenCreate {
        RefreshTokenCreate {
            token_id: token_id.to_string(),
            family_id: family_id.to_string(),
            parent_token_id: None,
            domain_id: "domain-1".to_string(),
            client_id: "client-1".to_string(),
            user_id: "user-1".to_string(),
            scope: vec!["openid".to_string()],
            issued_at: 1000,
            expires_at: 1000 + 2_592_000,
        }
    }

    #[tokio::test]
    async fn test_refresh_token_create_get_and_mark_spent() {
        let backend = RaftOauth2SessionBackend::default();
        let storage = MockStorage::default();
        backend
            .create_refresh_token_impl(&storage, sample_refresh_create("token-1", "family-1"))
            .await
            .unwrap();

        let fetched = backend
            .get_refresh_token_impl(&storage, "token-1")
            .await
            .unwrap()
            .unwrap();
        assert!(fetched.spent_at.is_none());

        backend
            .mark_refresh_token_spent_impl(&storage, "token-1", 2000)
            .await
            .unwrap();
        let spent = backend
            .get_refresh_token_impl(&storage, "token-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(spent.spent_at, Some(2000));
    }

    #[tokio::test]
    async fn test_list_and_revoke_refresh_token_family() {
        let backend = RaftOauth2SessionBackend::default();
        let storage = MockStorage::default();
        backend
            .create_refresh_token_impl(&storage, sample_refresh_create("token-1", "family-1"))
            .await
            .unwrap();
        let mut child = sample_refresh_create("token-2", "family-1");
        child.parent_token_id = Some("token-1".to_string());
        child.issued_at = 2000;
        backend
            .create_refresh_token_impl(&storage, child)
            .await
            .unwrap();
        // Different family, must not be affected.
        backend
            .create_refresh_token_impl(&storage, sample_refresh_create("token-3", "family-2"))
            .await
            .unwrap();

        let family = backend
            .list_refresh_token_family_impl(&storage, "family-1")
            .await
            .unwrap();
        assert_eq!(family.len(), 2);
        assert_eq!(family[0].token_id, "token-1");
        assert_eq!(family[1].token_id, "token-2");

        backend
            .revoke_refresh_token_family_impl(&storage, "family-1")
            .await
            .unwrap();
        assert!(
            backend
                .get_refresh_token_impl(&storage, "token-1")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            backend
                .get_refresh_token_impl(&storage, "token-2")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            backend
                .get_refresh_token_impl(&storage, "token-3")
                .await
                .unwrap()
                .is_some()
        );
    }

    fn sample_device_grant_create() -> DeviceCodeGrantCreate {
        DeviceCodeGrantCreate {
            device_code: "device-code-1".to_string(),
            user_code: "ABCD-EFGH".to_string(),
            domain_id: "domain-1".to_string(),
            client_id: "client-1".to_string(),
            scope: vec!["openid".to_string()],
            server_side_session_secret: "secret".to_string(),
            created_at: 1000,
            expires_at: 1600,
        }
    }

    #[tokio::test]
    async fn test_device_code_grant_create_and_lookup_by_both_codes() {
        let backend = RaftOauth2SessionBackend::default();
        let storage = MockStorage::default();

        let created = backend
            .create_device_code_grant_impl(&storage, sample_device_grant_create())
            .await
            .unwrap();
        assert_eq!(created.status, DeviceGrantStatus::Pending);

        let by_device_code = backend
            .get_device_code_grant_impl(&storage, "device-code-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_device_code, created);

        let by_user_code = backend
            .get_device_code_grant_by_user_code_impl(&storage, "ABCD-EFGH")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(by_user_code, created);
    }

    #[tokio::test]
    async fn test_device_code_grant_authenticate_and_decide() {
        let backend = RaftOauth2SessionBackend::default();
        let storage = MockStorage::default();
        backend
            .create_device_code_grant_impl(&storage, sample_device_grant_create())
            .await
            .unwrap();

        let authenticated = backend
            .mark_device_code_grant_authenticated_impl(
                &storage,
                "device-code-1",
                "user-1",
                1500,
                vec!["pwd".to_string()],
            )
            .await
            .unwrap();
        assert_eq!(authenticated.user_id.as_deref(), Some("user-1"));

        let decided = backend
            .mark_device_code_grant_decision_impl(
                &storage,
                "device-code-1",
                DeviceGrantStatus::Authorized,
            )
            .await
            .unwrap();
        assert_eq!(decided.status, DeviceGrantStatus::Authorized);
    }

    #[tokio::test]
    async fn test_device_code_grant_poll_stamp_and_single_use_take() {
        let backend = RaftOauth2SessionBackend::default();
        let storage = MockStorage::default();
        backend
            .create_device_code_grant_impl(&storage, sample_device_grant_create())
            .await
            .unwrap();

        backend
            .mark_device_code_grant_polled_impl(&storage, "device-code-1", 1100)
            .await
            .unwrap();
        let polled = backend
            .get_device_code_grant_impl(&storage, "device-code-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(polled.last_polled_at, Some(1100));

        let taken = backend
            .take_device_code_grant_impl(&storage, "device-code-1")
            .await
            .unwrap();
        assert!(taken.is_some());

        // Single-use: the primary record and the user_code index are both
        // gone after the first take.
        assert!(
            backend
                .get_device_code_grant_impl(&storage, "device-code-1")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            backend
                .get_device_code_grant_by_user_code_impl(&storage, "ABCD-EFGH")
                .await
                .unwrap()
                .is_none()
        );
    }
}
