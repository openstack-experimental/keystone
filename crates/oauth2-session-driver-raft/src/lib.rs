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
//! - `oauth2:device_code:v1:<device_code>` / `oauth2:device_user_code:v1:<user_code>`
//!   -- an RFC 8628 device authorization grant, addressable by either code.
//!
//! Plus secondary indexes, written atomically (`StorageApi::transaction`)
//! alongside the primary record they describe, keeping revocation and
//! expiry sweeps a prefix scan over just their own index keyspace instead
//! of a reverse scan over every oauth2 record in the store. Note this is
//! still a scan of the whole index (`StorageApi` has no range-bounded
//! query, only prefix), not a scan bounded by `limit`/`before` -- see
//! `list_expired_impl`.
//!
//! - `oauth2:refresh_family_idx:v1:<family_id>:<token_id>` -- family-wide
//!   fan-out (list/revoke) over a refresh token rotation family.
//! - `oauth2:refresh_user_idx:v1:<domain_id>:<user_id>:<family_id>` /
//!   `oauth2:refresh_client_idx:v1:<client_id>:<family_id>` /
//!   `oauth2:refresh_domain_idx:v1:<domain_id>:<family_id>` -- pure
//!   index-keyspace keys (no value) mapping a user/client/domain to the
//!   refresh token families it owns.
//! - `oauth2:expiry_idx:v1:<expires_at zero-padded i64>:<kind>:<primary_key>`
//!   -- orders every session/code/refresh/device record by `expires_at`
//!   for expiry sweeps. Rewritten on refresh rotation: the spent token's
//!   entry is removed (`mark_refresh_token_spent_impl`) and the rotated
//!   child gets its own fresh entry (`create_refresh_token_impl`).
use async_trait::async_trait;
use serde::Serialize;
use serde::de::DeserializeOwned;

use std::sync::Arc;

use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::oauth2_session::Oauth2SessionProviderError;
use openstack_keystone_core::oauth2_session::backend::Oauth2SessionBackend;
use openstack_keystone_core::plugin_manager::BackendRegistration;
use openstack_keystone_core_types::oauth2_session::*;
use openstack_keystone_distributed_storage::{
    ApiStoreError as StoreError, Metadata, Mutation, StorageApi, StoreDataEnvelope,
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

/// Secondary index keyed by (domain_id, user_id) -- lists refresh token
/// families owned by a user without a reverse scan over every refresh
/// token in the store. Pure index-keyspace key (no value): the family id
/// is fully recoverable from the key itself.
fn refresh_user_idx_key(domain_id: &str, user_id: &str, family_id: &str) -> String {
    format!("oauth2:refresh_user_idx:v1:{domain_id}:{user_id}:{family_id}")
}

fn refresh_user_idx_prefix(domain_id: &str, user_id: &str) -> String {
    format!("oauth2:refresh_user_idx:v1:{domain_id}:{user_id}:")
}

/// Secondary index keyed by `client_id` -- lists refresh token families
/// issued to a client (e.g. to revoke everything on client deregistration).
fn refresh_client_idx_key(client_id: &str, family_id: &str) -> String {
    format!("oauth2:refresh_client_idx:v1:{client_id}:{family_id}")
}

fn refresh_client_idx_prefix(client_id: &str) -> String {
    format!("oauth2:refresh_client_idx:v1:{client_id}:")
}

/// Secondary index keyed by `domain_id` -- lists refresh token families
/// within a domain (domain-wide revocation), kept explicit rather than
/// derived from the user index prefix.
fn refresh_domain_idx_key(domain_id: &str, family_id: &str) -> String {
    format!("oauth2:refresh_domain_idx:v1:{domain_id}:{family_id}")
}

fn refresh_domain_idx_prefix(domain_id: &str) -> String {
    format!("oauth2:refresh_domain_idx:v1:{domain_id}:")
}

/// Fixed width of the zero-padded `expires_at` component of an expiry
/// index key -- wide enough for any non-negative `i64` (max 19 digits),
/// so lexicographic key order matches numeric `expires_at` order.
const EXPIRY_TS_WIDTH: usize = 20;

const EXPIRY_IDX_PREFIX: &str = "oauth2:expiry_idx:v1:";

/// Secondary index ordering every session/code/refresh/device record by
/// `expires_at`, so expiry sweeps scan only this index instead of doing a
/// reverse scan over every oauth2 record in the store. `list_expired_impl`
/// still reads the whole index per call (`StorageApi::prefix_index` has no
/// range-bounded query) and filters/breaks client-side on `before`/`limit`.
/// `kind` distinguishes the record type sharing this index (`"session"`,
/// `"code"`, `"refresh"`, `"device"`).
fn expiry_idx_key(expires_at: i64, kind: &str, primary_key: &str) -> String {
    format!("{EXPIRY_IDX_PREFIX}{expires_at:0>EXPIRY_TS_WIDTH$}:{kind}:{primary_key}")
}

/// Parses an expiry index key back into `(expires_at, kind, primary_key)`.
fn parse_expiry_idx_key(key: &str) -> Option<(i64, &str, &str)> {
    let rest = key.strip_prefix(EXPIRY_IDX_PREFIX)?;
    let (ts, rest) = rest.split_at_checked(EXPIRY_TS_WIDTH)?;
    let rest = rest.strip_prefix(':')?;
    let (kind, primary_key) = rest.split_once(':')?;
    let expires_at: i64 = ts.parse().ok()?;
    Some((expires_at, kind, primary_key))
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
        let mutations = vec![
            Mutation::set(
                session_key(&data.session_id),
                &record,
                Metadata::new(),
                None::<&str>,
                None,
            )
            .map_err(store_err)?,
            Mutation::set_index(expiry_idx_key(data.expires_at, "session", &data.session_id)),
        ];
        storage.transaction(mutations).await.map_err(store_err)?;
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
        let existing: Option<PreAuthSession> = get(storage, &session_key(session_id))
            .await
            .map_err(store_err)?;
        let mut mutations = vec![Mutation::remove(
            session_key(session_id),
            None::<&str>,
            None,
        )];
        if let Some(record) = existing {
            mutations.push(Mutation::remove_index(expiry_idx_key(
                record.expires_at,
                "session",
                session_id,
            )));
        }
        storage.transaction(mutations).await.map_err(store_err)?;
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
        let mutations = vec![
            Mutation::set(
                code_key(&data.code),
                &record,
                Metadata::new(),
                None::<&str>,
                None,
            )
            .map_err(store_err)?,
            Mutation::set_index(expiry_idx_key(data.expires_at, "code", &data.code)),
        ];
        storage.transaction(mutations).await.map_err(store_err)?;
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
        if let Some(record) = &existing {
            let mutations = vec![
                Mutation::remove(key, None::<&str>, None),
                Mutation::remove_index(expiry_idx_key(record.expires_at, "code", code)),
            ];
            storage.transaction(mutations).await.map_err(store_err)?;
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
        let mutations = vec![
            Mutation::set(
                refresh_key(&data.token_id),
                &record,
                Metadata::new(),
                None::<&str>,
                None,
            )
            .map_err(store_err)?,
            Mutation::set(
                family_idx_key(&data.family_id, &data.token_id),
                &data.token_id,
                Metadata::new(),
                None::<&str>,
                None,
            )
            .map_err(store_err)?,
            Mutation::set_index(refresh_user_idx_key(
                &record.domain_id,
                &record.user_id,
                &record.family_id,
            )),
            Mutation::set_index(refresh_client_idx_key(&record.client_id, &record.family_id)),
            Mutation::set_index(refresh_domain_idx_key(&record.domain_id, &record.family_id)),
            Mutation::set_index(expiry_idx_key(
                record.expires_at,
                "refresh",
                &record.token_id,
            )),
        ];
        storage.transaction(mutations).await.map_err(store_err)?;
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
        // Rewrite the expiry entry on rotation: the spent token no longer
        // needs to be tracked for expiry sweeps (the rotated child gets
        // its own fresh entry via `create_refresh_token_impl`).
        let mutations = vec![
            Mutation::set(
                refresh_key(token_id),
                &record,
                Metadata::new(),
                None::<&str>,
                None,
            )
            .map_err(store_err)?,
            Mutation::remove_index(expiry_idx_key(record.expires_at, "refresh", token_id)),
        ];
        storage.transaction(mutations).await.map_err(store_err)?;
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
        if members.is_empty() {
            return Ok(());
        }
        let mut mutations = Vec::new();
        for member in &members {
            mutations.push(Mutation::remove(
                refresh_key(&member.token_id),
                None::<&str>,
                None,
            ));
            mutations.push(Mutation::remove(
                family_idx_key(family_id, &member.token_id),
                None::<&str>,
                None,
            ));
            // Spent members already had their expiry-index entry removed by
            // `mark_refresh_token_spent_impl` on rotation -- only unspent
            // members still have one to clean up.
            if member.spent_at.is_none() {
                mutations.push(Mutation::remove_index(expiry_idx_key(
                    member.expires_at,
                    "refresh",
                    &member.token_id,
                )));
            }
        }
        // The user/client/domain indexes are keyed by family_id, not by
        // individual token_id, so every member shares the same entry --
        // remove it once, using any member's (constant across rotation)
        // domain/client/user ids.
        if let Some(first) = members.first() {
            mutations.push(Mutation::remove_index(refresh_user_idx_key(
                &first.domain_id,
                &first.user_id,
                family_id,
            )));
            mutations.push(Mutation::remove_index(refresh_client_idx_key(
                &first.client_id,
                family_id,
            )));
            mutations.push(Mutation::remove_index(refresh_domain_idx_key(
                &first.domain_id,
                family_id,
            )));
        }
        storage.transaction(mutations).await.map_err(store_err)?;
        Ok(())
    }

    async fn list_refresh_families_by_user_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
        user_id: &str,
    ) -> Result<Vec<String>, Oauth2SessionProviderError> {
        let prefix = refresh_user_idx_prefix(domain_id, user_id);
        let keys = storage
            .prefix_index(prefix.as_bytes())
            .await
            .map_err(store_err)?;
        Ok(keys
            .into_iter()
            .map(|k| k[prefix.len()..].to_string())
            .collect())
    }

    async fn list_refresh_families_by_client_impl(
        &self,
        storage: &dyn StorageApi,
        client_id: &str,
    ) -> Result<Vec<String>, Oauth2SessionProviderError> {
        let prefix = refresh_client_idx_prefix(client_id);
        let keys = storage
            .prefix_index(prefix.as_bytes())
            .await
            .map_err(store_err)?;
        Ok(keys
            .into_iter()
            .map(|k| k[prefix.len()..].to_string())
            .collect())
    }

    async fn list_refresh_families_by_domain_impl(
        &self,
        storage: &dyn StorageApi,
        domain_id: &str,
    ) -> Result<Vec<String>, Oauth2SessionProviderError> {
        let prefix = refresh_domain_idx_prefix(domain_id);
        let keys = storage
            .prefix_index(prefix.as_bytes())
            .await
            .map_err(store_err)?;
        Ok(keys
            .into_iter()
            .map(|k| k[prefix.len()..].to_string())
            .collect())
    }

    async fn list_expired_impl(
        &self,
        storage: &dyn StorageApi,
        before: i64,
        limit: usize,
    ) -> Result<Vec<(String, String)>, Oauth2SessionProviderError> {
        // `StorageApi::prefix_index` has no range-bounded query, only a
        // prefix match, so this reads the entire expiry index into memory
        // on every call regardless of `before`/`limit` -- the loop below
        // only bounds how many entries end up in `out`, not how many are
        // fetched. Fine at oauth2-session scale (bounded by live
        // sessions/codes/refresh tokens/device grants); revisit if
        // `StorageApi` grows a real range scan.
        let keys = storage
            .prefix_index(EXPIRY_IDX_PREFIX.as_bytes())
            .await
            .map_err(store_err)?;
        let mut out = Vec::new();
        for key in &keys {
            if out.len() >= limit {
                break;
            }
            let Some((expires_at, kind, primary_key)) = parse_expiry_idx_key(key) else {
                continue;
            };
            if expires_at >= before {
                // `prefix_index` returns keys in lexicographic order, which
                // matches numeric `expires_at` order for the fixed-width
                // zero-padded timestamp -- everything from here on is not
                // yet expired.
                break;
            }
            out.push((kind.to_string(), primary_key.to_string()));
        }
        Ok(out)
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
        let mutations = vec![
            Mutation::set(
                device_code_key(&data.device_code),
                &record,
                Metadata::new(),
                None::<&str>,
                None,
            )
            .map_err(store_err)?,
            Mutation::set(
                device_user_code_key(&data.user_code),
                &data.device_code,
                Metadata::new(),
                None::<&str>,
                None,
            )
            .map_err(store_err)?,
            Mutation::set_index(expiry_idx_key(data.expires_at, "device", &data.device_code)),
        ];
        storage.transaction(mutations).await.map_err(store_err)?;
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
            let mutations = vec![
                Mutation::remove(device_code_key(device_code), None::<&str>, None),
                Mutation::remove(device_user_code_key(&record.user_code), None::<&str>, None),
                Mutation::remove_index(expiry_idx_key(record.expires_at, "device", device_code)),
            ];
            storage.transaction(mutations).await.map_err(store_err)?;
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

    async fn list_refresh_families_by_user(
        &self,
        state: &ServiceState,
        domain_id: &str,
        user_id: &str,
    ) -> Result<Vec<String>, Oauth2SessionProviderError> {
        self.list_refresh_families_by_user_impl(self.storage(state)?, domain_id, user_id)
            .await
    }

    async fn list_refresh_families_by_client(
        &self,
        state: &ServiceState,
        client_id: &str,
    ) -> Result<Vec<String>, Oauth2SessionProviderError> {
        self.list_refresh_families_by_client_impl(self.storage(state)?, client_id)
            .await
    }

    async fn list_refresh_families_by_domain(
        &self,
        state: &ServiceState,
        domain_id: &str,
    ) -> Result<Vec<String>, Oauth2SessionProviderError> {
        self.list_refresh_families_by_domain_impl(self.storage(state)?, domain_id)
            .await
    }

    async fn list_expired(
        &self,
        state: &ServiceState,
        before: i64,
        limit: usize,
    ) -> Result<Vec<(String, String)>, Oauth2SessionProviderError> {
        self.list_expired_impl(self.storage(state)?, before, limit)
            .await
    }
}

/// Linkage anchor — see ADR-0018.
#[allow(dead_code)]
pub fn anchor() {}

inventory::submit! {
    BackendRegistration::<dyn Oauth2SessionBackend> {
        name: "raft",
        selected: |_| true,
        build: |_cfg| Box::pin(async {
            Ok(Arc::new(RaftOauth2SessionBackend::default()) as Arc<dyn Oauth2SessionBackend>)
        }),
    }
}

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

    #[tokio::test]
    async fn test_refresh_family_indexes_round_trip() {
        let backend = RaftOauth2SessionBackend::default();
        let storage = MockStorage::default();
        backend
            .create_refresh_token_impl(&storage, sample_refresh_create("token-1", "family-1"))
            .await
            .unwrap();
        let mut other_family = sample_refresh_create("token-2", "family-2");
        other_family.client_id = "client-2".to_string();
        other_family.user_id = "user-2".to_string();
        other_family.domain_id = "domain-2".to_string();
        backend
            .create_refresh_token_impl(&storage, other_family)
            .await
            .unwrap();

        assert_eq!(
            backend
                .list_refresh_families_by_user_impl(&storage, "domain-1", "user-1")
                .await
                .unwrap(),
            vec!["family-1".to_string()]
        );
        assert_eq!(
            backend
                .list_refresh_families_by_client_impl(&storage, "client-1")
                .await
                .unwrap(),
            vec!["family-1".to_string()]
        );
        assert_eq!(
            backend
                .list_refresh_families_by_domain_impl(&storage, "domain-1")
                .await
                .unwrap(),
            vec!["family-1".to_string()]
        );
        // The second family must not show up under the first family's keys.
        assert!(
            backend
                .list_refresh_families_by_user_impl(&storage, "domain-1", "user-2")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_refresh_family_indexes_share_entry_across_rotation() {
        let backend = RaftOauth2SessionBackend::default();
        let storage = MockStorage::default();
        backend
            .create_refresh_token_impl(&storage, sample_refresh_create("token-1", "family-1"))
            .await
            .unwrap();
        let mut child = sample_refresh_create("token-2", "family-1");
        child.parent_token_id = Some("token-1".to_string());
        backend
            .create_refresh_token_impl(&storage, child)
            .await
            .unwrap();

        // Rotation within the same family must not duplicate the index
        // entry (it is keyed by family_id, not token_id).
        assert_eq!(
            backend
                .list_refresh_families_by_user_impl(&storage, "domain-1", "user-1")
                .await
                .unwrap(),
            vec!["family-1".to_string()]
        );
    }

    #[tokio::test]
    async fn test_revoke_refresh_token_family_clears_all_indexes() {
        let backend = RaftOauth2SessionBackend::default();
        let storage = MockStorage::default();
        backend
            .create_refresh_token_impl(&storage, sample_refresh_create("token-1", "family-1"))
            .await
            .unwrap();

        backend
            .revoke_refresh_token_family_impl(&storage, "family-1")
            .await
            .unwrap();

        assert!(
            backend
                .list_refresh_families_by_user_impl(&storage, "domain-1", "user-1")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            backend
                .list_refresh_families_by_client_impl(&storage, "client-1")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            backend
                .list_refresh_families_by_domain_impl(&storage, "domain-1")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            backend
                .list_expired_impl(&storage, i64::MAX, 100)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_list_expired_honours_before_and_limit_and_ordering() {
        let backend = RaftOauth2SessionBackend::default();
        let storage = MockStorage::default();
        backend
            .create_pre_auth_session_impl(&storage, sample_session_create())
            .await
            .unwrap();
        let mut code = sample_code_create();
        code.code = "code-early".to_string();
        code.expires_at = 500;
        backend
            .create_authorization_code_impl(&storage, code)
            .await
            .unwrap();
        backend
            .create_refresh_token_impl(&storage, sample_refresh_create("token-1", "family-1"))
            .await
            .unwrap();
        backend
            .create_device_code_grant_impl(&storage, sample_device_grant_create())
            .await
            .unwrap();

        // Only the two records with the lowest expires_at (500, 1600 --
        // the auth code and the device grant) precede `before = 2000`;
        // the pre-auth session (2000) and refresh token (~2.6M) don't.
        let expired = backend
            .list_expired_impl(&storage, 2000, 100)
            .await
            .unwrap();
        assert_eq!(
            expired,
            vec![
                ("code".to_string(), "code-early".to_string()),
                ("device".to_string(), "device-code-1".to_string()),
            ]
        );

        // `limit` caps the result even when more entries are expired.
        let limited = backend.list_expired_impl(&storage, 2000, 1).await.unwrap();
        assert_eq!(
            limited,
            vec![("code".to_string(), "code-early".to_string())]
        );

        // A generous `before` picks up everything, in expiry order.
        let all = backend
            .list_expired_impl(&storage, i64::MAX, 100)
            .await
            .unwrap();
        assert_eq!(
            all,
            vec![
                ("code".to_string(), "code-early".to_string()),
                ("device".to_string(), "device-code-1".to_string()),
                ("session".to_string(), "session-1".to_string()),
                ("refresh".to_string(), "token-1".to_string()),
            ]
        );
    }

    #[tokio::test]
    async fn test_take_authorization_code_removes_expiry_entry() {
        let backend = RaftOauth2SessionBackend::default();
        let storage = MockStorage::default();
        backend
            .create_authorization_code_impl(&storage, sample_code_create())
            .await
            .unwrap();

        backend
            .take_authorization_code_impl(&storage, "code-1")
            .await
            .unwrap();

        assert!(
            backend
                .list_expired_impl(&storage, i64::MAX, 100)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_delete_pre_auth_session_removes_expiry_entry() {
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

        assert!(
            backend
                .list_expired_impl(&storage, i64::MAX, 100)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_take_device_code_grant_removes_expiry_entry() {
        let backend = RaftOauth2SessionBackend::default();
        let storage = MockStorage::default();
        backend
            .create_device_code_grant_impl(&storage, sample_device_grant_create())
            .await
            .unwrap();

        backend
            .take_device_code_grant_impl(&storage, "device-code-1")
            .await
            .unwrap();

        assert!(
            backend
                .list_expired_impl(&storage, i64::MAX, 100)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn test_mark_refresh_token_spent_rewrites_expiry_entry() {
        let backend = RaftOauth2SessionBackend::default();
        let storage = MockStorage::default();
        backend
            .create_refresh_token_impl(&storage, sample_refresh_create("token-1", "family-1"))
            .await
            .unwrap();
        assert_eq!(
            backend
                .list_expired_impl(&storage, i64::MAX, 100)
                .await
                .unwrap(),
            vec![("refresh".to_string(), "token-1".to_string())]
        );

        backend
            .mark_refresh_token_spent_impl(&storage, "token-1", 2000)
            .await
            .unwrap();

        // Spent tokens drop out of the expiry sweep; the primary record is
        // untouched (still readable, `spent_at` set).
        assert!(
            backend
                .list_expired_impl(&storage, i64::MAX, 100)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            backend
                .get_refresh_token_impl(&storage, "token-1")
                .await
                .unwrap()
                .unwrap()
                .spent_at
                .is_some()
        );
    }
}
