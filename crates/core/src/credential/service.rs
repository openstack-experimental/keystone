// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! # Credentials provider (ADR 0019)
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use validator::Validate;

use openstack_keystone_config::Config;
use openstack_keystone_core_types::auth::{AuthenticationContext, ScopeInfo};
use openstack_keystone_core_types::credential::*;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};

use crate::auth::ExecutionContext;
use crate::credential::{CredentialApi, CredentialProviderError, backend::CredentialBackend};
use crate::events::AuditDispatchError;
use crate::plugin_manager::PluginManagerApi;

/// Delegation-metadata fields inside the EC2 `blob` (ADR 0019 §1). These are
/// never client-settable: they are derived server-side from the creating
/// request's own [`AuthenticationContext`] (OSSA-2026-005 / CVE-2026-33551)
/// and, once set, are carried forward untouched across updates rather than
/// requiring the caller to resupply them (CVE-2020-12691 fix scope).
const DELEGATION_BLOB_FIELDS: &[&str] = &["trust_id", "app_cred_id", "access_token_id"];

/// Stamps `trust_id`/`app_cred_id` into an EC2 credential's `blob` from the
/// *actual* authentication context of the creating request, discarding any
/// client-supplied value for these fields first.
///
/// # Security Note
///
/// Without this, an EC2 credential created while authenticated via a
/// trust or (critically, per OSSA-2026-015 / CVE-2026-33551) a *restricted*
/// application credential would be indistinguishable at `/v3/ec2tokens`
/// validation time from a directly-authenticated EC2 credential, silently
/// regaining the parent user's full, unrestricted project role set on
/// every subsequent use.
fn stamp_ec2_delegation_metadata(
    blob: &str,
    vsc: Option<&crate::auth::ValidatedSecurityContext>,
) -> Result<String, CredentialProviderError> {
    let mut blob_val: Value = serde_json::from_str(blob)
        .map_err(|e| CredentialProviderError::InvalidBlob(e.to_string()))?;
    let Value::Object(map) = &mut blob_val else {
        return Err(CredentialProviderError::InvalidBlob(
            "ec2 blob must be a JSON object".into(),
        ));
    };
    for field in DELEGATION_BLOB_FIELDS {
        map.remove(*field);
    }
    match vsc.map(|vsc| vsc.authentication_context()) {
        Some(AuthenticationContext::Trust { trust, .. }) => {
            map.insert("trust_id".to_string(), Value::String(trust.id.clone()));
        }
        Some(AuthenticationContext::ApplicationCredential {
            application_credential,
            ..
        }) => {
            map.insert(
                "app_cred_id".to_string(),
                Value::String(application_credential.id.clone()),
            );
        }
        _ => {}
    }
    serde_json::to_string(&blob_val)
        .map_err(|e| CredentialProviderError::InvalidBlob(e.to_string()))
}

/// Credential provider.
pub struct CredentialService {
    backend_driver: Arc<dyn CredentialBackend>,
}

impl CredentialService {
    /// Create a new credential service.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, CredentialProviderError> {
        let backend_driver = plugin_manager
            .get_credential_backend(config.credential.driver.clone())?
            .clone();
        Ok(Self { backend_driver })
    }
}

#[async_trait]
impl CredentialApi for CredentialService {
    async fn create_credential<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        rec: CredentialCreate,
    ) -> Result<Credential, CredentialProviderError> {
        rec.validate()?;
        let mut rec = rec;

        if rec.r#type == "ec2" {
            if rec.project_id.is_none() {
                return Err(CredentialProviderError::MissingProjectId);
            }
            rec.blob = stamp_ec2_delegation_metadata(&rec.blob, ctx.ctx())?;
        }

        if rec.user_id.is_none() {
            match ctx.ctx() {
                Some(vsc) => {
                    // Under system scope there is no implicit "acting user"
                    // to default to (ADR 0019 §2, Create).
                    let is_system_scoped = matches!(
                        vsc.authorization().map(|a| &a.scope),
                        Some(ScopeInfo::System(_))
                    );
                    if is_system_scoped {
                        return Err(CredentialProviderError::MissingUserId);
                    }
                    rec.user_id = Some(vsc.principal().get_user_id());
                }
                None => return Err(CredentialProviderError::MissingUserId),
            }
        }

        if rec.id.is_none() {
            rec.id = Some(if rec.r#type == "ec2" {
                let blob_val: Value = serde_json::from_str(&rec.blob)
                    .map_err(|e| CredentialProviderError::InvalidBlob(e.to_string()))?;
                let access = blob_val
                    .get("access")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        CredentialProviderError::InvalidBlob(
                            "ec2 blob missing mandatory `access` field".into(),
                        )
                    })?;
                let mut hasher = Sha256::new();
                hasher.update(access.as_bytes());
                hasher
                    .finalize()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            } else {
                Uuid::new_v4().simple().to_string()
            });
        }

        let user_id = rec.user_id.clone().unwrap_or_default();
        let cred_id = rec.id.clone().unwrap_or_default();
        let credential = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let rec_clone = rec.clone();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Create,
                    EventPayload::Credential {
                        id: cred_id.clone(),
                        user_id: user_id.clone(),
                    },
                ),
                operation: async {
                    backend_driver.create_credential(ctx.state(), rec_clone).await
                },
                on_audit_error: |_: AuditDispatchError| CredentialProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            let credential = self
                .backend_driver
                .create_credential(ctx.state(), rec)
                .await?;

            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Create,
                    EventPayload::Credential {
                        id: credential.id.clone(),
                        user_id: user_id.clone(),
                    },
                ))
                .await;

            credential
        };

        Ok(credential)
    }

    async fn get_credential<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<Credential>, CredentialProviderError> {
        self.backend_driver.get_credential(ctx.state(), id).await
    }

    async fn get_credential_by_ec2_access<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        access: &'a str,
    ) -> Result<Option<Credential>, CredentialProviderError> {
        self.backend_driver
            .get_credential_by_ec2_access(ctx.state(), access)
            .await
    }

    async fn list_credentials<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        params: &CredentialListParameters,
    ) -> Result<Vec<Credential>, CredentialProviderError> {
        self.backend_driver
            .list_credentials(ctx.state(), params)
            .await
    }

    async fn list_credentials_for_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
        r#type: Option<&'a str>,
    ) -> Result<Vec<Credential>, CredentialProviderError> {
        self.backend_driver
            .list_credentials_for_user(ctx.state(), user_id, r#type)
            .await
    }

    async fn update_credential<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
        rec: CredentialUpdate,
    ) -> Result<Credential, CredentialProviderError> {
        rec.validate()?;
        let mut rec = rec;

        if let Some(new_blob) = &rec.blob {
            let existing = self
                .backend_driver
                .get_credential(ctx.state(), id)
                .await?
                .ok_or_else(|| CredentialProviderError::CredentialNotFound(id.to_string()))?;

            let old_val: Value = serde_json::from_str(&existing.blob)?;
            let mut new_val: Value = serde_json::from_str(new_blob)?;

            // Delegation metadata is server-managed (see
            // `stamp_ec2_delegation_metadata`): the caller's patch is not
            // expected to resupply it, so a missing field carries the
            // stored value forward rather than being treated as a change.
            // An explicitly *different* value is still rejected.
            if let Value::Object(new_map) = &mut new_val {
                for field in DELEGATION_BLOB_FIELDS {
                    match old_val.get(*field) {
                        Some(old) if new_map.get(*field).is_none_or(|new| new == old) => {
                            new_map.insert((*field).to_string(), old.clone());
                        }
                        None if new_map.contains_key(*field) => {
                            return Err(CredentialProviderError::ImmutableField(
                                (*field).to_string(),
                            ));
                        }
                        Some(_) => {
                            return Err(CredentialProviderError::ImmutableField(
                                (*field).to_string(),
                            ));
                        }
                        None => {}
                    }
                }
            }

            rec.blob = Some(
                serde_json::to_string(&new_val)
                    .map_err(|e| CredentialProviderError::InvalidBlob(e.to_string()))?,
            );
        }

        let user_id = self
            .backend_driver
            .get_credential(ctx.state(), id)
            .await?
            .map(|c| c.user_id)
            .unwrap_or_default();

        let credential = if let Some(vsc) = ctx.ctx() {
            let backend_driver = &self.backend_driver;
            let rec_clone = rec.clone();
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Update,
                    EventPayload::Credential {
                        id: id.to_string(),
                        user_id: user_id.clone(),
                    },
                ),
                operation: async {
                    backend_driver.update_credential(ctx.state(), id, rec_clone).await
                },
                on_audit_error: |_: AuditDispatchError| CredentialProviderError::Driver("audit dispatch failed".into()),
            }?
        } else {
            self.backend_driver
                .update_credential(ctx.state(), id, rec)
                .await?
        };

        Ok(credential)
    }

    async fn delete_credential<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), CredentialProviderError> {
        let user_id = self
            .backend_driver
            .get_credential(ctx.state(), id)
            .await?
            .map(|c| c.user_id)
            .unwrap_or_default();

        if let Some(vsc) = ctx.ctx() {
            crate::audited_op! {
                dispatcher: &ctx.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(
                    Operation::Delete,
                    EventPayload::Credential {
                        id: id.to_string(),
                        user_id: user_id.clone(),
                    },
                ),
                operation: async {
                    self.backend_driver.delete_credential(ctx.state(), id).await?;
                    Ok::<(), CredentialProviderError>(())
                },
                on_audit_error: |_: AuditDispatchError| CredentialProviderError::Driver("audit dispatch failed".into()),
            }?;
        } else {
            self.backend_driver
                .delete_credential(ctx.state(), id)
                .await?;

            ctx.state()
                .event_dispatcher
                .emit(Event::new(
                    Operation::Delete,
                    EventPayload::Credential {
                        id: id.to_string(),
                        user_id,
                    },
                ))
                .await;
        }

        Ok(())
    }

    async fn delete_credentials_for_user<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        user_id: &'a str,
    ) -> Result<(), CredentialProviderError> {
        self.backend_driver
            .delete_credentials_for_user(ctx.state(), user_id)
            .await
    }

    async fn delete_credentials_for_project<'a>(
        &self,
        ctx: &ExecutionContext<'a>,
        project_id: &'a str,
    ) -> Result<(), CredentialProviderError> {
        self.backend_driver
            .delete_credentials_for_project(ctx.state(), project_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credential::backend::MockCredentialBackend;
    use crate::tests::get_mocked_state;

    fn create_provider(backend: MockCredentialBackend) -> CredentialService {
        CredentialService {
            backend_driver: Arc::new(backend),
        }
    }

    fn ec2_id(access: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(access.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    #[tokio::test]
    async fn test_create_ec2_requires_project_id() {
        let state = get_mocked_state(None, None).await;
        let provider = create_provider(MockCredentialBackend::default());

        let rec = CredentialCreate {
            blob: r#"{"access":"AKIA123"}"#.into(),
            r#type: "ec2".into(),
            user_id: Some("user_id".into()),
            project_id: None,
            ..Default::default()
        };

        let err = provider
            .create_credential(&ExecutionContext::internal(&state), rec)
            .await
            .unwrap_err();
        assert!(matches!(err, CredentialProviderError::MissingProjectId));
    }

    #[tokio::test]
    async fn test_create_requires_user_id_when_no_context() {
        let state = get_mocked_state(None, None).await;
        let provider = create_provider(MockCredentialBackend::default());

        let rec = CredentialCreate {
            blob: r#"{"seed":"JBSWY3DPEHPK3PXP"}"#.into(),
            r#type: "totp".into(),
            user_id: None,
            ..Default::default()
        };

        let err = provider
            .create_credential(&ExecutionContext::internal(&state), rec)
            .await
            .unwrap_err();
        assert!(matches!(err, CredentialProviderError::MissingUserId));
    }

    #[tokio::test]
    async fn test_create_ec2_computes_sha256_id() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockCredentialBackend::default();
        let expected_id = ec2_id("AKIAIOSFODNN7EXAMPLE");
        let expected_id_clone = expected_id.clone();
        backend
            .expect_create_credential()
            .withf(move |_, rec: &CredentialCreate| {
                rec.id.as_deref() == Some(expected_id_clone.as_str())
            })
            .returning(move |_, rec| {
                Ok(Credential {
                    id: rec.id.clone().unwrap_or_default(),
                    user_id: rec.user_id.clone().unwrap_or_default(),
                    project_id: rec.project_id.clone(),
                    blob: rec.blob.clone(),
                    r#type: rec.r#type.clone(),
                    extra: rec.extra.clone(),
                })
            });
        let provider = create_provider(backend);

        let rec = CredentialCreate {
            blob: r#"{"access":"AKIAIOSFODNN7EXAMPLE","secret":"x"}"#.into(),
            r#type: "ec2".into(),
            user_id: Some("user_id".into()),
            project_id: Some("project_id".into()),
            ..Default::default()
        };

        let created = provider
            .create_credential(&ExecutionContext::internal(&state), rec)
            .await
            .unwrap();
        assert_eq!(created.id, expected_id);
    }

    /// Regression test (GitHub issue #1044): keystone-py's update handler
    /// (`keystone/api/credentials.py::_validate_blob_update_keys`) only
    /// actually enforces immutability on `trust_id`/`app_cred_id`/
    /// `access_token_id`/`access_id` -- and `access_id` is not a real blob
    /// key (the EC2 access value is stored under `access`), so that check is
    /// permanently a no-op and keystone-py allows `access` to change freely
    /// on update, with the credential's `id` (computed once at create time)
    /// left as-is. Tempest's `test_credentials_create_get_update_delete`
    /// relies on exactly this and fails if `access` is rejected here.
    #[tokio::test]
    async fn test_update_allows_changing_access_field() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockCredentialBackend::default();
        backend.expect_get_credential().returning(|_, _| {
            Ok(Some(Credential {
                id: "cred_id".into(),
                user_id: "user_id".into(),
                project_id: Some("project_id".into()),
                blob: r#"{"access":"AKIA_OLD","secret":"s"}"#.into(),
                r#type: "ec2".into(),
                extra: None,
            }))
        });
        backend.expect_update_credential().returning(|_, id, _| {
            Ok(Credential {
                id: id.to_string(),
                user_id: "user_id".into(),
                project_id: Some("project_id".into()),
                blob: r#"{"access":"AKIA_NEW","secret":"s"}"#.into(),
                r#type: "ec2".into(),
                extra: None,
            })
        });
        let provider = create_provider(backend);

        let rec = CredentialUpdate {
            blob: Some(r#"{"access":"AKIA_NEW","secret":"s"}"#.into()),
            ..Default::default()
        };

        let updated = provider
            .update_credential(&ExecutionContext::internal(&state), "cred_id", rec)
            .await
            .unwrap();
        assert_eq!(updated.blob, r#"{"access":"AKIA_NEW","secret":"s"}"#);
    }

    #[tokio::test]
    async fn test_update_allows_blob_change_when_immutable_fields_unchanged() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockCredentialBackend::default();
        backend.expect_get_credential().returning(|_, _| {
            Ok(Some(Credential {
                id: "cred_id".into(),
                user_id: "user_id".into(),
                project_id: Some("project_id".into()),
                blob: r#"{"access":"AKIA_OLD","secret":"old"}"#.into(),
                r#type: "ec2".into(),
                extra: None,
            }))
        });
        backend.expect_update_credential().returning(|_, id, _| {
            Ok(Credential {
                id: id.to_string(),
                user_id: "user_id".into(),
                project_id: Some("project_id".into()),
                blob: r#"{"access":"AKIA_OLD","secret":"new"}"#.into(),
                r#type: "ec2".into(),
                extra: None,
            })
        });
        let provider = create_provider(backend);

        let rec = CredentialUpdate {
            blob: Some(r#"{"access":"AKIA_OLD","secret":"new"}"#.into()),
            ..Default::default()
        };

        let updated = provider
            .update_credential(&ExecutionContext::internal(&state), "cred_id", rec)
            .await
            .unwrap();
        assert_eq!(updated.blob, r#"{"access":"AKIA_OLD","secret":"new"}"#);
    }

    fn vsc_for_app_cred(unrestricted: bool) -> crate::auth::ValidatedSecurityContext {
        use openstack_keystone_core_types::application_credential::ApplicationCredential;
        use openstack_keystone_core_types::auth::{
            IdentityInfo, PrincipalInfo, SecurityContextTestingBuilder, UserIdentityInfoBuilder,
        };

        let ac = ApplicationCredential {
            id: "ac1".to_string(),
            user_id: "user_id".to_string(),
            project_id: "project_id".to_string(),
            name: "cred".to_string(),
            description: None,
            roles: vec![],
            unrestricted,
            expires_at: None,
            access_rules: None,
        };
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::ApplicationCredential {
                application_credential: ac,
                token: None,
            })
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("user_id")
                        .build()
                        .unwrap(),
                ),
            })
            .build();
        crate::auth::ValidatedSecurityContext::test_new(ctx)
    }

    fn vsc_for_trust(trust_id: &str) -> crate::auth::ValidatedSecurityContext {
        use openstack_keystone_core_types::auth::{
            IdentityInfo, PrincipalInfo, SecurityContextTestingBuilder, UserIdentityInfoBuilder,
        };
        use openstack_keystone_core_types::trust::Trust;

        let trust = Trust {
            id: trust_id.to_string(),
            impersonation: false,
            project_id: Some("project_id".to_string()),
            trustee_user_id: "user_id".to_string(),
            trustor_user_id: "trustor_id".to_string(),
            ..Default::default()
        };
        let ctx = SecurityContextTestingBuilder::default()
            .authentication_context(AuthenticationContext::Trust { trust, token: None })
            .principal(PrincipalInfo {
                identity: IdentityInfo::User(
                    UserIdentityInfoBuilder::default()
                        .user_id("user_id")
                        .build()
                        .unwrap(),
                ),
            })
            .build();
        crate::auth::ValidatedSecurityContext::test_new(ctx)
    }

    #[tokio::test]
    async fn test_create_ec2_stamps_app_cred_id_from_auth_context() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockCredentialBackend::default();
        backend
            .expect_create_credential()
            .withf(|_, rec: &CredentialCreate| {
                let blob: Value = serde_json::from_str(&rec.blob).unwrap();
                blob.get("app_cred_id").and_then(Value::as_str) == Some("ac1")
                    && blob.get("trust_id").is_none()
            })
            .returning(|_, rec| {
                Ok(Credential {
                    id: rec.id.clone().unwrap_or_default(),
                    user_id: rec.user_id.clone().unwrap_or_default(),
                    project_id: rec.project_id.clone(),
                    blob: rec.blob.clone(),
                    r#type: rec.r#type.clone(),
                    extra: rec.extra.clone(),
                })
            });
        let provider = create_provider(backend);

        // A malicious caller cannot forge a *different* trust_id/app_cred_id
        // via the blob: it must be discarded and replaced by the real one
        // derived from the creating request's own auth context.
        let rec = CredentialCreate {
            blob: r#"{"access":"AKIA123","secret":"s3cr3t","app_cred_id":"forged"}"#.into(),
            r#type: "ec2".into(),
            user_id: Some("user_id".into()),
            project_id: Some("project_id".into()),
            ..Default::default()
        };

        let vsc = vsc_for_app_cred(true);
        let ctx = ExecutionContext::from_auth(&state, &vsc);
        provider.create_credential(&ctx, rec).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_ec2_stamps_trust_id_from_auth_context() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockCredentialBackend::default();
        backend
            .expect_create_credential()
            .withf(|_, rec: &CredentialCreate| {
                let blob: Value = serde_json::from_str(&rec.blob).unwrap();
                blob.get("trust_id").and_then(Value::as_str) == Some("trust1")
            })
            .returning(|_, rec| {
                Ok(Credential {
                    id: rec.id.clone().unwrap_or_default(),
                    user_id: rec.user_id.clone().unwrap_or_default(),
                    project_id: rec.project_id.clone(),
                    blob: rec.blob.clone(),
                    r#type: rec.r#type.clone(),
                    extra: rec.extra.clone(),
                })
            });
        let provider = create_provider(backend);

        let rec = CredentialCreate {
            blob: r#"{"access":"AKIA123","secret":"s3cr3t"}"#.into(),
            r#type: "ec2".into(),
            user_id: Some("user_id".into()),
            project_id: Some("project_id".into()),
            ..Default::default()
        };

        let vsc = vsc_for_trust("trust1");
        let ctx = ExecutionContext::from_auth(&state, &vsc);
        provider.create_credential(&ctx, rec).await.unwrap();
    }

    #[tokio::test]
    async fn test_create_ec2_no_delegation_metadata_without_delegated_auth() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockCredentialBackend::default();
        backend
            .expect_create_credential()
            .withf(|_, rec: &CredentialCreate| {
                let blob: Value = serde_json::from_str(&rec.blob).unwrap();
                blob.get("trust_id").is_none() && blob.get("app_cred_id").is_none()
            })
            .returning(|_, rec| {
                Ok(Credential {
                    id: rec.id.clone().unwrap_or_default(),
                    user_id: rec.user_id.clone().unwrap_or_default(),
                    project_id: rec.project_id.clone(),
                    blob: rec.blob.clone(),
                    r#type: rec.r#type.clone(),
                    extra: rec.extra.clone(),
                })
            });
        let provider = create_provider(backend);

        let rec = CredentialCreate {
            blob: r#"{"access":"AKIA123","secret":"s3cr3t"}"#.into(),
            r#type: "ec2".into(),
            user_id: Some("user_id".into()),
            project_id: Some("project_id".into()),
            ..Default::default()
        };

        provider
            .create_credential(&ExecutionContext::internal(&state), rec)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_update_carries_forward_delegation_metadata_when_omitted() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockCredentialBackend::default();
        backend.expect_get_credential().returning(|_, _| {
            Ok(Some(Credential {
                id: "cred_id".into(),
                user_id: "user_id".into(),
                project_id: Some("project_id".into()),
                blob: r#"{"access":"AKIA_OLD","secret":"old","app_cred_id":"ac1"}"#.into(),
                r#type: "ec2".into(),
                extra: None,
            }))
        });
        backend
            .expect_update_credential()
            .withf(|_, _, rec: &CredentialUpdate| {
                let blob: Value = serde_json::from_str(rec.blob.as_ref().unwrap()).unwrap();
                blob.get("app_cred_id").and_then(Value::as_str) == Some("ac1")
                    && blob.get("secret").and_then(Value::as_str) == Some("new")
            })
            .returning(|_, id, rec| {
                Ok(Credential {
                    id: id.to_string(),
                    user_id: "user_id".into(),
                    project_id: Some("project_id".into()),
                    blob: rec.blob.clone().unwrap(),
                    r#type: "ec2".into(),
                    extra: None,
                })
            });
        let provider = create_provider(backend);

        // Caller's patch omits app_cred_id entirely (as any real client
        // would, since it's a server-managed field) — it must be carried
        // forward from the stored blob, not dropped.
        let rec = CredentialUpdate {
            blob: Some(r#"{"access":"AKIA_OLD","secret":"new"}"#.into()),
            ..Default::default()
        };

        provider
            .update_credential(&ExecutionContext::internal(&state), "cred_id", rec)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_update_rejects_forged_delegation_metadata() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockCredentialBackend::default();
        backend.expect_get_credential().returning(|_, _| {
            Ok(Some(Credential {
                id: "cred_id".into(),
                user_id: "user_id".into(),
                project_id: Some("project_id".into()),
                blob: r#"{"access":"AKIA_OLD","secret":"old","app_cred_id":"ac1"}"#.into(),
                r#type: "ec2".into(),
                extra: None,
            }))
        });
        let provider = create_provider(backend);

        let rec = CredentialUpdate {
            blob: Some(r#"{"access":"AKIA_OLD","secret":"new","app_cred_id":"forged"}"#.into()),
            ..Default::default()
        };

        let err = provider
            .update_credential(&ExecutionContext::internal(&state), "cred_id", rec)
            .await
            .unwrap_err();
        assert!(matches!(err, CredentialProviderError::ImmutableField(f) if f == "app_cred_id"));
    }

    #[tokio::test]
    async fn test_update_rejects_injecting_delegation_metadata_not_originally_set() {
        let state = get_mocked_state(None, None).await;
        let mut backend = MockCredentialBackend::default();
        backend.expect_get_credential().returning(|_, _| {
            Ok(Some(Credential {
                id: "cred_id".into(),
                user_id: "user_id".into(),
                project_id: Some("project_id".into()),
                blob: r#"{"access":"AKIA_OLD","secret":"old"}"#.into(),
                r#type: "ec2".into(),
                extra: None,
            }))
        });
        let provider = create_provider(backend);

        let rec = CredentialUpdate {
            blob: Some(r#"{"access":"AKIA_OLD","secret":"new","app_cred_id":"injected"}"#.into()),
            ..Default::default()
        };

        let err = provider
            .update_credential(&ExecutionContext::internal(&state), "cred_id", rec)
            .await
            .unwrap_err();
        assert!(matches!(err, CredentialProviderError::ImmutableField(f) if f == "app_cred_id"));
    }
}
