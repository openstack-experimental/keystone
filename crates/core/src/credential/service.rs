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
use openstack_keystone_core_types::auth::ScopeInfo;
use openstack_keystone_core_types::credential::*;
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};

use crate::auth::ExecutionContext;
use crate::credential::{CredentialApi, CredentialProviderError, backend::CredentialBackend};
use crate::events::AuditDispatchError;
use crate::plugin_manager::PluginManagerApi;

/// Fields inside the EC2 `blob` that are immutable on update (ADR 0019 §2,
/// Update; CVE-2020-12691 fix scope extended to the delegation fields).
const IMMUTABLE_BLOB_FIELDS: &[&str] = &["access", "trust_id", "app_cred_id", "access_token_id"];

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

        if rec.r#type == "ec2" && rec.project_id.is_none() {
            return Err(CredentialProviderError::MissingProjectId);
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

        if let Some(new_blob) = &rec.blob {
            let existing = self
                .backend_driver
                .get_credential(ctx.state(), id)
                .await?
                .ok_or_else(|| CredentialProviderError::CredentialNotFound(id.to_string()))?;

            let old_val: Value = serde_json::from_str(&existing.blob)?;
            let new_val: Value = serde_json::from_str(new_blob)?;
            for field in IMMUTABLE_BLOB_FIELDS {
                if old_val.get(field) != new_val.get(field) {
                    return Err(CredentialProviderError::ImmutableField(
                        (*field).to_string(),
                    ));
                }
            }
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

    #[tokio::test]
    async fn test_update_rejects_change_to_immutable_access_field() {
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
        let provider = create_provider(backend);

        let rec = CredentialUpdate {
            blob: Some(r#"{"access":"AKIA_NEW","secret":"s"}"#.into()),
            ..Default::default()
        };

        let err = provider
            .update_credential(&ExecutionContext::internal(&state), "cred_id", rec)
            .await
            .unwrap_err();
        assert!(matches!(err, CredentialProviderError::ImmutableField(f) if f == "access"));
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
}
