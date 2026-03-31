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
//! # Role assignment driver for OpenStack Keystone using OpenFGA
use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use reqwest::Client;
use serde_json::{Value, json};
use tracing::error;

use openstack_keystone_core::assignment::{AssignmentProviderError, backend::AssignmentBackend};
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::plugin_manager::BackendRegistration;
use openstack_keystone_core_types::assignment::*;

mod types;
use types::*;

pub use types::OpenFGADriverError;

/// Linkage anchor — see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker extracts `.rlib`
/// members, keeping `inventory::submit!` sections visible at runtime.
#[allow(dead_code)]
pub fn anchor() {}

inventory::submit! {
    BackendRegistration::<dyn AssignmentBackend> {
        name: "openfga",
        selected: |_| true,
        build: |_cfg| Box::pin(async {
            Ok(Arc::new(OpenFGADriver::default()) as Arc<dyn AssignmentBackend>)
        }),
    }
}

pub struct OpenFGADriver {
    openfga_client: Client,
}

impl Default for OpenFGADriver {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenFGADriver {
    /// Initialize the OpenFGA driver.
    pub fn new() -> Self {
        Self {
            openfga_client: Client::new(),
        }
    }

    async fn get_openfga_relation(&self, state: &ServiceState, role_id: &String) -> Option<String> {
        state
            .config_manager
            .config
            .read()
            .await
            .openfga
            .as_ref()
            .and_then(|x| x.role_to_relation.as_ref())
            .and_then(|x| x.get(role_id).cloned())
    }

    async fn get_role_id(&self, state: &ServiceState, openfga_relation: &String) -> Option<String> {
        state
            .config_manager
            .config
            .read()
            .await
            .openfga
            .as_ref()
            .and_then(|x| x.role_to_relation.as_ref())
            .and_then(|x| {
                x.iter()
                    .find(|(_, v)| *v == openfga_relation)
                    .map(|(k, _)| k.clone())
            })
    }

    /// Check tuples.
    async fn openfga_check(
        &self,
        state: &ServiceState,
        tuple: Value,
    ) -> Result<bool, OpenFGADriverError> {
        let cfg = state
            .config_manager
            .config
            .read()
            .await
            .openfga
            .clone()
            .ok_or(OpenFGADriverError::MissingConfiguration)?;
        let mut body = tuple;
        if let Some(model_id) = &cfg.model_id {
            body["authorization_model_id"] = model_id.clone().into();
        }

        let request = self
            .openfga_client
            .post(
                cfg.api_url
                    .join(format!("stores/{store_id}/check", store_id = cfg.store_id).as_str())
                    .map_err(OpenFGADriverError::from)?,
            )
            .bearer_auth(cfg.api_key.clone())
            .json(&body);
        let response = request.send().await.map_err(OpenFGADriverError::from)?;

        if response.status().is_success() {
            let rsp: OpenFGACheckResponse = response.json().await?;
            Ok(rsp.allowed)
        } else {
            let body = response.text().await.map_err(OpenFGADriverError::from)?;
            if let Ok(rsp) = serde_json::from_str::<OpenFGAErrorResponse>(&body) {
                let msg = format!("OpenFGA write error: {}", rsp.message);
                error!("{}", msg);
                Err(OpenFGADriverError::OpenFGAError(msg))
            } else {
                Err(OpenFGADriverError::OpenFGAError(body))?
            }
        }
    }

    /// Read data from OpenFGA.
    async fn openfga_read(
        &self,
        state: &ServiceState,
        tuple: Value,
    ) -> Result<Vec<Assignment>, OpenFGADriverError> {
        let cfg = state
            .config_manager
            .config
            .read()
            .await
            .openfga
            .clone()
            .ok_or(OpenFGADriverError::MissingConfiguration)?;
        let mut body = tuple;
        if let Some(model_id) = &cfg.model_id {
            body["authorization_model_id"] = model_id.clone().into();
        }
        let mut results: Vec<Assignment> = Vec::new();

        let request = self
            .openfga_client
            .post(
                cfg.api_url
                    .join(format!("stores/{store_id}/read", store_id = cfg.store_id).as_str())
                    .map_err(OpenFGADriverError::from)?,
            )
            .bearer_auth(cfg.api_key.clone())
            .json(&body);
        let response = request.send().await.map_err(OpenFGADriverError::from)?;

        if response.status().is_success() {
            let rsp: OpenFGAReadResponse = response.json().await?;
            for item in rsp.tuples.iter() {
                if let Some(role_id) = self.get_role_id(state, &item.tuple.relation).await {
                    let user = OpenFGAUser::from_openfga_tuple(state, &item.tuple).await?;
                    let object = OpenFGAObject::try_from(&item.tuple)?;
                    results.push(Assignment {
                        actor_id: user.local_actor_id(),
                        role_id,
                        role_name: None,
                        target_id: object.local_target_id(),
                        r#type: user.as_assignment_type(&object),
                        inherited: false,
                        implied_via: None,
                    });
                }
            }
        } else {
            let body = response.text().await.map_err(OpenFGADriverError::from)?;
            if let Ok(rsp) = serde_json::from_str::<OpenFGAErrorResponse>(&body) {
                let msg = format!("OpenFGA write error: {}", rsp.message);
                error!("{}", msg);
                return Err(OpenFGADriverError::OpenFGAError(msg));
            } else {
                Err(OpenFGADriverError::OpenFGAError(body))?;
            }
        }
        Ok(results)
    }

    /// Write changes to the OpenFGA.
    async fn openfga_write(
        &self,
        state: &ServiceState,
        write: Option<Value>,
        delete: Option<Value>,
    ) -> Result<(), OpenFGADriverError> {
        let cfg = state
            .config_manager
            .config
            .read()
            .await
            .openfga
            .clone()
            .ok_or(OpenFGADriverError::MissingConfiguration)?;
        let mut body = json!({});
        if let Some(writes) = write {
            body["writes"] = json!({
                "tuple_keys": [writes]
            });
        }
        if let Some(deletes) = delete {
            body["deletes"] = json!({
                "tuple_keys": [deletes]
            });
        }
        if let Some(model_id) = &cfg.model_id {
            body["authorization_model_id"] = model_id.clone().into();
        }

        let request = self
            .openfga_client
            .post(
                cfg.api_url
                    .join(format!("stores/{store_id}/write", store_id = cfg.store_id).as_str())
                    .map_err(OpenFGADriverError::from)?,
            )
            .bearer_auth(cfg.api_key.clone())
            .json(&body);
        let response = request.send().await.map_err(OpenFGADriverError::from)?;
        if response.status().is_success() {
            Ok(())
        } else {
            let body = response.text().await.map_err(OpenFGADriverError::from)?;
            if let Ok(rsp) = serde_json::from_str::<OpenFGAErrorResponse>(&body) {
                let msg = format!("OpenFGA write error: {}", rsp.message);
                error!("{}", msg);
                Err(OpenFGADriverError::OpenFGAError(rsp.message))
            } else {
                Err(OpenFGADriverError::OpenFGAError(body))?
            }
        }
    }

    /// List relations between user and the objects.
    ///
    /// Performs a batch-check call to the OpenFGA querying each relation
    /// present in the role_to_relation map.
    ///
    /// Returns list of role_ids representing active relations.
    async fn check_relations_between_user_and_object(
        &self,
        state: &ServiceState,
        user: &OpenFGAUser,
        object: &OpenFGAObject,
    ) -> Result<Vec<String>, OpenFGADriverError> {
        let cfg = state
            .config_manager
            .config
            .read()
            .await
            .openfga
            .clone()
            .ok_or(OpenFGADriverError::MissingConfiguration)?;
        let role_relation_map = if let Some(val) = &cfg.role_to_relation.as_ref() {
            val
        } else {
            &HashMap::default()
        };
        let mut query = json!({});
        if let Some(model_id) = &cfg.model_id {
            query["authorization_model_id"] = model_id.clone().into();
        }
        let mut checks: Vec<Value> = Vec::new();
        for (role_id, relation) in role_relation_map.iter() {
            checks.push(json!({
                "tuple_key": {
                    "user": user.to_string(),
                    "object": object.to_string(),
                    "relation": relation.clone()
                },
                "correlation_id": role_id.clone()
            }));
        }
        query["checks"] = checks.into();
        let request = self
            .openfga_client
            .post(
                cfg.api_url
                    .join(
                        format!("stores/{store_id}/batch-check", store_id = cfg.store_id).as_str(),
                    )
                    .map_err(OpenFGADriverError::from)?,
            )
            .bearer_auth(cfg.api_key.clone())
            .json(&query);
        let response = request.send().await?;
        let mut results: Vec<String> = Vec::new();
        if response.status().is_success() {
            let rsp: OpenFGABatchCheckResponse = response.json().await?;
            for (correlation, result) in rsp.result.iter() {
                if result.allowed {
                    results.push(correlation.to_string());
                }
            }
        } else {
            let body = response.text().await.map_err(OpenFGADriverError::from)?;
            if let Ok(rsp) = serde_json::from_str::<OpenFGAErrorResponse>(&body) {
                let msg = format!("OpenFGA check error: {}", rsp.message);
                error!("{}", msg);
                return Err(OpenFGADriverError::OpenFGAError(msg));
            } else {
                return Err(OpenFGADriverError::OpenFGAError(body));
            }
        }
        Ok(results)
    }
}

// `Assignment{,Create}::inherited` is intentionally not encoded into any
// OpenFGA tuple or relation: the OpenFGA authorization model itself performs
// the cascading, so every stored tuple is implicitly "inheritable" through
// the model's userset rewrite rules. `openfga_read` (raw tuple listing)
// therefore only ever surfaces the direct tuples that were written, while
// `check`/`batch-check` resolve direct and inherited grants alike.
#[async_trait]
impl AssignmentBackend for OpenFGADriver {
    /// Check assignment grant.
    async fn check_grant(
        &self,
        state: &ServiceState,
        assignment: &Assignment,
    ) -> Result<bool, AssignmentProviderError> {
        let tuple = json!({
            "tuple_key": {
                "relation": self.get_openfga_relation(state, &assignment.role_id).await.ok_or(OpenFGADriverError::RoleRelationNotConfigured(assignment.role_id.clone()))?,
                "user": OpenFGAUser::from_assignment(state, assignment).await?.to_string(),
                "object": OpenFGAObject::from(assignment).to_string(),
            }
        });
        Ok(self.openfga_check(state, tuple).await?)
    }

    /// Create assignment grant.
    async fn create_grant(
        &self,
        state: &ServiceState,
        assignment: AssignmentCreate,
    ) -> Result<Assignment, AssignmentProviderError> {
        let tuple = json!({
            "relation": self.get_openfga_relation(state, &assignment.role_id).await.ok_or(
                OpenFGADriverError::RoleRelationNotConfigured(assignment.role_id.clone()),
            )?,
            "user": OpenFGAUser::from_create_assignment(state, &assignment).await?.to_string(),
            "object": OpenFGAObject::from(&assignment).to_string(),
        });
        self.openfga_write(state, Some(tuple), None).await?;
        Ok(Assignment {
            actor_id: assignment.actor_id,
            implied_via: None,
            inherited: assignment.inherited,
            r#type: assignment.r#type,
            role_id: assignment.role_id,
            role_name: None,
            target_id: assignment.target_id,
        })
    }

    /// List role assignments.
    async fn list_assignments(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        let user = OpenFGAUser::from_list_parameters(state, params).await?;
        let object = OpenFGAObject::try_from(params).ok();
        let relation = if let Some(role_id) = &params.role_id {
            Some(self.get_openfga_relation(state, role_id).await.ok_or(
                OpenFGADriverError::RoleRelationNotConfigured(role_id.clone()),
            )?)
        } else {
            None
        };

        let mut results: Vec<Assignment> = Vec::new();
        match (user, object, relation) {
            (Some(user), Some(object), Some(relation)) => {
                // all 3 parameters - just check
                let tuple = json!({
                    "tuple_key": {
                        "relation": relation,
                        "user": user.to_string(),
                        "object": object.to_string(),
                    }
                });
                if self.openfga_check(state, tuple).await?
                    && let Some(role_id) = &params.role_id
                {
                    results.push(Assignment {
                        actor_id: user.local_actor_id(),
                        role_id: role_id.clone(),
                        role_name: None,
                        target_id: object.local_target_id(),
                        r#type: user.as_assignment_type(&object),
                        inherited: false,
                        implied_via: None,
                    });
                }
            }
            (Some(user), Some(object), None) => {
                // Login attempt - listing all roles of the user on the scope - need to perform
                // batch check for all of the roles of interest

                for role_id in self
                    .check_relations_between_user_and_object(state, &user, &object)
                    .await?
                {
                    results.push(Assignment {
                        actor_id: user.local_actor_id(),
                        role_id,
                        role_name: None,
                        target_id: object.local_target_id(),
                        r#type: user.as_assignment_type(&object),
                        inherited: false,
                        implied_via: None,
                    });
                }
            }
            (Some(_user), None, Some(_relation)) => {
                // TODO: potentially it is a list-objects call
                // need to join 2 queries with object = "project:" and "domain:"
                todo!();
            }
            (Some(_user), None, None) => {
                //object = Some("project:".into());
                todo!();
            }
            (None, Some(object), Some(relation)) => {
                // Query for all stored relationship tuples that have a particular relation and
                // scope
                results.extend(
                    self.openfga_read(
                        state,
                        json!({"tuple_key": {
                            "relation": relation,
                            "object": object.to_string()
                        }}),
                    )
                    .await?,
                );
            }
            (None, Some(object), None) => {
                // Query for all users with all relationships for a particular scope
                results.extend(
                    self.openfga_read(state, json!({"tuple_key": {"object": object.to_string()}}))
                        .await?,
                );
            }
            (None, None, Some(_relation)) => {
                Err(OpenFGADriverError::ListingAssignmentsByRoleNotSupported)?;
            }
            (None, None, None) => {
                // Listing effective assignments is in principle not possible with openFGA
                // Direct assignments are a huge list and it also does not make sense to be
                // allowed
                Err(OpenFGADriverError::ListingAllAssignmentsNotSupported)?;
            }
        };
        Ok(results)
    }

    /// Revoke assignment grant.
    async fn revoke_grant(
        &self,
        state: &ServiceState,
        assignment: &Assignment,
    ) -> Result<(), AssignmentProviderError> {
        let tuple = json!({
            "relation": self.get_openfga_relation(state, &assignment.role_id).await.ok_or(
                OpenFGADriverError::RoleRelationNotConfigured(assignment.role_id.clone()),
            )?,
            "user": OpenFGAUser::from_assignment(state, assignment).await?.to_string(),
            "object": OpenFGAObject::from(assignment).to_string(),
        });
        Ok(self.openfga_write(state, None, Some(tuple)).await?)
    }
}

#[cfg(test)]
mod tests {
    use eyre::Result;
    use httpmock::MockServer;
    use reqwest::Client;
    use tracing_test::traced_test;
    use url::Url;

    use openstack_keystone_config::{Config, OpenFGAAssignmentDriver};
    use openstack_keystone_core::identity::MockIdentityProvider;
    use openstack_keystone_core::idmapping::MockIdMappingProvider;
    use openstack_keystone_core::provider::Provider;
    use openstack_keystone_core::tests::get_mocked_state;
    use openstack_keystone_core_types::idmapping::*;

    use super::*;

    #[tokio::test]
    #[traced_test]
    async fn test_check_grant() -> Result<()> {
        let mock_srv = MockServer::start_async().await;
        let host = format!("http://{}:{}", mock_srv.host(), mock_srv.port());
        let driver = OpenFGADriver {
            openfga_client: Client::new(),
        };
        let mut config = Config::default();
        config.openfga = Some(OpenFGAAssignmentDriver {
            api_url: Url::parse(&host)?,
            api_key: "secret".into(),
            model_id: Some("model_id".into()),
            store_id: "store_id".into(),
            role_to_relation: Some(HashMap::from([("role_id".into(), "relation".into())])),
            timeout: Some(5),
        });
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user_domain_id()
            .withf(|_, uid: &'_ str| uid == "actor_id")
            .returning(|_, _| Ok("user_did".to_string()));
        let mut identity_mapping_mock = MockIdMappingProvider::default();
        identity_mapping_mock
            .expect_get_by_local_id()
            .withf(|_, uid: &'_ str, did: &'_ str, typ: &IdMappingEntityType| {
                uid == "actor_id" && did == "user_did" && *typ == IdMappingEntityType::User
            })
            .returning(|_, _, _, _| {
                Ok(Some(IdMapping {
                    domain_id: "user_did".into(),
                    entity_type: IdMappingEntityType::User,
                    local_id: "actor_id".into(),
                    public_id: "user_type:user_id".into(),
                }))
            });

        let state = get_mocked_state(
            Some(config),
            Some(
                Provider::mocked_builder()
                    .mock_identity(identity_mock)
                    .mock_idmapping(identity_mapping_mock),
            ),
        )
        .await;

        let _mock_ok = mock_srv
            .mock_async(|when, then| {
                when.method("POST")
                    .path("/stores/store_id/check")
                    .header("authorization", "Bearer secret")
                    .json_body(json!({
                        "tuple_key": {
                            "user": "user_type:user_id",
                            "relation": "relation",
                            "object": "project:target_id",
                        },
                        "authorization_model_id": "model_id"
                    }));
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(json!({"allowed": true}));
            })
            .await;
        let _res = driver
            .check_grant(
                &state,
                &Assignment {
                    actor_id: "actor_id".into(),
                    role_id: "role_id".into(),
                    role_name: None,
                    target_id: "target_id".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                    implied_via: None,
                },
            )
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_check_grant_no_role_mapping() -> Result<()> {
        let mock_srv = MockServer::start_async().await;
        let host = format!("http://{}:{}", mock_srv.host(), mock_srv.port());
        let driver = OpenFGADriver {
            openfga_client: Client::new(),
        };
        let mut config = Config::default();
        config.openfga = Some(OpenFGAAssignmentDriver {
            api_url: Url::parse(&host)?,
            api_key: "secret".into(),
            model_id: Some("model_id".into()),
            store_id: "store_id".into(),
            role_to_relation: Some(HashMap::new()),
            timeout: Some(5),
        });

        let state = get_mocked_state(Some(config), Some(Provider::mocked_builder())).await;

        match driver
            .check_grant(
                &state,
                &Assignment {
                    actor_id: "actor_id".into(),
                    role_id: "role_id".into(),
                    role_name: None,
                    target_id: "target_id".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                    implied_via: None,
                },
            )
            .await
        {
            Err(AssignmentProviderError::Driver(source)) => {
                assert_eq!(
                    "role to relation mapping for the openfga driver is not configured for role `role_id`",
                    source.to_string()
                )
            }
            _ => {
                panic!("error is expected");
            }
        }
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_create_grant() -> Result<()> {
        let mock_srv = MockServer::start_async().await;
        let host = format!("http://{}:{}", mock_srv.host(), mock_srv.port());
        let driver = OpenFGADriver {
            openfga_client: Client::new(),
        };
        let mut config = Config::default();
        config.openfga = Some(OpenFGAAssignmentDriver {
            api_url: Url::parse(&host)?,
            api_key: "secret".into(),
            model_id: Some("model_id".into()),
            store_id: "store_id".into(),
            role_to_relation: Some(HashMap::from([("role_id".into(), "relation".into())])),
            timeout: Some(5),
        });
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user_domain_id()
            .withf(|_, uid: &'_ str| uid == "actor_id")
            .returning(|_, _| Ok("user_did".to_string()));
        let mut identity_mapping_mock = MockIdMappingProvider::default();
        identity_mapping_mock
            .expect_get_by_local_id()
            .withf(|_, uid: &'_ str, did: &'_ str, typ: &IdMappingEntityType| {
                uid == "actor_id" && did == "user_did" && *typ == IdMappingEntityType::User
            })
            .returning(|_, _, _, _| {
                Ok(Some(IdMapping {
                    domain_id: "user_did".into(),
                    entity_type: IdMappingEntityType::User,
                    local_id: "actor_id".into(),
                    public_id: "user_type:user_id".into(),
                }))
            });

        let state = get_mocked_state(
            Some(config),
            Some(
                Provider::mocked_builder()
                    .mock_identity(identity_mock)
                    .mock_idmapping(identity_mapping_mock),
            ),
        )
        .await;

        let mock_ok = mock_srv
            .mock_async(|when, then| {
                when.method("POST")
                    .path("/stores/store_id/write")
                    .header("authorization", "Bearer secret")
                    .json_body(json!({
                        "writes": {
                            "tuple_keys": [{
                                "user": "user_type:user_id",
                                "relation": "relation",
                                "object": "project:target_id",
                            }],
                        },
                        "authorization_model_id": "model_id"
                    }));
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(json!({}));
            })
            .await;
        mock_srv
            .mock_async(|when, then| {
                when.method("POST")
                    .path("/stores/store_id/write")
                    .header("authorization", "Bearer secret")
                    .json_body(json!({
                        "writes": {
                            "tuple_keys": [{
                                "user": "user_type:user_id",
                                "relation": "relation",
                                "object": "project:bad_target_id",
                            }],
                        },
                        "authorization_model_id": "model_id"
                    }));
                then.status(400)
                    .header("content-type", "application/json")
                    .json_body(json!({"code": "foo", "message": "bar"}));
            })
            .await;
        assert!(
            driver
                .create_grant(
                    &state,
                    AssignmentCreate {
                        actor_id: "actor_id".into(),
                        role_id: "role_id".into(),
                        role_name: None,
                        target_id: "target_id".into(),
                        r#type: AssignmentType::UserProject,
                        inherited: false,
                    },
                )
                .await
                .is_ok()
        );
        mock_ok.assert();
        match driver
            .create_grant(
                &state,
                AssignmentCreate {
                    actor_id: "actor_id".into(),
                    role_id: "role_id".into(),
                    role_name: None,
                    target_id: "bad_target_id".into(),
                    r#type: AssignmentType::UserProject,
                    inherited: false,
                },
            )
            .await
        {
            Err(AssignmentProviderError::Driver(source)) => {
                assert_eq!("openfga http error: bar", source.to_string())
            }
            _ => {
                panic!("error was expected");
            }
        }
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_roles_wrong_role() -> Result<()> {
        let mock_srv = MockServer::start_async().await;
        let host = format!("http://{}:{}", mock_srv.host(), mock_srv.port());
        let driver = OpenFGADriver {
            openfga_client: Client::new(),
        };
        let mut config = Config::default();
        config.openfga = Some(OpenFGAAssignmentDriver {
            api_url: Url::parse(&host)?,
            api_key: "secret".into(),
            model_id: Some("model_id".into()),
            store_id: "store_id".into(),
            role_to_relation: Some(HashMap::from([("rid1".into(), "relation1".into())])),
            timeout: Some(5),
        });
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user_domain_id()
            .withf(|_, uid: &'_ str| uid == "user_id")
            .returning(|_, _| Ok("user_did".to_string()));
        let mut identity_mapping_mock = MockIdMappingProvider::default();
        identity_mapping_mock
            .expect_get_by_local_id()
            .withf(|_, uid: &'_ str, did: &'_ str, typ: &IdMappingEntityType| {
                uid == "user_id" && did == "user_did" && *typ == IdMappingEntityType::User
            })
            .returning(|_, _, _, _| {
                Ok(Some(IdMapping {
                    domain_id: "user_did".into(),
                    entity_type: IdMappingEntityType::User,
                    local_id: "user_id".into(),
                    public_id: "user_type:user_id".into(),
                }))
            });

        let state = get_mocked_state(
            Some(config),
            Some(
                Provider::mocked_builder()
                    .mock_identity(identity_mock)
                    .mock_idmapping(identity_mapping_mock),
            ),
        )
        .await;
        match driver
            .list_assignments(
                &state,
                &RoleAssignmentListParameters {
                    user_id: Some("user_id".into()),
                    project_id: Some("project_id".into()),
                    role_id: Some("wrong_role".into()),
                    ..Default::default()
                },
            )
            .await
        {
            Err(AssignmentProviderError::Driver(er)) => {
                assert_eq!(
                    "role to relation mapping for the openfga driver is not configured for role `wrong_role`",
                    er.to_string()
                );
            }
            _ => {
                panic!("error was expected");
            }
        }
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_roles_project_user() -> Result<()> {
        let mock_srv = MockServer::start_async().await;
        let host = format!("http://{}:{}", mock_srv.host(), mock_srv.port());
        let driver = OpenFGADriver {
            openfga_client: Client::new(),
        };
        let mut config = Config::default();
        config.openfga = Some(OpenFGAAssignmentDriver {
            api_url: Url::parse(&host)?,
            api_key: "secret".into(),
            model_id: Some("model_id".into()),
            store_id: "store_id".into(),
            role_to_relation: Some(HashMap::from([
                ("rid1".into(), "relation1".into()),
                ("rid2".into(), "relation2".into()),
                ("rid3".into(), "relation3".into()),
            ])),
            timeout: Some(5),
        });
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user_domain_id()
            .withf(|_, uid: &'_ str| uid == "user_id")
            .returning(|_, _| Ok("user_did".to_string()));
        let mut identity_mapping_mock = MockIdMappingProvider::default();
        identity_mapping_mock
            .expect_get_by_local_id()
            .withf(|_, uid: &'_ str, did: &'_ str, typ: &IdMappingEntityType| {
                uid == "user_id" && did == "user_did" && *typ == IdMappingEntityType::User
            })
            .returning(|_, _, _, _| {
                Ok(Some(IdMapping {
                    domain_id: "user_did".into(),
                    entity_type: IdMappingEntityType::User,
                    local_id: "user_id".into(),
                    public_id: "user_type:user_id".into(),
                }))
            });

        let state = get_mocked_state(
            Some(config),
            Some(
                Provider::mocked_builder()
                    .mock_identity(identity_mock)
                    .mock_idmapping(identity_mapping_mock),
            ),
        )
        .await;
        let _mock_1 = mock_srv
            .mock_async(|when, then| {
                when.method("POST")
                    .path("/stores/store_id/batch-check")
                    .header("authorization", "Bearer secret")
                    .json_body(json!({
                       "authorization_model_id": "model_id",
                       "checks": [{
                           "correlation_id": "rid1",
                           "tuple_key": {
                               "object": "project:project_id",
                               "relation": "relation1",
                               "user": "user_type:user_id"
                           }
                       }]
                    }));
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(json!({
                        "result": {
                            "rid1": {
                                "allowed": true
                            }
                        }
                    }));
            })
            .await;

        // The second mock cannot check the request body because of vector sorting
        let _mock_2 = mock_srv
            .mock_async(|when, then| {
                when.method("POST")
                    .path("/stores/store_id/batch-check")
                    .header("authorization", "Bearer secret");
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(json!({
                        "result": {
                            "rid1": {
                                "allowed": true
                            },
                            "rid2": {
                                "allowed": true
                            },
                            "rid3": {
                                "allowed": false
                            },
                        }
                    }));
            })
            .await;
        assert!(
            driver
                .list_assignments(
                    &state,
                    &RoleAssignmentListParameters {
                        user_id: Some("user_id".into()),
                        project_id: Some("project_id".into()),
                        ..Default::default()
                    },
                )
                .await
                .is_ok(),
            "first check verifies the body sent"
        );
        match driver
            .list_assignments(
                &state,
                &RoleAssignmentListParameters {
                    user_id: Some("user_id".into()),
                    project_id: Some("project_id".into()),
                    ..Default::default()
                },
            )
            .await
        {
            Ok(res) => {
                assert!(res.iter().find(|x| x.role_id == "rid1").is_some());
                assert!(res.iter().find(|x| x.role_id == "rid2").is_some());
                assert!(res.iter().find(|x| x.role_id == "rid3").is_none());
            }
            _ => {
                panic!("success was expected");
            }
        }
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_roles_project_user_role() -> Result<()> {
        let mock_srv = MockServer::start_async().await;
        let host = format!("http://{}:{}", mock_srv.host(), mock_srv.port());
        let driver = OpenFGADriver {
            openfga_client: Client::new(),
        };
        let mut config = Config::default();
        config.openfga = Some(OpenFGAAssignmentDriver {
            api_url: Url::parse(&host)?,
            api_key: "secret".into(),
            model_id: Some("model_id".into()),
            store_id: "store_id".into(),
            role_to_relation: Some(HashMap::from([
                ("rid1".into(), "relation1".into()),
                ("rid2".into(), "relation2".into()),
                ("rid3".into(), "relation3".into()),
            ])),
            timeout: Some(5),
        });
        let mut identity_mock = MockIdentityProvider::default();
        identity_mock
            .expect_get_user_domain_id()
            .withf(|_, uid: &'_ str| uid == "user_id")
            .returning(|_, _| Ok("user_did".to_string()));
        let mut identity_mapping_mock = MockIdMappingProvider::default();
        identity_mapping_mock
            .expect_get_by_local_id()
            .withf(|_, uid: &'_ str, did: &'_ str, typ: &IdMappingEntityType| {
                uid == "user_id" && did == "user_did" && *typ == IdMappingEntityType::User
            })
            .returning(|_, _, _, _| {
                Ok(Some(IdMapping {
                    domain_id: "user_did".into(),
                    entity_type: IdMappingEntityType::User,
                    local_id: "user_id".into(),
                    public_id: "user_type:user_id".into(),
                }))
            });

        let state = get_mocked_state(
            Some(config),
            Some(
                Provider::mocked_builder()
                    .mock_identity(identity_mock)
                    .mock_idmapping(identity_mapping_mock),
            ),
        )
        .await;
        let _mock_1 = mock_srv
            .mock_async(|when, then| {
                when.method("POST")
                    .path("/stores/store_id/check")
                    .header("authorization", "Bearer secret")
                    .json_body(json!({
                       "authorization_model_id": "model_id",
                       "tuple_key": {
                           "object": "project:project_id",
                           "relation": "relation1",
                           "user": "user_type:user_id"
                       }
                    }));
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(json!({"allowed": true}));
            })
            .await;

        match driver
            .list_assignments(
                &state,
                &RoleAssignmentListParameters {
                    user_id: Some("user_id".into()),
                    project_id: Some("project_id".into()),
                    role_id: Some("rid1".into()),
                    ..Default::default()
                },
            )
            .await
        {
            Ok(res) => {
                assert!(res.iter().find(|x| x.role_id == "rid1").is_some());
            }
            other => {
                panic!("success was expected, and not {:?}", other);
            }
        }
        Ok(())
    }

    #[tokio::test]
    #[traced_test]
    async fn test_list_roles_project_only() -> Result<()> {
        let mock_srv = MockServer::start_async().await;
        let host = format!("http://{}:{}", mock_srv.host(), mock_srv.port());
        let driver = OpenFGADriver {
            openfga_client: Client::new(),
        };
        let mut config = Config::default();
        config.openfga = Some(OpenFGAAssignmentDriver {
            api_url: Url::parse(&host)?,
            api_key: "secret".into(),
            model_id: Some("model_id".into()),
            store_id: "store_id".into(),
            role_to_relation: Some(HashMap::from([
                ("rid1".into(), "relation1".into()),
                ("rid2".into(), "relation2".into()),
                ("rid3".into(), "relation3".into()),
            ])),
            timeout: Some(5),
        });
        let mut identity_mapping_mock = MockIdMappingProvider::default();
        identity_mapping_mock
            .expect_get_by_public_id()
            .withf(|_, ruid: &'_ str| ruid == "user:uid1")
            .returning(|_, _| {
                Ok(Some(IdMapping {
                    domain_id: "user_did".into(),
                    entity_type: IdMappingEntityType::User,
                    local_id: "user_id1".into(),
                    public_id: "user:uid1".into(),
                }))
            });
        identity_mapping_mock
            .expect_get_by_public_id()
            .withf(|_, ruid: &'_ str| ruid == "user:uid2")
            .returning(|_, _| {
                Ok(Some(IdMapping {
                    domain_id: "user_did".into(),
                    entity_type: IdMappingEntityType::User,
                    local_id: "user_id2".into(),
                    public_id: "user:uid2".into(),
                }))
            });

        let state = get_mocked_state(
            Some(config),
            Some(Provider::mocked_builder().mock_idmapping(identity_mapping_mock)),
        )
        .await;
        let _mock_1 = mock_srv
            .mock_async(|when, then| {
                when.method("POST")
                    .path("/stores/store_id/read")
                    .header("authorization", "Bearer secret")
                    .json_body(json!({
                       "authorization_model_id": "model_id",
                       "tuple_key": {
                           "object": "project:project_id",
                       }
                    }));
                then.status(200)
                    .header("content-type", "application/json")
                    .json_body(json!({
                        "tuples": [
                            {
                                "key": {
                                    "user": "user:uid1",
                                    "object": "project:project_id",
                                    "relation": "relation1"
                                }
                            },
                            {
                                "key": {
                                    "user": "user:uid2",
                                    "object": "project:project_id",
                                    "relation": "relation2"
                                }
                            }
                        ]
                    }));
            })
            .await;

        match driver
            .list_assignments(
                &state,
                &RoleAssignmentListParameters {
                    project_id: Some("project_id".into()),
                    ..Default::default()
                },
            )
            .await
        {
            Ok(res) => {
                assert!(
                    res.iter()
                        .find(|x| x.role_id == "rid1" && x.actor_id == "user_id1")
                        .is_some()
                );
                assert!(
                    res.iter()
                        .find(|x| x.role_id == "rid2" && x.actor_id == "user_id2")
                        .is_some()
                );
            }
            other => {
                panic!("success was expected, and not {:?}", other);
            }
        }
        Ok(())
    }
}
