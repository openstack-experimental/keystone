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
//! # Unified limits provider
use async_trait::async_trait;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use uuid::Uuid;
use validator::Validate;

use openstack_keystone_config::{Config, LimitEnforcementModel};
use openstack_keystone_core_types::events::{Event, EventPayload, Operation};
use openstack_keystone_core_types::limit::*;
use openstack_keystone_core_types::resource::ProjectListParametersBuilder;

use crate::auth::ExecutionContext;
use crate::events::AuditDispatchError;
use crate::limit::{LimitApi, LimitProviderError, backend::LimitBackend};
use crate::plugin_manager::PluginManagerApi;

type BoxFut<'f, T> = Pin<Box<dyn Future<Output = Result<T, LimitProviderError>> + Send + 'f>>;

/// Page size used while walking the resources the limits are checked against.
const SCAN_PAGE_SIZE: u64 = 100;

pub struct LimitService {
    backend_driver: Arc<dyn LimitBackend>,
    model: LimitEnforcementModel,
}

/// Compare two limit values taking the unlimited value (`-1`) into account.
///
/// Returns `true` when `a` is strictly bigger than `b`.
fn exceeds(a: i32, b: i32) -> bool {
    match (a == -1, b == -1) {
        (_, true) => false,
        (true, false) => true,
        (false, false) => a > b,
    }
}

impl LimitService {
    /// Creates a new `LimitService`.
    ///
    /// # Parameters
    /// - `config`: The configuration for the limit provider.
    /// - `plugin_manager`: The plugin manager used to load the limit backend.
    pub fn new<P: PluginManagerApi>(
        config: &Config,
        plugin_manager: &P,
    ) -> Result<Self, LimitProviderError> {
        let backend_driver = plugin_manager
            .get_limit_backend(config.limit.driver.clone())?
            .clone();
        Ok(Self {
            backend_driver,
            model: config.limit.enforcement_model,
        })
    }

    /// Run the operation wrapped with the audit events.
    ///
    /// With the security context the operation is audited fail-closed, without
    /// it the plain event is emitted once the operation has succeeded.
    async fn audited<'f, T, F>(
        &self,
        exec: &ExecutionContext<'_>,
        operation: Operation,
        payload: EventPayload,
        fut: F,
    ) -> Result<T, LimitProviderError>
    where
        F: Future<Output = Result<T, LimitProviderError>> + Send + 'f,
    {
        if let Some(vsc) = exec.ctx() {
            crate::audited_op! {
                dispatcher: &exec.state().event_dispatcher,
                ctx: vsc,
                event: Event::new(operation, payload),
                operation: fut,
                on_audit_error: |_: AuditDispatchError| LimitProviderError::Driver("audit dispatch failed".into()),
            }
        } else {
            let res = fut.await?;
            exec.state()
                .event_dispatcher
                .emit(Event::new(operation, payload))
                .await;
            Ok(res)
        }
    }

    /// Run the operation wrapped with the audit events of every payload.
    async fn audited_many<'f, T: Send + 'f>(
        &self,
        exec: &ExecutionContext<'_>,
        operation: Operation,
        payloads: Vec<EventPayload>,
        fut: BoxFut<'f, T>,
    ) -> Result<T, LimitProviderError> {
        let mut fut = fut;
        for payload in payloads {
            let inner = fut;
            fut = Box::pin(self.audited(exec, operation.clone(), payload, inner));
        }
        fut.await
    }

    /// Ensure that the service exists.
    async fn ensure_service(
        &self,
        exec: &ExecutionContext<'_>,
        id: &str,
    ) -> Result<(), LimitProviderError> {
        if exec
            .state()
            .provider
            .get_catalog_provider()
            .get_service(exec, id)
            .await
            .map_err(|e| LimitProviderError::Driver(e.to_string()))?
            .is_none()
        {
            return Err(LimitProviderError::InvalidReference(format!(
                "service_id: service {id} not found"
            )));
        }
        Ok(())
    }

    /// Ensure that the region exists.
    async fn ensure_region(
        &self,
        exec: &ExecutionContext<'_>,
        id: &str,
    ) -> Result<(), LimitProviderError> {
        if exec
            .state()
            .provider
            .get_catalog_provider()
            .get_region(exec, id)
            .await
            .map_err(|e| LimitProviderError::Driver(e.to_string()))?
            .is_none()
        {
            return Err(LimitProviderError::InvalidReference(format!(
                "region_id: region {id} not found"
            )));
        }
        Ok(())
    }

    /// Validate the references of the new limit and normalize them.
    ///
    /// A project that acts as a domain is turned into the `domain_id`.
    async fn resolve_limit_references(
        &self,
        exec: &ExecutionContext<'_>,
        limit: &mut LimitCreate,
    ) -> Result<(), LimitProviderError> {
        self.ensure_service(exec, &limit.service_id).await?;
        if let Some(region_id) = &limit.region_id {
            self.ensure_region(exec, region_id).await?;
        }
        match (limit.project_id.clone(), limit.domain_id.clone()) {
            (Some(_), Some(_)) | (None, None) => {
                return Err(LimitProviderError::InvalidReference(
                    "exactly one of project_id and domain_id must be provided".into(),
                ));
            }
            (Some(project_id), None) => {
                let project = exec
                    .state()
                    .provider
                    .get_resource_provider()
                    .get_project(exec, &project_id)
                    .await
                    .map_err(|e| LimitProviderError::Driver(e.to_string()))?
                    .ok_or_else(|| {
                        LimitProviderError::InvalidReference(format!(
                            "project_id: project {project_id} not found"
                        ))
                    })?;
                if project.is_domain {
                    limit.domain_id = limit.project_id.take();
                }
            }
            (None, Some(domain_id)) => {
                if exec
                    .state()
                    .provider
                    .get_resource_provider()
                    .get_domain(exec, &domain_id)
                    .await
                    .map_err(|e| LimitProviderError::Driver(e.to_string()))?
                    .is_none()
                {
                    return Err(LimitProviderError::InvalidReference(format!(
                        "domain_id: domain {domain_id} not found"
                    )));
                }
            }
        }
        Ok(())
    }

    /// Get the value specified for the project or domain.
    ///
    /// Falls back to the registered limit for domains.
    async fn specified_value(
        &self,
        exec: &ExecutionContext<'_>,
        limit: &LimitCreate,
        project_id: Option<&str>,
        domain_id: Option<&str>,
    ) -> Result<Option<i32>, LimitProviderError> {
        let params = LimitListParameters {
            domain_id: domain_id.map(String::from),
            project_id: project_id.map(String::from),
            region_id: limit.region_id.clone(),
            resource_name: Some(limit.resource_name.clone()),
            service_id: Some(limit.service_id.clone()),
            ..Default::default()
        };
        // The region filter is absent for the global limits, therefore match
        // the region explicitly.
        if let Some(found) = self
            .backend_driver
            .list_limits(exec.state(), &params)
            .await?
            .into_iter()
            .find(|l| l.region_id == limit.region_id)
        {
            return Ok(Some(found.resource_limit));
        }
        if domain_id.is_some() {
            let params = RegisteredLimitListParameters {
                region_id: limit.region_id.clone(),
                resource_name: Some(limit.resource_name.clone()),
                service_id: Some(limit.service_id.clone()),
                ..Default::default()
            };
            return Ok(self
                .backend_driver
                .list_registered_limits(exec.state(), &params)
                .await?
                .into_iter()
                .find(|l| l.region_id == limit.region_id)
                .map(|l| l.default_limit));
        }
        Ok(None)
    }

    /// Verify that the limits satisfy the configured enforcement model.
    ///
    /// `batch` are limits that are going to be created together with the
    /// verified ones.
    async fn check_limits(
        &self,
        exec: &ExecutionContext<'_>,
        limits: &[LimitCreate],
        batch: &[LimitCreate],
    ) -> Result<(), LimitProviderError> {
        if self.model == LimitEnforcementModel::Flat {
            return Ok(());
        }
        for limit in limits {
            let target = limit
                .project_id
                .as_deref()
                .or(limit.domain_id.as_deref())
                .unwrap_or_default();
            let invalid = |reason: &str| {
                LimitProviderError::InvalidLimit(format!(
                    "the resource limit ({target}, resource_name: {}, resource_limit: {}, \
                     service_id: {}, region_id: {:?}) doesn't satisfy current hierarchy \
                     model: {reason}",
                    limit.resource_name, limit.resource_limit, limit.service_id, limit.region_id
                ))
            };
            if let Some(project_id) = &limit.project_id {
                // Project limit may not exceed the limit of the parent domain.
                let Some(parent_id) = exec
                    .state()
                    .provider
                    .get_resource_provider()
                    .get_project(exec, project_id)
                    .await
                    .map_err(|e| LimitProviderError::Driver(e.to_string()))?
                    .and_then(|p| p.parent_id)
                else {
                    continue;
                };
                let in_batch = batch.iter().find(|l| {
                    l.domain_id.as_deref() == Some(parent_id.as_str())
                        && l.service_id == limit.service_id
                        && l.region_id == limit.region_id
                        && l.resource_name == limit.resource_name
                });
                let parent_value = if let Some(parent) = in_batch {
                    Some(parent.resource_limit)
                } else {
                    self.specified_value(exec, limit, None, Some(&parent_id))
                        .await?
                };
                if let Some(parent_value) = parent_value
                    && exceeds(limit.resource_limit, parent_value)
                {
                    return Err(invalid("limit is bigger than parent"));
                }
            } else if let Some(domain_id) = &limit.domain_id {
                // Domain limit may not be smaller than any of its projects'.
                let mut marker: Option<String> = None;
                loop {
                    let params = ProjectListParametersBuilder::default()
                        .domain_id(Some(domain_id.clone()))
                        .pagination(openstack_keystone_core_types::ListPagination {
                            limit: Some(SCAN_PAGE_SIZE),
                            marker: marker.clone(),
                            page_reverse: false,
                        })
                        .build()
                        .map_err(|e| LimitProviderError::Driver(e.to_string()))?;
                    let page = exec
                        .state()
                        .provider
                        .get_resource_provider()
                        .list_projects(exec, &params)
                        .await
                        .map_err(|e| LimitProviderError::Driver(e.to_string()))?;
                    for project in &page {
                        if let Some(child) = self
                            .specified_value(exec, limit, Some(&project.id), None)
                            .await?
                            && exceeds(child, limit.resource_limit)
                        {
                            return Err(invalid("limit is smaller than child"));
                        }
                    }
                    if (page.len() as u64) < SCAN_PAGE_SIZE {
                        break;
                    }
                    marker = page.last().map(|p| p.id.clone());
                }
            }
        }
        Ok(())
    }
}

#[async_trait]
impl LimitApi for LimitService {
    /// Describe the enforcement model.
    async fn get_limit_model<'a>(
        &self,
        _exec: &ExecutionContext<'a>,
    ) -> Result<LimitModel, LimitProviderError> {
        Ok(match self.model {
            LimitEnforcementModel::Flat => LimitModel {
                name: "flat".into(),
                description: "Limit enforcement and validation does not take project hierarchy \
                              into consideration."
                    .into(),
            },
            LimitEnforcementModel::StrictTwoLevel => LimitModel {
                name: "strict_two_level".into(),
                description: "This model requires project hierarchy never exceeds a depth of two"
                    .into(),
            },
        })
    }

    /// Create registered limits.
    async fn create_registered_limits<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        mut limits: Vec<RegisteredLimitCreate>,
    ) -> Result<Vec<RegisteredLimit>, LimitProviderError> {
        for limit in limits.iter_mut() {
            limit.validate()?;
            self.ensure_service(exec, &limit.service_id).await?;
            if let Some(region_id) = &limit.region_id {
                self.ensure_region(exec, region_id).await?;
            }
            if limit.id.is_none() {
                limit.id = Some(Uuid::new_v4().simple().to_string());
            }
        }
        let payloads = limits
            .iter()
            .map(|l| EventPayload::RegisteredLimit {
                id: l.id.clone().unwrap_or_default(),
            })
            .collect();
        self.audited_many(
            exec,
            Operation::Create,
            payloads,
            Box::pin(
                self.backend_driver
                    .create_registered_limits(exec.state(), limits),
            ),
        )
        .await
    }

    /// Get a registered limit.
    async fn get_registered_limit<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<RegisteredLimit>, LimitProviderError> {
        self.backend_driver
            .get_registered_limit(exec.state(), id)
            .await
    }

    /// List registered limits.
    async fn list_registered_limits<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        params: &RegisteredLimitListParameters,
    ) -> Result<Vec<RegisteredLimit>, LimitProviderError> {
        params.validate()?;
        self.backend_driver
            .list_registered_limits(exec.state(), params)
            .await
    }

    /// Update a registered limit.
    async fn update_registered_limit<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
        data: RegisteredLimitUpdate,
    ) -> Result<RegisteredLimit, LimitProviderError> {
        data.validate()?;
        if let Some(service_id) = &data.service_id {
            self.ensure_service(exec, service_id).await?;
        }
        if let Some(Some(region_id)) = &data.region_id {
            self.ensure_region(exec, region_id).await?;
        }
        self.audited(
            exec,
            Operation::Update,
            EventPayload::RegisteredLimit { id: id.to_string() },
            self.backend_driver
                .update_registered_limit(exec.state(), id, data),
        )
        .await
    }

    /// Delete a registered limit.
    async fn delete_registered_limit<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), LimitProviderError> {
        self.audited(
            exec,
            Operation::Delete,
            EventPayload::RegisteredLimit { id: id.to_string() },
            self.backend_driver
                .delete_registered_limit(exec.state(), id),
        )
        .await
    }

    /// Create limits.
    async fn create_limits<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        mut limits: Vec<LimitCreate>,
    ) -> Result<Vec<Limit>, LimitProviderError> {
        for limit in limits.iter_mut() {
            limit.validate()?;
            self.resolve_limit_references(exec, limit).await?;
            if limit.id.is_none() {
                limit.id = Some(Uuid::new_v4().simple().to_string());
            }
        }
        self.check_limits(exec, &limits, &limits).await?;
        let payloads = limits
            .iter()
            .map(|l| EventPayload::Limit {
                id: l.id.clone().unwrap_or_default(),
            })
            .collect();
        self.audited_many(
            exec,
            Operation::Create,
            payloads,
            Box::pin(self.backend_driver.create_limits(exec.state(), limits)),
        )
        .await
    }

    /// Get a limit.
    async fn get_limit<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<Option<Limit>, LimitProviderError> {
        self.backend_driver.get_limit(exec.state(), id).await
    }

    /// List limits.
    async fn list_limits<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        params: &LimitListParameters,
    ) -> Result<Vec<Limit>, LimitProviderError> {
        params.validate()?;
        self.backend_driver.list_limits(exec.state(), params).await
    }

    /// Update a limit.
    async fn update_limit<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
        data: LimitUpdate,
    ) -> Result<Limit, LimitProviderError> {
        data.validate()?;
        if let Some(resource_limit) = data.resource_limit {
            let existing = self
                .backend_driver
                .get_limit(exec.state(), id)
                .await?
                .ok_or_else(|| LimitProviderError::LimitNotFound(id.to_string()))?;
            let candidate = LimitCreate {
                domain_id: existing.domain_id,
                id: Some(existing.id),
                project_id: existing.project_id,
                region_id: existing.region_id,
                resource_limit,
                resource_name: existing.resource_name,
                service_id: existing.service_id,
                description: None,
            };
            self.check_limits(exec, &[candidate], &[]).await?;
        }
        self.audited(
            exec,
            Operation::Update,
            EventPayload::Limit { id: id.to_string() },
            self.backend_driver.update_limit(exec.state(), id, data),
        )
        .await
    }

    /// Delete a limit.
    async fn delete_limit<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        id: &'a str,
    ) -> Result<(), LimitProviderError> {
        self.audited(
            exec,
            Operation::Delete,
            EventPayload::Limit { id: id.to_string() },
            self.backend_driver.delete_limit(exec.state(), id),
        )
        .await
    }

    /// Delete all limits of the project.
    async fn delete_limits_by_project<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        project_id: &'a str,
    ) -> Result<(), LimitProviderError> {
        self.backend_driver
            .delete_limits_by_project(exec.state(), project_id)
            .await
    }

    /// Delete all limits of the domain.
    async fn delete_limits_by_domain<'a>(
        &self,
        exec: &ExecutionContext<'a>,
        domain_id: &'a str,
    ) -> Result<(), LimitProviderError> {
        self.backend_driver
            .delete_limits_by_domain(exec.state(), domain_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exceeds() {
        assert!(exceeds(5, 3));
        assert!(!exceeds(3, 3));
        assert!(!exceeds(2, 3));
        assert!(exceeds(-1, 3));
        assert!(!exceeds(3, -1));
        assert!(!exceeds(-1, -1));
    }
}
