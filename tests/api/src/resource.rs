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
//! Shared helpers for project and domain CRUD tests.

use derive_builder::Builder;
use eyre::Result;
use openstack_sdk::config::CloudConfig;

use openstack_sdk::AsyncOpenStack;

pub mod domain;
pub mod project;
pub mod project_v4;

pub fn get_system_scope_config() -> Result<CloudConfig> {
    let mut cfg = CloudConfig::from_env()?;
    if let Some(ref mut auth) = cfg.auth {
        auth.project_id = None;
        auth.project_name = None;
        auth.domain_id = None;
        auth.domain_name = None;
        auth.system_scope = Some("all".into());
    }
    Ok(cfg)
}

//
// /// Rescope the client to the given domain.
// pub async fn auth_domain(tc: &mut TestClient, domain_id: &str) -> Result<()>
// {     tc.rescope(Some(Scope::Domain(ScopeDomain {
//         id: Some(domain_id.to_string()),
//         name: None,
//     })))
//     .await?;
//     Ok(())
// }
//
// /// Create a test domain with the current client.
// pub async fn create_test_domain(tc: &TestClient) -> Result<Domain> {
//     let name = format!("test-domain-{}", uuid::Uuid::new_v4());
//     let domain = DomainCreateBuilder::default().name(&name).build()?;
//     domain_api::create_domain(tc, domain).await
// }
//
// /// Create a test domain + project, returning (domain, project) for explicit
// cleanup. pub async fn create_test_project(tc: &TestClient) -> Result<(Domain,
// Project)> {     let domain = create_test_domain(tc).await?;
//     let mut domain_tc = TestClient::default()?;
//     auth_domain(&mut domain_tc, &domain.id).await?;
//     let project = ProjectCreateBuilder::default()
//         .name(format!("test-project-{}", uuid::Uuid::new_v4()))
//         .domain_id(&domain.id)
//         .build()?;
//     let proj = project_api::create_project_scoped(&domain_tc,
// project).await?;     Ok((domain, proj))
// }
