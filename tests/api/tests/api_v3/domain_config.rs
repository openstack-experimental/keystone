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
//! Live end-to-end coverage of ADR 0034 §6: binding a domain to an
//! assignment backend (`assignment/driver` in the domain-config API) is a
//! role-minting surface reserved for cloud admins.
//!
//! A cloud (system) admin can write it on every shape; a non-system caller
//! is refused it by the real OPA policy over real HTTP.
//!
//! Two ADR aspects are covered elsewhere, not here:
//!
//! - **The domain-`manager` carve-out** — a domain manager may write every
//!   other group of their own domain but not `assignment` — needs a
//!   domain-scoped non-admin token, which the v3 API cannot mint (there is
//!   no domain role-grant route; only project and system). It is verified in
//!   `policy/domain_config/{create,update}_test.rego` and the
//!   `crates/keystone/src/api/v3/domain_config/group.rs` handler tests.
//! - **Provisioning a named OpenFGA backend and routing a domain onto it** —
//!   the live server runs a fixed sql-only `[assignment]` config. That path
//!   is covered by `tests/integration/src/assignment_per_domain.rs`.

use eyre::Result;
use serde_json::Value;

use test_api::asserts::assert_forbidden;
use test_api::common::get_system_scope_session;
use test_api::domain_config::{
    driver_body, get_domain_config_group, patch_domain_config_group, patch_domain_config_option,
    replace_domain_config,
};
use test_api::fixtures::{ProjectScopedUser, warn_on_cleanup_failure};
use test_api::guard::ResourceGuard;
use test_api::resource::domain::create_test_domain;

fn stored_driver(config: &Value) -> Option<&str> {
    config.pointer("/assignment/driver").and_then(Value::as_str)
}

/// A cloud admin writes `assignment/driver` for a fresh domain and reads it
/// back — the positive half of the §6 contract.
#[tokio::test]
async fn test_cloud_admin_binds_the_assignment_driver() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let domain = create_test_domain(&admin).await?;

    let result: Result<Value> = async {
        replace_domain_config(&admin, &domain.id, driver_body("assignment", "sql")).await?;
        get_domain_config_group(&admin, &domain.id, "assignment").await
    }
    .await;

    let cleanup = domain.delete().await;
    let stored = result?;
    cleanup?;

    assert_eq!(
        stored_driver(&stored),
        Some("sql"),
        "the cloud admin's assignment binding must round-trip through the config API"
    );
    Ok(())
}

/// A non-system caller (here a project-scoped `manager` of the domain) is
/// refused the `assignment` binding on every write shape — whole-config
/// `PUT`, group `PATCH`, and option `PATCH`.
#[tokio::test]
async fn test_a_non_system_caller_is_refused_the_assignment_binding() -> Result<()> {
    let admin = get_system_scope_session().await?;
    let domain = create_test_domain(&admin).await?;

    // A driver is already bound, so the writes under test are updates, not
    // first writes — the policy denial, not a validation error, is the
    // failure being asserted.
    if let Err(error) =
        replace_domain_config(&admin, &domain.id, driver_body("assignment", "sql")).await
    {
        warn_on_cleanup_failure("adr34 domain", domain.delete().await);
        return Err(error);
    }

    let manager = match ProjectScopedUser::provision(&admin, &domain.id, "manager").await {
        Ok(manager) => manager,
        Err(error) => {
            warn_on_cleanup_failure("adr34 domain", domain.delete().await);
            return Err(error);
        }
    };

    let whole = replace_domain_config(
        &manager.session,
        &domain.id,
        driver_body("assignment", "openfga"),
    )
    .await;
    let group = patch_domain_config_group(
        &manager.session,
        &domain.id,
        "assignment",
        driver_body("assignment", "openfga"),
    )
    .await;
    let option = patch_domain_config_option(
        &manager.session,
        &domain.id,
        "assignment",
        "driver",
        driver_body("assignment", "openfga"),
    )
    .await;

    let manager_cleanup = manager.cleanup().await;
    let domain_cleanup = domain.delete().await;

    assert_forbidden(
        whole,
        "a non-system caller must not replace a config carrying an assignment block",
    );
    assert_forbidden(
        group,
        "a non-system caller must not write the assignment group",
    );
    assert_forbidden(
        option,
        "a non-system caller must not write assignment/driver",
    );
    manager_cleanup?;
    domain_cleanup?;
    Ok(())
}
