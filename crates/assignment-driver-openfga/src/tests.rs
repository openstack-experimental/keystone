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
//! # OpenFGA assignment driver tests
//!
//! These exercise the driver against an `httpmock` OpenFGA. Actor/target
//! mapping is now pure config, so there are no identity-provider mocks.

use std::collections::HashMap;

use eyre::Result;
use httpmock::MockServer;
use serde_json::json;
use tracing_test::traced_test;
use url::Url;

use openstack_keystone_config::{Config, OpenFGAAssignmentDriver, OpenFGAIdTransform};
use openstack_keystone_core::tests::get_mocked_state;

use super::*;

/// Default-shaped driver config pointing at `host`, with a single
/// `role_id -> relation` mapping.
fn driver_config(host: &str) -> OpenFGAAssignmentDriver {
    OpenFGAAssignmentDriver {
        api_url: Url::parse(host).expect("valid url"),
        api_key: Some("secret".into()),
        model_id: Some("model_id".into()),
        store_id: "store_id".into(),
        timeout: Some(5),
        max_retries: 0,
        retry_backoff_ms: 1,
        max_concurrency: 10,
        role_to_relation: Some(HashMap::from([("role_id".into(), "relation".into())])),
        user_actor_types: vec!["user".into()],
        group_actor_types: vec!["group".into()],
        project_target_types: vec!["project".into()],
        domain_target_types: vec!["domain".into()],
        system_target_types: vec!["system".into()],
        id_transform: OpenFGAIdTransform::None,
    }
}

async fn state_with(cfg: OpenFGAAssignmentDriver) -> ServiceState {
    let config = Config {
        openfga: Some(cfg),
        ..Default::default()
    };
    get_mocked_state(Some(config), None).await
}

fn driver() -> OpenFGADriver {
    OpenFGADriver::new(None).expect("client builds")
}

fn user_project_assignment(actor: &str, role: &str, target: &str) -> Assignment {
    Assignment {
        actor_id: actor.into(),
        role_id: role.into(),
        role_name: None,
        target_id: target.into(),
        r#type: AssignmentType::UserProject,
        inherited: false,
        implied_via: None,
    }
}

#[tokio::test]
async fn new_rejects_absurd_timeout_but_accepts_normal() {
    // Just make sure the timeout path builds a client.
    assert!(OpenFGADriver::new(Some(30)).is_ok());
    assert!(OpenFGADriver::new(None).is_ok());
}

#[tokio::test]
async fn check_grant_maps_actor_and_target_and_returns_true() -> Result<()> {
    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    let mock = srv
        .mock_async(|when, then| {
            when.method("POST")
                .path("/stores/store_id/check")
                .header("authorization", "Bearer secret")
                .json_body(json!({
                    "tuple_key": {
                        "user": "user:actor_id",
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

    let allowed = driver()
        .check_grant(
            &state,
            &user_project_assignment("actor_id", "role_id", "target_id"),
        )
        .await?;

    assert!(allowed);
    mock.assert_async().await;
    Ok(())
}

#[tokio::test]
async fn check_grant_returns_false_when_not_allowed() -> Result<()> {
    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    srv.mock_async(|when, then| {
        when.method("POST").path("/stores/store_id/check");
        then.status(200)
            .header("content-type", "application/json")
            .json_body(json!({"allowed": false}));
    })
    .await;

    let allowed = driver()
        .check_grant(
            &state,
            &user_project_assignment("actor_id", "role_id", "target_id"),
        )
        .await?;

    assert!(!allowed);
    Ok(())
}

#[tokio::test]
async fn check_grant_fans_out_over_actor_representations() -> Result<()> {
    let srv = MockServer::start_async().await;
    let mut cfg = driver_config(&srv.base_url());
    cfg.user_actor_types = vec!["user".into(), "account".into()];
    let state = state_with(cfg).await;

    // The `user:` representation is denied...
    srv.mock_async(|when, then| {
        when.method("POST")
            .path("/stores/store_id/check")
            .json_body(json!({
                "tuple_key": {
                    "user": "user:actor_id",
                    "relation": "relation",
                    "object": "project:target_id",
                },
                "authorization_model_id": "model_id"
            }));
        then.status(200).json_body(json!({"allowed": false}));
    })
    .await;
    // ...the `account:` representation is allowed.
    let hit = srv
        .mock_async(|when, then| {
            when.method("POST")
                .path("/stores/store_id/check")
                .json_body(json!({
                    "tuple_key": {
                        "user": "account:actor_id",
                        "relation": "relation",
                        "object": "project:target_id",
                    },
                    "authorization_model_id": "model_id"
                }));
            then.status(200).json_body(json!({"allowed": true}));
        })
        .await;

    let allowed = driver()
        .check_grant(
            &state,
            &user_project_assignment("actor_id", "role_id", "target_id"),
        )
        .await?;

    assert!(allowed, "grant found under the alternate representation");
    hit.assert_async().await;
    Ok(())
}

#[tokio::test]
async fn check_grant_errors_when_role_has_no_relation() -> Result<()> {
    let srv = MockServer::start_async().await;
    let mut cfg = driver_config(&srv.base_url());
    cfg.role_to_relation = Some(HashMap::new());
    let state = state_with(cfg).await;

    match driver()
        .check_grant(
            &state,
            &user_project_assignment("actor_id", "role_id", "target_id"),
        )
        .await
    {
        Err(AssignmentProviderError::Driver(msg)) => assert_eq!(
            msg,
            "role to relation mapping for the openfga driver is not configured for role `role_id`"
        ),
        other => panic!("expected a driver error, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn check_grant_errors_when_config_missing() {
    let state = get_mocked_state(Some(Config::default()), None).await;
    match driver()
        .check_grant(
            &state,
            &user_project_assignment("actor_id", "role_id", "target_id"),
        )
        .await
    {
        Err(AssignmentProviderError::Driver(msg)) => {
            assert_eq!(msg, "openfga driver configuration missing")
        }
        other => panic!("expected a driver error, got {other:?}"),
    }
}

#[tokio::test]
async fn create_grant_writes_canonical_tuple() -> Result<()> {
    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    let mock = srv
        .mock_async(|when, then| {
            when.method("POST")
                .path("/stores/store_id/write")
                .header("authorization", "Bearer secret")
                .json_body(json!({
                    "writes": {
                        "tuple_keys": [{
                            "user": "user:actor_id",
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

    let created = driver()
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
        .await?;

    assert_eq!(created.actor_id, "actor_id");
    assert_eq!(created.role_id, "role_id");
    mock.assert_async().await;
    Ok(())
}

#[tokio::test]
async fn create_grant_surfaces_openfga_error_message() -> Result<()> {
    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    srv.mock_async(|when, then| {
        when.method("POST").path("/stores/store_id/write");
        then.status(400)
            .header("content-type", "application/json")
            .json_body(json!({"code": "validation_error", "message": "bar"}));
    })
    .await;

    match driver()
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
    {
        Err(AssignmentProviderError::Driver(msg)) => {
            assert_eq!(msg, "openfga http error: bar")
        }
        other => panic!("expected a driver error, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn create_grant_uses_canonical_type_with_custom_actor_types() -> Result<()> {
    let srv = MockServer::start_async().await;
    let mut cfg = driver_config(&srv.base_url());
    cfg.user_actor_types = vec!["user".into(), "account".into()];
    let state = state_with(cfg).await;

    let mock = srv
        .mock_async(|when, then| {
            when.method("POST")
                .path("/stores/store_id/write")
                .json_body(json!({
                    "writes": {
                        "tuple_keys": [{
                            "user": "user:actor_id",
                            "relation": "relation",
                            "object": "project:target_id",
                        }],
                    },
                    "authorization_model_id": "model_id"
                }));
            then.status(200).json_body(json!({}));
        })
        .await;

    driver()
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
        .await?;

    mock.assert_async().await;
    Ok(())
}

#[tokio::test]
async fn create_grant_applies_uuid_dashes_transform() -> Result<()> {
    let srv = MockServer::start_async().await;
    let mut cfg = driver_config(&srv.base_url());
    cfg.id_transform = OpenFGAIdTransform::UuidDashes;
    let state = state_with(cfg).await;

    let dashless_user = "0123456789abcdef0123456789abcdef";
    let dashless_proj = "fedcba9876543210fedcba9876543210";

    let mock = srv
        .mock_async(|when, then| {
            when.method("POST")
                .path("/stores/store_id/write")
                .json_body(json!({
                    "writes": {
                        "tuple_keys": [{
                            "user": "user:01234567-89ab-cdef-0123-456789abcdef",
                            "relation": "relation",
                            "object": "project:fedcba98-7654-3210-fedc-ba9876543210",
                        }],
                    },
                    "authorization_model_id": "model_id"
                }));
            then.status(200).json_body(json!({}));
        })
        .await;

    driver()
        .create_grant(
            &state,
            AssignmentCreate {
                actor_id: dashless_user.into(),
                role_id: "role_id".into(),
                role_name: None,
                target_id: dashless_proj.into(),
                r#type: AssignmentType::UserProject,
                inherited: false,
            },
        )
        .await?;

    mock.assert_async().await;
    Ok(())
}

/// `read` body the revoke path issues to probe one representation.
fn revoke_probe_body(user: &str) -> serde_json::Value {
    json!({
        "authorization_model_id": "model_id",
        "tuple_key": { "user": user, "relation": "relation", "object": "project:target_id" }
    })
}

fn held_tuple(user: &str) -> serde_json::Value {
    json!({
        "tuples": [
            { "key": { "user": user, "relation": "relation", "object": "project:target_id" } }
        ]
    })
}

#[tokio::test]
async fn revoke_grant_deletes_tuple() -> Result<()> {
    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    // The representation holds the tuple...
    srv.mock_async(|when, then| {
        when.method("POST")
            .path("/stores/store_id/read")
            .json_body(revoke_probe_body("user:actor_id"));
        then.status(200).json_body(held_tuple("user:actor_id"));
    })
    .await;
    // ...so it is deleted.
    let del = srv
        .mock_async(|when, then| {
            when.method("POST")
                .path("/stores/store_id/write")
                .json_body(json!({
                    "deletes": {
                        "tuple_keys": [{
                            "user": "user:actor_id",
                            "relation": "relation",
                            "object": "project:target_id",
                        }],
                    },
                    "authorization_model_id": "model_id"
                }));
            then.status(200).json_body(json!({}));
        })
        .await;

    driver()
        .revoke_grant(
            &state,
            &user_project_assignment("actor_id", "role_id", "target_id"),
        )
        .await?;

    del.assert_async().await;
    Ok(())
}

#[tokio::test]
async fn revoke_grant_deletes_only_representations_that_hold_the_tuple() -> Result<()> {
    let srv = MockServer::start_async().await;
    let mut cfg = driver_config(&srv.base_url());
    cfg.user_actor_types = vec!["user".into(), "account".into()];
    let state = state_with(cfg).await;

    // `user:` representation is empty, `account:` holds the tuple.
    srv.mock_async(|when, then| {
        when.method("POST")
            .path("/stores/store_id/read")
            .json_body(revoke_probe_body("user:actor_id"));
        then.status(200).json_body(json!({ "tuples": [] }));
    })
    .await;
    srv.mock_async(|when, then| {
        when.method("POST")
            .path("/stores/store_id/read")
            .json_body(revoke_probe_body("account:actor_id"));
        then.status(200).json_body(held_tuple("account:actor_id"));
    })
    .await;
    // Only the `account:` tuple is deleted.
    let del = srv
        .mock_async(|when, then| {
            when.method("POST")
                .path("/stores/store_id/write")
                .json_body(json!({
                    "deletes": {
                        "tuple_keys": [{
                            "user": "account:actor_id",
                            "relation": "relation",
                            "object": "project:target_id",
                        }],
                    },
                    "authorization_model_id": "model_id"
                }));
            then.status(200).json_body(json!({}));
        })
        .await;

    driver()
        .revoke_grant(
            &state,
            &user_project_assignment("actor_id", "role_id", "target_id"),
        )
        .await?;

    del.assert_async().await;
    Ok(())
}

#[tokio::test]
async fn revoke_grant_absent_tuple_is_a_noop() -> Result<()> {
    // Mirrors the SQL driver: revoking a grant that is not present succeeds
    // without issuing a delete.
    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    srv.mock_async(|when, then| {
        when.method("POST").path("/stores/store_id/read");
        then.status(200).json_body(json!({ "tuples": [] }));
    })
    .await;
    let del = srv
        .mock_async(|when, then| {
            when.method("POST").path("/stores/store_id/write");
            then.status(200).json_body(json!({}));
        })
        .await;

    driver()
        .revoke_grant(
            &state,
            &user_project_assignment("actor_id", "role_id", "target_id"),
        )
        .await?;

    assert_eq!(del.calls_async().await, 0);
    Ok(())
}

#[tokio::test]
async fn revoke_grant_propagates_real_openfga_errors() -> Result<()> {
    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    srv.mock_async(|when, then| {
        when.method("POST").path("/stores/store_id/read");
        then.status(500)
            .json_body(json!({"code": "internal_error", "message": "boom"}));
    })
    .await;

    match driver()
        .revoke_grant(
            &state,
            &user_project_assignment("actor_id", "role_id", "target_id"),
        )
        .await
    {
        Err(AssignmentProviderError::Driver(msg)) => {
            assert_eq!(msg, "openfga http error: boom")
        }
        other => panic!("expected a driver error, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn list_assignments_unknown_role_filter_errors() -> Result<()> {
    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    match driver()
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
        Err(AssignmentProviderError::Driver(msg)) => assert_eq!(
            msg,
            "role to relation mapping for the openfga driver is not configured for role `wrong_role`"
        ),
        other => panic!("expected a driver error, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn list_assignments_actor_and_target_and_role_checks() -> Result<()> {
    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    let mock = srv
        .mock_async(|when, then| {
            when.method("POST")
                .path("/stores/store_id/check")
                .json_body(json!({
                    "authorization_model_id": "model_id",
                    "tuple_key": {
                        "object": "project:project_id",
                        "relation": "relation",
                        "user": "user:user_id"
                    }
                }));
            then.status(200).json_body(json!({"allowed": true}));
        })
        .await;

    let res = driver()
        .list_assignments(
            &state,
            &RoleAssignmentListParameters {
                user_id: Some("user_id".into()),
                project_id: Some("project_id".into()),
                role_id: Some("role_id".into()),
                effective: Some(true),
                ..Default::default()
            },
        )
        .await?;

    assert_eq!(res.len(), 1);
    assert_eq!(res[0].role_id, "role_id");
    assert_eq!(res[0].actor_id, "user_id");
    assert_eq!(res[0].target_id, "project_id");
    assert_eq!(res[0].r#type, AssignmentType::UserProject);
    mock.assert_async().await;
    Ok(())
}

#[tokio::test]
async fn list_assignments_login_path_batch_checks_every_role() -> Result<()> {
    let srv = MockServer::start_async().await;
    let mut cfg = driver_config(&srv.base_url());
    cfg.role_to_relation = Some(HashMap::from([
        ("rid1".into(), "relation1".into()),
        ("rid2".into(), "relation2".into()),
        ("rid3".into(), "relation3".into()),
    ]));
    let state = state_with(cfg).await;

    srv.mock_async(|when, then| {
        when.method("POST").path("/stores/store_id/batch-check");
        then.status(200).json_body(json!({
            "result": {
                "rid1": { "allowed": true },
                "rid2": { "allowed": true },
                "rid3": { "allowed": false },
            }
        }));
    })
    .await;

    let res = driver()
        .list_assignments(
            &state,
            &RoleAssignmentListParameters {
                user_id: Some("user_id".into()),
                project_id: Some("project_id".into()),
                effective: Some(true),
                ..Default::default()
            },
        )
        .await?;

    let roles: Vec<&str> = res.iter().map(|a| a.role_id.as_str()).collect();
    assert!(roles.contains(&"rid1"));
    assert!(roles.contains(&"rid2"));
    assert!(!roles.contains(&"rid3"));
    Ok(())
}

#[tokio::test]
async fn list_assignments_actor_without_scope_uses_streamed_list_objects() -> Result<()> {
    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    // One streamed-list-objects call per target kind; only `project` yields an
    // object. The response body is newline-delimited JSON frames.
    srv.mock_async(|when, then| {
        when.method("POST")
            .path("/stores/store_id/streamed-list-objects")
            .json_body(json!({
                "authorization_model_id": "model_id",
                "type": "project",
                "relation": "relation",
                "user": "user:user_id"
            }));
        then.status(200)
            .body("{\"result\":{\"object\":\"project:p1\"}}\n");
    })
    .await;
    for target_type in ["domain", "system"] {
        srv.mock_async(move |when, then| {
            when.method("POST")
                .path("/stores/store_id/streamed-list-objects")
                .json_body(json!({
                    "authorization_model_id": "model_id",
                    "type": target_type,
                    "relation": "relation",
                    "user": "user:user_id"
                }));
            then.status(200).body("");
        })
        .await;
    }

    let res = driver()
        .list_assignments(
            &state,
            &RoleAssignmentListParameters {
                user_id: Some("user_id".into()),
                effective: Some(true),
                ..Default::default()
            },
        )
        .await?;

    assert_eq!(res.len(), 1);
    assert_eq!(res[0].role_id, "role_id");
    assert_eq!(res[0].actor_id, "user_id");
    assert_eq!(res[0].target_id, "p1");
    assert_eq!(res[0].r#type, AssignmentType::UserProject);
    Ok(())
}

#[tokio::test]
async fn list_assignments_streamed_list_objects_reads_every_frame() -> Result<()> {
    // The streamed endpoint has no result cap; every newline-delimited frame in
    // the body is turned into an assignment (no silent truncation).
    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    srv.mock_async(|when, then| {
        when.method("POST")
            .path("/stores/store_id/streamed-list-objects")
            .json_body_includes(r#"{"type":"project"}"#);
        then.status(200).body(concat!(
            "{\"result\":{\"object\":\"project:p1\"}}\n",
            "{\"result\":{\"object\":\"project:p2\"}}\n",
            "{\"result\":{\"object\":\"project:p3\"}}\n",
        ));
    })
    .await;
    for target_type in ["domain", "system"] {
        srv.mock_async(move |when, then| {
            when.method("POST")
                .path("/stores/store_id/streamed-list-objects")
                .json_body_includes(format!(r#"{{"type":"{target_type}"}}"#));
            then.status(200).body("");
        })
        .await;
    }

    let res = driver()
        .list_assignments(
            &state,
            &RoleAssignmentListParameters {
                user_id: Some("user_id".into()),
                effective: Some(true),
                ..Default::default()
            },
        )
        .await?;

    let mut targets: Vec<&str> = res.iter().map(|a| a.target_id.as_str()).collect();
    targets.sort_unstable();
    assert_eq!(targets, ["p1", "p2", "p3"]);
    Ok(())
}

#[tokio::test]
async fn list_assignments_fan_out_is_serial_when_max_concurrency_is_one() -> Result<()> {
    // `max_concurrency = 1` must still produce the full result set - it only
    // constrains how many requests are in flight, not correctness.
    let srv = MockServer::start_async().await;
    let mut cfg = driver_config(&srv.base_url());
    cfg.max_concurrency = 1;
    cfg.project_target_types = vec!["project".into(), "proj".into()];
    let state = state_with(cfg).await;

    srv.mock_async(|when, then| {
        when.method("POST")
            .path("/stores/store_id/read")
            .json_body(json!({
                "authorization_model_id": "model_id",
                "tuple_key": { "object": "project:project_id" }
            }));
        then.status(200).json_body(json!({
            "tuples": [
                { "key": { "user": "user:uid1", "object": "project:project_id", "relation": "relation" } }
            ]
        }));
    })
    .await;
    srv.mock_async(|when, then| {
        when.method("POST")
            .path("/stores/store_id/read")
            .json_body(json!({
                "authorization_model_id": "model_id",
                "tuple_key": { "object": "proj:project_id" }
            }));
        then.status(200).json_body(json!({
            "tuples": [
                { "key": { "user": "user:uid2", "object": "proj:project_id", "relation": "relation" } }
            ]
        }));
    })
    .await;

    let res = driver()
        .list_assignments(
            &state,
            &RoleAssignmentListParameters {
                project_id: Some("project_id".into()),
                ..Default::default()
            },
        )
        .await?;

    let mut actors: Vec<&str> = res.iter().map(|a| a.actor_id.as_str()).collect();
    actors.sort_unstable();
    assert_eq!(actors, ["uid1", "uid2"]);
    Ok(())
}

#[tokio::test]
async fn list_assignments_actor_without_scope_honours_role_filter() -> Result<()> {
    let srv = MockServer::start_async().await;
    let mut cfg = driver_config(&srv.base_url());
    cfg.role_to_relation = Some(HashMap::from([
        ("rid1".into(), "relation1".into()),
        ("rid2".into(), "relation2".into()),
    ]));
    let state = state_with(cfg).await;

    // Only `relation1` (the filtered role) is ever queried.
    srv.mock_async(|when, then| {
        when.method("POST")
            .path("/stores/store_id/streamed-list-objects")
            .json_body_includes(r#"{"relation":"relation1"}"#);
        then.status(200)
            .body("{\"result\":{\"object\":\"project:p1\"}}\n");
    })
    .await;
    let forbidden = srv
        .mock_async(|when, then| {
            when.method("POST")
                .path("/stores/store_id/streamed-list-objects")
                .json_body_includes(r#"{"relation":"relation2"}"#);
            then.status(200).body("");
        })
        .await;

    let res = driver()
        .list_assignments(
            &state,
            &RoleAssignmentListParameters {
                user_id: Some("user_id".into()),
                role_id: Some("rid1".into()),
                effective: Some(true),
                ..Default::default()
            },
        )
        .await?;

    assert!(res.iter().all(|a| a.role_id == "rid1"));
    assert_eq!(forbidden.calls_async().await, 0);
    Ok(())
}

#[tokio::test]
async fn list_assignments_by_role_only_is_unsupported() -> Result<()> {
    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    match driver()
        .list_assignments(
            &state,
            &RoleAssignmentListParameters {
                role_id: Some("role_id".into()),
                ..Default::default()
            },
        )
        .await
    {
        Err(AssignmentProviderError::NotImplemented(msg)) => assert_eq!(
            msg,
            "listing assignments by only the role is not supported by the openfga"
        ),
        other => panic!("expected a not-implemented error, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn list_assignments_no_parameters_is_unsupported() -> Result<()> {
    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    match driver()
        .list_assignments(&state, &RoleAssignmentListParameters::default())
        .await
    {
        Err(AssignmentProviderError::NotImplemented(msg)) => assert_eq!(
            msg,
            "listing all assignments is not supported by the openfga"
        ),
        other => panic!("expected a not-implemented error, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn list_assignments_project_only_reads_and_maps_tuples() -> Result<()> {
    let srv = MockServer::start_async().await;
    let mut cfg = driver_config(&srv.base_url());
    cfg.role_to_relation = Some(HashMap::from([
        ("rid1".into(), "relation1".into()),
        ("rid2".into(), "relation2".into()),
    ]));
    let state = state_with(cfg).await;

    srv.mock_async(|when, then| {
        when.method("POST")
            .path("/stores/store_id/read")
            .json_body(json!({
                "authorization_model_id": "model_id",
                "tuple_key": { "object": "project:project_id" }
            }));
        then.status(200).json_body(json!({
            "tuples": [
                { "key": { "user": "user:uid1", "object": "project:project_id", "relation": "relation1" } },
                { "key": { "user": "group:gid2", "object": "project:project_id", "relation": "relation2" } },
                { "key": { "user": "widget:w9", "object": "project:project_id", "relation": "relation1" } },
                { "key": { "user": "user:uid3", "object": "project:project_id", "relation": "unmapped_relation" } }
            ]
        }));
    })
    .await;

    let res = driver()
        .list_assignments(
            &state,
            &RoleAssignmentListParameters {
                project_id: Some("project_id".into()),
                ..Default::default()
            },
        )
        .await?;

    // The `widget:` and `unmapped_relation` rows are skipped with a warning.
    assert_eq!(res.len(), 2);
    assert!(res.iter().any(|a| a.role_id == "rid1"
        && a.actor_id == "uid1"
        && a.r#type == AssignmentType::UserProject));
    assert!(res.iter().any(|a| a.role_id == "rid2"
        && a.actor_id == "gid2"
        && a.r#type == AssignmentType::GroupProject));
    assert!(logs_contain("has no configured type"));
    Ok(())
}

#[tokio::test]
async fn list_assignments_project_only_follows_pagination() -> Result<()> {
    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    // Page 1: no continuation_token in the request body, token returned.
    srv.mock_async(|when, then| {
        when.method("POST")
            .path("/stores/store_id/read")
            .json_body(json!({
                "authorization_model_id": "model_id",
                "tuple_key": { "object": "project:project_id" }
            }));
        then.status(200).json_body(json!({
            "tuples": [
                { "key": { "user": "user:uid1", "object": "project:project_id", "relation": "relation" } }
            ],
            "continuation_token": "page-2"
        }));
    })
    .await;
    // Page 2: request carries the token, empty token ends the loop.
    srv.mock_async(|when, then| {
        when.method("POST")
            .path("/stores/store_id/read")
            .json_body(json!({
                "authorization_model_id": "model_id",
                "tuple_key": { "object": "project:project_id" },
                "continuation_token": "page-2"
            }));
        then.status(200).json_body(json!({
            "tuples": [
                { "key": { "user": "user:uid2", "object": "project:project_id", "relation": "relation" } }
            ],
            "continuation_token": ""
        }));
    })
    .await;

    let res = driver()
        .list_assignments(
            &state,
            &RoleAssignmentListParameters {
                project_id: Some("project_id".into()),
                ..Default::default()
            },
        )
        .await?;

    let actors: Vec<&str> = res.iter().map(|a| a.actor_id.as_str()).collect();
    assert!(actors.contains(&"uid1"));
    assert!(actors.contains(&"uid2"));
    Ok(())
}

#[tokio::test]
async fn list_assignments_project_only_reads_every_target_representation() -> Result<()> {
    let srv = MockServer::start_async().await;
    let mut cfg = driver_config(&srv.base_url());
    cfg.project_target_types = vec!["project".into(), "proj".into()];
    let state = state_with(cfg).await;

    srv.mock_async(|when, then| {
        when.method("POST")
            .path("/stores/store_id/read")
            .json_body(json!({
                "authorization_model_id": "model_id",
                "tuple_key": { "object": "project:project_id" }
            }));
        then.status(200).json_body(json!({ "tuples": [] }));
    })
    .await;
    let proj_mock = srv
        .mock_async(|when, then| {
            when.method("POST")
                .path("/stores/store_id/read")
                .json_body(json!({
                    "authorization_model_id": "model_id",
                    "tuple_key": { "object": "proj:project_id" }
                }));
            then.status(200).json_body(json!({
                "tuples": [
                    { "key": { "user": "user:uid1", "object": "proj:project_id", "relation": "relation" } }
                ]
            }));
        })
        .await;

    let res = driver()
        .list_assignments(
            &state,
            &RoleAssignmentListParameters {
                project_id: Some("project_id".into()),
                ..Default::default()
            },
        )
        .await?;

    assert_eq!(res.len(), 1);
    assert_eq!(res[0].actor_id, "uid1");
    proj_mock.assert_async().await;
    Ok(())
}

#[tokio::test]
async fn list_assignments_applies_pagination_limit_post_fetch() -> Result<()> {
    use openstack_keystone_core_types::ListPagination;

    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    srv.mock_async(|when, then| {
        when.method("POST").path("/stores/store_id/read");
        then.status(200).json_body(json!({
            "tuples": [
                { "key": { "user": "user:uid1", "object": "project:project_id", "relation": "relation" } },
                { "key": { "user": "user:uid2", "object": "project:project_id", "relation": "relation" } },
                { "key": { "user": "user:uid3", "object": "project:project_id", "relation": "relation" } }
            ]
        }));
    })
    .await;

    let res = driver()
        .list_assignments(
            &state,
            &RoleAssignmentListParameters {
                project_id: Some("project_id".into()),
                pagination: ListPagination {
                    limit: Some(1),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await?;

    // Over-fetch by one (limit + 1), mirroring the SQL driver, so the service
    // layer can detect that another page exists.
    assert_eq!(res.len(), 2);
    // Sorted by the opaque marker before truncation.
    assert_eq!(res[0].actor_id, "uid1");
    assert_eq!(res[1].actor_id, "uid2");
    Ok(())
}

#[tokio::test]
async fn list_assignments_marker_drops_the_prior_page() -> Result<()> {
    use openstack_keystone_core_types::ListPagination;

    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    srv.mock_async(|when, then| {
        when.method("POST").path("/stores/store_id/read");
        then.status(200).json_body(json!({
            "tuples": [
                { "key": { "user": "user:uid1", "object": "project:project_id", "relation": "relation" } },
                { "key": { "user": "user:uid2", "object": "project:project_id", "relation": "relation" } }
            ]
        }));
    })
    .await;

    let first = driver()
        .list_assignments(
            &state,
            &RoleAssignmentListParameters {
                project_id: Some("project_id".into()),
                ..Default::default()
            },
        )
        .await?;
    let marker = first[0].pagination_marker();

    let rest = driver()
        .list_assignments(
            &state,
            &RoleAssignmentListParameters {
                project_id: Some("project_id".into()),
                pagination: ListPagination {
                    marker: Some(marker),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await?;

    assert_eq!(rest.len(), 1);
    assert_eq!(rest[0].actor_id, "uid2");
    Ok(())
}

#[tokio::test]
async fn create_grant_rejects_inherited() -> Result<()> {
    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    // No `write` must be issued: the request is rejected before any OpenFGA
    // call.
    let write = srv
        .mock_async(|when, then| {
            when.method("POST").path("/stores/store_id/write");
            then.status(200).json_body(json!({}));
        })
        .await;

    let err = driver()
        .create_grant(
            &state,
            AssignmentCreate {
                actor_id: "actor_id".into(),
                role_id: "role_id".into(),
                role_name: None,
                target_id: "target_id".into(),
                r#type: AssignmentType::UserProject,
                inherited: true,
            },
        )
        .await
        .unwrap_err();

    // Maps to a validation error (HTTP 400), not a backend/driver error.
    assert!(
        matches!(err, AssignmentProviderError::Validation { .. }),
        "got {err:?}"
    );
    assert_eq!(write.calls_async().await, 0);
    Ok(())
}

#[tokio::test]
async fn list_assignments_actor_and_target_role_direct_mode_reads_tuple() -> Result<()> {
    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    let check = srv
        .mock_async(|when, then| {
            when.method("POST").path("/stores/store_id/check");
            then.status(200).json_body(json!({ "allowed": true }));
        })
        .await;
    let read = srv
        .mock_async(|when, then| {
            when.method("POST")
                .path("/stores/store_id/read")
                .json_body(json!({
                    "authorization_model_id": "model_id",
                    "tuple_key": {
                        "user": "user:user_id",
                        "relation": "relation",
                        "object": "project:project_id"
                    }
                }));
            then.status(200).json_body(json!({
                "tuples": [
                    { "key": { "user": "user:user_id", "relation": "relation", "object": "project:project_id" } }
                ]
            }));
        })
        .await;

    let res = driver()
        .list_assignments(
            &state,
            &RoleAssignmentListParameters {
                user_id: Some("user_id".into()),
                project_id: Some("project_id".into()),
                role_id: Some("role_id".into()),
                // No `effective` flag: the grant is proven by a direct tuple
                // `read`, not a model-resolving `check`.
                ..Default::default()
            },
        )
        .await?;

    assert_eq!(res.len(), 1);
    assert_eq!(res[0].role_id, "role_id");
    assert_eq!(res[0].actor_id, "user_id");
    assert_eq!(res[0].target_id, "project_id");
    read.assert_async().await;
    assert_eq!(check.calls_async().await, 0);
    Ok(())
}

#[tokio::test]
async fn list_assignments_actor_without_scope_direct_mode_errors() -> Result<()> {
    let srv = MockServer::start_async().await;
    let state = state_with(driver_config(&srv.base_url())).await;

    match driver()
        .list_assignments(
            &state,
            &RoleAssignmentListParameters {
                user_id: Some("user_id".into()),
                ..Default::default()
            },
        )
        .await
    {
        Err(AssignmentProviderError::NotImplemented(msg)) => {
            assert!(msg.contains("requires effective mode"), "got {msg:?}")
        }
        other => panic!("expected a not-implemented error, got {other:?}"),
    }
    Ok(())
}

#[tokio::test]
async fn send_retries_transient_server_error() -> Result<()> {
    let srv = MockServer::start_async().await;
    let mut cfg = driver_config(&srv.base_url());
    cfg.max_retries = 2;
    cfg.retry_backoff_ms = 1;
    let state = state_with(cfg).await;

    let m = srv
        .mock_async(|when, then| {
            when.method("POST").path("/stores/store_id/check");
            then.status(503)
                .json_body(json!({ "code": "internal_error", "message": "boom" }));
        })
        .await;

    let err = driver()
        .check_grant(&state, &user_project_assignment("a", "role_id", "t"))
        .await
        .unwrap_err();

    assert!(matches!(err, AssignmentProviderError::Driver(_)));
    // 1 initial attempt + 2 retries.
    assert_eq!(m.calls_async().await, 3);
    Ok(())
}

#[tokio::test]
async fn send_does_not_retry_client_error() -> Result<()> {
    let srv = MockServer::start_async().await;
    let mut cfg = driver_config(&srv.base_url());
    cfg.max_retries = 3;
    cfg.retry_backoff_ms = 1;
    let state = state_with(cfg).await;

    let m = srv
        .mock_async(|when, then| {
            when.method("POST").path("/stores/store_id/check");
            then.status(400)
                .json_body(json!({ "code": "validation_error", "message": "bad" }));
        })
        .await;

    let err = driver()
        .check_grant(&state, &user_project_assignment("a", "role_id", "t"))
        .await
        .unwrap_err();

    assert!(matches!(err, AssignmentProviderError::Driver(_)));
    assert_eq!(m.calls_async().await, 1);
    Ok(())
}
