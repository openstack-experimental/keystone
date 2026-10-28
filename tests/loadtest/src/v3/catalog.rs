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

//! Catalog churn: region, service and endpoint are created, read, updated,
//! listed and deleted in every iteration.

use goose::prelude::*;
use serde_json::json;
use uuid::Uuid;

use crate::v3::util::{Undo, admin_token, call, create};

pub async fn cycle(user: &mut GooseUser) -> TransactionResult {
    let mut undo = Undo::default();
    let res = run(user, &mut undo).await;
    undo.run(user).await;
    res
}

async fn run(user: &mut GooseUser, undo: &mut Undo) -> TransactionResult {
    let token = admin_token(user);
    let uniq = Uuid::new_v4().as_simple().to_string();

    let Some(region_id) = create(
        user,
        undo,
        "regions",
        "region",
        json!({"region": {"description": format!("loadtest region {uniq}")}}),
        "POST /v3/regions",
        "DELETE /v3/regions/:id",
    )
    .await?
    else {
        return Ok(());
    };
    let Some(service_id) = create(
        user,
        undo,
        "services",
        "service",
        json!({"service": {
            "type": "loadtest",
            "name": format!("loadtest-svc-{uniq}"),
            "enabled": true,
        }}),
        "POST /v3/services",
        "DELETE /v3/services/:id",
    )
    .await?
    else {
        return Ok(());
    };
    let Some(endpoint_id) = create(
        user,
        undo,
        "endpoints",
        "endpoint",
        json!({"endpoint": {
            "service_id": service_id,
            "region_id": region_id,
            "interface": "public",
            "url": format!("http://loadtest-{uniq}.example.com:8080/v1"),
            "enabled": true,
        }}),
        "POST /v3/endpoints",
        "DELETE /v3/endpoints/:id",
    )
    .await?
    else {
        return Ok(());
    };

    let get = |name: &'static str, path: String| (name, path);
    for (name, path) in [
        get("GET /v3/regions/:id", format!("/v3/regions/{region_id}")),
        get("GET /v3/services/:id", format!("/v3/services/{service_id}")),
        get(
            "GET /v3/endpoints/:id",
            format!("/v3/endpoints/{endpoint_id}"),
        ),
        get(
            "GET /v3/endpoints (by service)",
            format!("/v3/endpoints?service_id={service_id}"),
        ),
        get("GET /v3/services", "/v3/services".to_string()),
    ] {
        call(user, GooseMethod::Get, &path, name, None, Some(&token)).await?;
    }
    let patch =
        json!({"service": {"name": format!("loadtest-svc-{}", Uuid::new_v4().as_simple())}});
    call(
        user,
        GooseMethod::Patch,
        &format!("/v3/services/{service_id}"),
        "PATCH /v3/services/:id",
        Some(&patch),
        Some(&token),
    )
    .await?;
    Ok(())
}
