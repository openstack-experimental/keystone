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
//!
//! Keystone role assignments are stored as OpenFGA relationship tuples. The
//! Keystone role id is mapped to an OpenFGA relation name via the
//! `[openfga] role_to_relation` config; actors and targets are mapped to
//! OpenFGA objects by [`types::ObjectMapper`] (stateless, config-driven).
//!
//! `Assignment::inherited` is intentionally never encoded into a tuple: the
//! OpenFGA authorization model performs the cascading itself, so every stored
//! tuple is implicitly inheritable through the model's userset rewrite rules.
//! `openfga_read` (raw tuple listing) therefore only surfaces the direct
//! tuples that were written, while `check`/`batch-check` resolve direct and
//! inherited grants alike.
//!
//! ## Authorization-model assumptions
//!
//! This driver does not resolve group membership or role implication itself.
//! It assumes the OpenFGA authorization model does both:
//!
//! - **Group membership** must be represented in OpenFGA (e.g. a `member`
//!   relation on the group type) so that a `check` for a user picks up grants
//!   made to that user's groups. Keystone's identity backend is *not*
//!   consulted here, and nothing in this driver syncs group membership into
//!   OpenFGA - the deployment is responsible for that.
//! - **Implied roles** must be expressed as relation rewrites in the model.
//!
//! ## `effective` selects the API family
//!
//! `list_assignments` keys off `RoleAssignmentListParameters::effective`:
//!
//! - **`effective == Some(true)`** - use the model-resolving APIs. An
//!   actor+target query uses `check`/`batch-check`; an actor-only query uses
//!   `streamed-list-objects` (the uncapped streaming form of `list-objects`).
//!   Results include grants reached via group membership,
//!   implied roles and project-tree inheritance, each reported as a direct
//!   (`inherited: false`, `implied_via: None`) assignment. `resolve_implied_roles`
//!   only takes effect in this mode (again, via the model).
//! - **otherwise** - use a raw `read` of the stored tuples (direct grants
//!   only). An actor-only query is rejected in this mode
//!   (`ListingActorWithoutScopeRequiresEffective`): OpenFGA's `read` cannot
//!   enumerate tuples by user alone.
//!
//! A **target-scoped** listing always uses `read` (direct only) even in
//! effective mode - this driver does not call `list-users`, so group-derived
//! grants on a target are not resolved. A `debug!` is logged when effective
//! mode is asked for there.
//!
//! `create_grant` **rejects** `inherited: true`: every grant is stored as a
//! single relationship tuple with no `inherited` marker, so an inherited grant
//! could not be told apart from a direct one on read. Project-tree inheritance
//! must be expressed in the OpenFGA authorization model instead.
//!
//! ## Concurrency
//!
//! An operation that fans out over several actor/target representations, target
//! kinds or role relations issues its OpenFGA requests concurrently, with at
//! most `[openfga] max_concurrency` (default 10) in flight. `read` continuation
//! and `batch-check` chunking stay sequential.
use std::future::{Future, ready};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::stream::{self, StreamExt, TryStreamExt};
use reqwest::{Client, RequestBuilder, Response, Url};
use serde_json::{Value, json};
use tracing::{debug, error, warn};

use openstack_keystone_config::OpenFGAAssignmentDriver;
use openstack_keystone_core::assignment::{AssignmentProviderError, backend::AssignmentBackend};
use openstack_keystone_core::keystone::ServiceState;
use openstack_keystone_core::plugin_manager::BackendRegistration;
use openstack_keystone_core_types::assignment::*;

mod types;
use types::*;

pub use types::OpenFGADriverError;

/// OpenFGA `batch-check` caps a request at 50 items.
const BATCH_CHECK_MAX: usize = 50;

/// Safety bound on `read` pagination, in case a server keeps handing back a
/// non-empty continuation token.
const MAX_READ_PAGES: usize = 1000;

/// Linkage anchor - see ADR-0018. Referenced by the `keystone` crate's
/// `build.rs`-generated `_ANCHORS` static so the linker extracts `.rlib`
/// members, keeping `inventory::submit!` sections visible at runtime.
#[allow(dead_code)]
pub fn anchor() {}

inventory::submit! {
    BackendRegistration::<dyn AssignmentBackend> {
        name: "openfga",
        selected: |_| true,
        build: |cfg| {
            let timeout = cfg.openfga.as_ref().and_then(|c| c.timeout);
            Box::pin(async move {
                Ok(Arc::new(OpenFGADriver::new(timeout)?) as Arc<dyn AssignmentBackend>)
            })
        },
    }
}

pub struct OpenFGADriver {
    openfga_client: Client,
}

impl Default for OpenFGADriver {
    fn default() -> Self {
        Self {
            openfga_client: Client::new(),
        }
    }
}

impl OpenFGADriver {
    /// Initialize the OpenFGA driver.
    ///
    /// `timeout_secs`, when set, is applied as a total per-request timeout on
    /// the OpenFGA HTTP client.
    pub fn new(timeout_secs: Option<u16>) -> Result<Self, OpenFGADriverError> {
        let mut builder = Client::builder();
        if let Some(secs) = timeout_secs {
            builder = builder.timeout(Duration::from_secs(secs.into()));
        }
        Ok(Self {
            openfga_client: builder.build()?,
        })
    }

    /// Snapshot the `[openfga]` config section.
    async fn config(
        &self,
        state: &ServiceState,
    ) -> Result<OpenFGAAssignmentDriver, OpenFGADriverError> {
        state
            .config_manager
            .config
            .read()
            .await
            .openfga
            .clone()
            .ok_or(OpenFGADriverError::MissingConfiguration)
    }

    /// Build a POST to `stores/{store_id}/{path}` with auth and JSON body.
    fn post(
        &self,
        cfg: &OpenFGAAssignmentDriver,
        path: &str,
        body: &Value,
    ) -> Result<RequestBuilder, OpenFGADriverError> {
        let url: Url = cfg
            .api_url
            .join(&format!("stores/{}/{}", cfg.store_id, path))?;
        let mut rb = self.openfga_client.post(url).json(body);
        if let Some(key) = &cfg.api_key {
            rb = rb.bearer_auth(key);
        }
        Ok(rb)
    }

    /// POST to `stores/{store_id}/{path}`, retrying a transient failure
    /// (connection error, timeout, HTTP 429 or 5xx) up to `cfg.max_retries`
    /// times with exponential backoff from `cfg.retry_backoff_ms`. Returns a
    /// 2xx response, or the last error once retries are exhausted. A 4xx
    /// response other than 429 is returned immediately.
    async fn send(
        &self,
        cfg: &OpenFGAAssignmentDriver,
        path: &str,
        body: &Value,
    ) -> Result<Response, OpenFGADriverError> {
        let attempts = u32::from(cfg.max_retries).saturating_add(1);
        let mut backoff = Duration::from_millis(cfg.retry_backoff_ms);

        for attempt in 1..=attempts {
            if attempt > 1 {
                debug!("openfga {path}: retry {}/{}", attempt - 1, attempts - 1);
                tokio::time::sleep(backoff).await;
                backoff = backoff.saturating_mul(2);
            }
            match self.post(cfg, path, body)?.send().await {
                Ok(response) if response.status().is_success() => return Ok(response),
                Ok(response) => {
                    let retryable = is_retryable_status(response.status());
                    let err = openfga_error(response).await;
                    if retryable && attempt < attempts {
                        continue;
                    }
                    return Err(err);
                }
                Err(source) => {
                    if is_retryable_error(&source) && attempt < attempts {
                        continue;
                    }
                    return Err(source.into());
                }
            }
        }
        // Unreachable: the final attempt always returns from the match above.
        Err(OpenFGADriverError::OpenFGAError(
            "retry loop exhausted".into(),
        ))
    }

    /// Run a single `check` call for one already-mapped tuple.
    async fn openfga_check(
        &self,
        cfg: &OpenFGAAssignmentDriver,
        user: &str,
        relation: &str,
        object: &str,
    ) -> Result<bool, OpenFGADriverError> {
        let mut body = json!({
            "tuple_key": { "user": user, "relation": relation, "object": object }
        });
        add_model_id(&mut body, cfg);

        let response = self.send(cfg, "check", &body).await?;
        Ok(response.json::<OpenFGACheckResponse>().await?.allowed)
    }

    /// `batch-check` every `(role_id, relation)` pair for one already-mapped
    /// `(user, object)`; returns the role ids whose relation is allowed.
    async fn openfga_batch_check(
        &self,
        cfg: &OpenFGAAssignmentDriver,
        user: &str,
        object: &str,
        role_relations: &[(String, String)],
    ) -> Result<Vec<String>, OpenFGADriverError> {
        let mut allowed: Vec<String> = Vec::new();
        for chunk in role_relations.chunks(BATCH_CHECK_MAX) {
            let checks: Vec<Value> = chunk
                .iter()
                .map(|(role_id, relation)| {
                    json!({
                        "tuple_key": { "user": user, "object": object, "relation": relation },
                        "correlation_id": role_id,
                    })
                })
                .collect();
            let mut body = json!({ "checks": checks });
            add_model_id(&mut body, cfg);

            let response = self.send(cfg, "batch-check", &body).await?;
            let parsed: OpenFGABatchCheckResponse = response.json().await?;
            for (correlation_id, result) in parsed.result {
                if result.allowed {
                    allowed.push(correlation_id);
                }
            }
        }
        Ok(allowed)
    }

    /// Read every stored tuple matching `tuple_key`, following continuation
    /// tokens.
    async fn openfga_read(
        &self,
        cfg: &OpenFGAAssignmentDriver,
        tuple_key: Value,
    ) -> Result<Vec<OpenFGATuple>, OpenFGADriverError> {
        let mut out: Vec<OpenFGATuple> = Vec::new();
        let mut continuation: Option<String> = None;

        for _ in 0..MAX_READ_PAGES {
            let mut body = json!({ "tuple_key": tuple_key });
            add_model_id(&mut body, cfg);
            if let Some(token) = &continuation {
                body["continuation_token"] = token.clone().into();
            }

            let response = self.send(cfg, "read", &body).await?;
            let page: OpenFGAReadResponse = response.json().await?;
            out.extend(page.tuples.into_iter().map(|k| k.tuple));

            match page.continuation_token {
                Some(token) if !token.is_empty() => continuation = Some(token),
                _ => return Ok(out),
            }
        }

        warn!("openfga read exceeded {MAX_READ_PAGES} pages; returning a truncated result");
        Ok(out)
    }

    /// List every object of `object_type` on which `user` has `relation`
    /// (direct or computed by the model).
    ///
    /// Uses `streamed-list-objects` rather than `list-objects`: the streaming
    /// endpoint has no `OPENFGA_LIST_OBJECTS_MAX_RESULTS` cap (its only bound is
    /// `OPENFGA_LIST_OBJECTS_DEADLINE`), so the result is not silently
    /// truncated. The response is a sequence of newline-delimited JSON frames,
    /// each `{"result":{"object":"type:id"}}`; frames without a `result` (an
    /// end-of-stream marker, say) are ignored.
    async fn openfga_list_objects(
        &self,
        cfg: &OpenFGAAssignmentDriver,
        user: &str,
        relation: &str,
        object_type: &str,
    ) -> Result<Vec<String>, OpenFGADriverError> {
        let mut body = json!({ "type": object_type, "relation": relation, "user": user });
        add_model_id(&mut body, cfg);

        let response = self.send(cfg, "streamed-list-objects", &body).await?;
        let stream_body = response.text().await?;
        let mut objects = Vec::new();
        for frame in
            serde_json::Deserializer::from_str(&stream_body).into_iter::<OpenFGAStreamedFrame>()
        {
            if let Some(result) = frame?.result {
                objects.push(result.object);
            }
        }
        Ok(objects)
    }

    /// Write or delete a single already-mapped tuple.
    async fn openfga_write(
        &self,
        cfg: &OpenFGAAssignmentDriver,
        user: &str,
        relation: &str,
        object: &str,
        delete: bool,
    ) -> Result<(), OpenFGADriverError> {
        let tuple = json!({ "user": user, "relation": relation, "object": object });
        let mut body = if delete {
            json!({ "deletes": { "tuple_keys": [tuple] } })
        } else {
            json!({ "writes": { "tuple_keys": [tuple] } })
        };
        add_model_id(&mut body, cfg);

        self.send(cfg, "write", &body).await?;
        Ok(())
    }
}

/// HTTP statuses worth retrying: rate-limit and transient server errors.
fn is_retryable_status(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

/// Whether a transport-level error is transient enough to retry.
fn is_retryable_error(err: &reqwest::Error) -> bool {
    err.is_timeout() || err.is_connect() || err.is_request()
}

/// Drive `tasks` to completion with at most `limit` (>= 1) running at once,
/// concatenating their per-task `Vec` outputs. Result order is not preserved.
async fn fan_out<T, F>(limit: usize, tasks: Vec<F>) -> Result<Vec<T>, OpenFGADriverError>
where
    F: Future<Output = Result<Vec<T>, OpenFGADriverError>>,
{
    stream::iter(tasks)
        .buffer_unordered(limit.max(1))
        .try_concat()
        .await
}

/// Drive `tasks` with at most `limit` (>= 1) running at once, discarding their
/// outputs. Stops early on the first error.
async fn run_all<F>(limit: usize, tasks: Vec<F>) -> Result<(), OpenFGADriverError>
where
    F: Future<Output = Result<(), OpenFGADriverError>>,
{
    stream::iter(tasks)
        .buffer_unordered(limit.max(1))
        .try_collect::<Vec<()>>()
        .await?;
    Ok(())
}

/// Drive `tasks` with at most `limit` (>= 1) running at once, returning `true`
/// as soon as one yields `true` (remaining tasks are dropped). `false` only
/// once every task has yielded `false`.
async fn any_true<F>(limit: usize, tasks: Vec<F>) -> Result<bool, OpenFGADriverError>
where
    F: Future<Output = Result<bool, OpenFGADriverError>>,
{
    let hit = stream::iter(tasks)
        .buffer_unordered(limit.max(1))
        .try_filter(|allowed| ready(*allowed))
        .try_next()
        .await?;
    Ok(hit.unwrap_or(false))
}

/// Insert `authorization_model_id` into a request body when pinned in config.
fn add_model_id(body: &mut Value, cfg: &OpenFGAAssignmentDriver) {
    if let Some(model_id) = &cfg.model_id {
        body["authorization_model_id"] = model_id.clone().into();
    }
}

/// Map the Keystone role id to its configured OpenFGA relation name.
fn relation_for_role(
    cfg: &OpenFGAAssignmentDriver,
    role_id: &str,
) -> Result<String, OpenFGADriverError> {
    cfg.role_to_relation
        .as_ref()
        .and_then(|map| map.get(role_id).cloned())
        .ok_or_else(|| OpenFGADriverError::RoleRelationNotConfigured(role_id.to_string()))
}

/// Reverse of [`relation_for_role`] - the Keystone role id for a relation.
fn role_for_relation(cfg: &OpenFGAAssignmentDriver, relation: &str) -> Option<String> {
    cfg.role_to_relation
        .as_ref()?
        .iter()
        .find(|(_, configured)| configured.as_str() == relation)
        .map(|(role_id, _)| role_id.clone())
}

/// All `(role_id, relation)` pairs from config.
fn role_relations(cfg: &OpenFGAAssignmentDriver) -> Vec<(String, String)> {
    cfg.role_to_relation
        .as_ref()
        .map(|map| {
            map.iter()
                .map(|(role_id, relation)| (role_id.clone(), relation.clone()))
                .collect()
        })
        .unwrap_or_default()
}

/// Turn an OpenFGA error response body into a driver error, logging it.
async fn openfga_error(response: Response) -> OpenFGADriverError {
    let body = match response.text().await {
        Ok(body) => body,
        Err(source) => return OpenFGADriverError::from(source),
    };
    match serde_json::from_str::<OpenFGAErrorResponse>(&body) {
        Ok(parsed) => {
            error!("OpenFGA API error: {}", parsed.message);
            OpenFGADriverError::OpenFGAError(parsed.message)
        }
        Err(_) => OpenFGADriverError::OpenFGAError(body),
    }
}

/// Build an [`Assignment`] from an actor/target kind pair, or `None` when the
/// pairing does not describe a valid grant (an actor kind in the target slot,
/// etc.).
fn make_assignment(
    role_id: String,
    actor_kind: Kind,
    target_kind: Kind,
    actor_id: &str,
    target_id: &str,
) -> Option<Assignment> {
    Some(Assignment {
        actor_id: actor_id.to_string(),
        role_id,
        role_name: None,
        target_id: target_id.to_string(),
        r#type: kinds_to_assignment_type(actor_kind, target_kind)?,
        inherited: false,
        implied_via: None,
    })
}

/// Convert a raw stored tuple back into an [`Assignment`], or `None` (with a
/// warning) when any part is not recognised by the current config.
fn tuple_to_assignment(
    cfg: &OpenFGAAssignmentDriver,
    mapper: &ObjectMapper,
    tuple: &OpenFGATuple,
) -> Option<Assignment> {
    let Some(role_id) = role_for_relation(cfg, &tuple.relation) else {
        warn!(
            "openfga tuple relation `{}` maps to no configured role; skipping",
            tuple.relation
        );
        return None;
    };
    let Some((actor_kind, actor_id)) = mapper.parse_object(&tuple.user) else {
        warn!(
            "openfga tuple user `{}` has no configured type; skipping",
            tuple.user
        );
        return None;
    };
    let Some((target_kind, target_id)) = mapper.parse_object(&tuple.object) else {
        warn!(
            "openfga tuple object `{}` has no configured type; skipping",
            tuple.object
        );
        return None;
    };
    let Some(assignment_type) = kinds_to_assignment_type(actor_kind, target_kind) else {
        warn!(
            "openfga tuple `{}#{}@{}` does not describe an actor/target grant; skipping",
            tuple.user, tuple.relation, tuple.object
        );
        return None;
    };
    Some(Assignment {
        actor_id,
        role_id,
        role_name: None,
        target_id,
        r#type: assignment_type,
        inherited: false,
        implied_via: None,
    })
}

#[async_trait]
impl AssignmentBackend for OpenFGADriver {
    /// Check whether a grant exists.
    ///
    /// Fans out over every configured representation of the actor and target
    /// and returns `true` if any combination is allowed.
    async fn check_grant(
        &self,
        state: &ServiceState,
        assignment: &Assignment,
    ) -> Result<bool, AssignmentProviderError> {
        let cfg = self.config(state).await?;
        let mapper = ObjectMapper::from_config(&cfg);
        let relation = relation_for_role(&cfg, &assignment.role_id)?;
        let (actor_kind, target_kind) = assignment_type_kinds(&assignment.r#type);

        let users = mapper.objects_for(actor_kind, &assignment.actor_id);
        let objects = mapper.objects_for(target_kind, &assignment.target_id);
        let cfg_ref = &cfg;
        let relation_ref = &relation;
        let tasks: Vec<_> = users
            .iter()
            .flat_map(|user| objects.iter().map(move |object| (user, object)))
            .map(|(user, object)| async move {
                self.openfga_check(cfg_ref, user, relation_ref, object)
                    .await
            })
            .collect();

        Ok(any_true(cfg.max_concurrency, tasks).await?)
    }

    /// Create a grant by writing the canonical tuple.
    async fn create_grant(
        &self,
        state: &ServiceState,
        assignment: AssignmentCreate,
    ) -> Result<Assignment, AssignmentProviderError> {
        let cfg = self.config(state).await?;
        let mapper = ObjectMapper::from_config(&cfg);
        let relation = relation_for_role(&cfg, &assignment.role_id)?;
        let (actor_kind, target_kind) = assignment_type_kinds(&assignment.r#type);

        if assignment.inherited {
            // A grant is stored as a single tuple with no `inherited` marker, so
            // an inherited grant could not be distinguished from a direct one on
            // read. Reject rather than silently downgrade (see the module docs);
            // project-tree inheritance belongs in the authorization model.
            return Err(OpenFGADriverError::InheritedGrantsNotSupported.into());
        }

        let user = mapper.canonical_object(actor_kind, &assignment.actor_id)?;
        let object = mapper.canonical_object(target_kind, &assignment.target_id)?;
        self.openfga_write(&cfg, &user, &relation, &object, false)
            .await?;

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

    /// List role assignments matching `params`.
    async fn list_assignments(
        &self,
        state: &ServiceState,
        params: &RoleAssignmentListParameters,
    ) -> Result<Vec<Assignment>, AssignmentProviderError> {
        let cfg = self.config(state).await?;
        let mapper = ObjectMapper::from_config(&cfg);

        // Whether the caller asked for the *effective* assignment set - grants
        // reached via group membership, implied roles and project-tree
        // inheritance. This driver never expands those itself; it relies on the
        // OpenFGA authorization model. `effective` therefore selects between the
        // model-resolving APIs (`check`/`batch-check`/`list-objects`) and a raw
        // `read` of the stored tuples. See the module docs.
        let effective = params.effective == Some(true);
        if params.resolve_implied_roles && !effective {
            debug!(
                "openfga list_assignments: `resolve_implied_roles` is delegated to the \
                 authorization model and only takes effect in effective mode"
            );
        }

        let actor = actor_from_list_parameters(params);
        let target = target_from_list_parameters(params);
        // Resolve the role filter up front so an unknown role id fails fast.
        let role_relation: Option<(String, String)> = match &params.role_id {
            Some(role_id) => Some((role_id.clone(), relation_for_role(&cfg, role_id)?)),
            None => None,
        };

        // Every fan-out below issues its OpenFGA calls concurrently, capped at
        // `max_concurrency`. Rebind `cfg`/`mapper` as shared references so the
        // per-task `async move` blocks copy the reference rather than moving the
        // value.
        let max_concurrency = cfg.max_concurrency;
        let cfg = &cfg;
        let mapper = &mapper;

        let mut results: Vec<Assignment> = Vec::new();

        match (actor, target) {
            (Some((actor_kind, actor_id)), Some((target_kind, target_id))) => {
                match &role_relation {
                    // actor + target + role: is the grant present for any rep
                    // pair? `check` in effective mode, a direct tuple `read`
                    // otherwise.
                    Some((role_id, relation)) => {
                        let users = mapper.objects_for(actor_kind, actor_id);
                        let objects = mapper.objects_for(target_kind, target_id);
                        let tasks: Vec<_> = users
                            .iter()
                            .flat_map(|user| objects.iter().map(move |object| (user, object)))
                            .map(|(user, object)| async move {
                                if effective {
                                    self.openfga_check(cfg, user, relation, object).await
                                } else {
                                    Ok(!self
                                        .openfga_read(
                                            cfg,
                                            json!({
                                                "user": user,
                                                "relation": relation,
                                                "object": object,
                                            }),
                                        )
                                        .await?
                                        .is_empty())
                                }
                            })
                            .collect();
                        if any_true(max_concurrency, tasks).await? {
                            results.extend(make_assignment(
                                role_id.clone(),
                                actor_kind,
                                target_kind,
                                actor_id,
                                target_id,
                            ));
                        }
                    }
                    // actor + target, no role (login path): every configured
                    // role between the actor and the target. `batch-check` in
                    // effective mode, a direct tuple `read` otherwise.
                    None => {
                        let pairs = role_relations(cfg);
                        let pairs_ref = &pairs;
                        let users = mapper.objects_for(actor_kind, actor_id);
                        let objects = mapper.objects_for(target_kind, target_id);
                        let tasks: Vec<_> = users
                            .iter()
                            .flat_map(|user| objects.iter().map(move |object| (user, object)))
                            .map(|(user, object)| async move {
                                let mut out: Vec<Assignment> = Vec::new();
                                if effective {
                                    for role_id in self
                                        .openfga_batch_check(cfg, user, object, pairs_ref)
                                        .await?
                                    {
                                        out.extend(make_assignment(
                                            role_id,
                                            actor_kind,
                                            target_kind,
                                            actor_id,
                                            target_id,
                                        ));
                                    }
                                } else {
                                    for tuple in self
                                        .openfga_read(
                                            cfg,
                                            json!({ "user": user, "object": object }),
                                        )
                                        .await?
                                    {
                                        if let Some(assignment) =
                                            tuple_to_assignment(cfg, mapper, &tuple)
                                        {
                                            out.push(assignment);
                                        }
                                    }
                                }
                                Ok::<_, OpenFGADriverError>(out)
                            })
                            .collect();
                        results.extend(fan_out(max_concurrency, tasks).await?);
                    }
                }
            }
            // actor without a target scope: enumerate the objects the actor
            // holds each role relation on, per target kind. Only answerable in
            // effective mode - OpenFGA's `read` cannot enumerate by user alone.
            (Some((actor_kind, actor_id)), None) => {
                if !effective {
                    Err(OpenFGADriverError::ListingActorWithoutScopeRequiresEffective)?;
                }
                let pairs: Vec<(String, String)> = match &role_relation {
                    Some(pair) => vec![pair.clone()],
                    None => role_relations(cfg),
                };
                let users = mapper.objects_for(actor_kind, actor_id);
                let mut tasks = Vec::new();
                for user in &users {
                    for tkind in [Kind::Project, Kind::Domain, Kind::System] {
                        for object_type in mapper.types_for(tkind) {
                            for (role_id, relation) in &pairs {
                                tasks.push(async move {
                                    let mut out: Vec<Assignment> = Vec::new();
                                    for object in self
                                        .openfga_list_objects(cfg, user, relation, object_type)
                                        .await?
                                    {
                                        let Some((parsed_kind, target_id)) =
                                            mapper.parse_object(&object)
                                        else {
                                            warn!(
                                                "openfga list-objects returned `{object}` with \
                                                 no configured type; skipping"
                                            );
                                            continue;
                                        };
                                        // `make_assignment` returns `None` for a
                                        // nonsensical actor/target kind pairing.
                                        out.extend(make_assignment(
                                            role_id.clone(),
                                            actor_kind,
                                            parsed_kind,
                                            actor_id,
                                            &target_id,
                                        ));
                                    }
                                    Ok::<_, OpenFGADriverError>(out)
                                });
                            }
                        }
                    }
                }
                results.extend(fan_out(max_concurrency, tasks).await?);
            }
            // target scope, maybe a role filter: read stored tuples per rep.
            // Always direct - OpenFGA's `read` does not resolve group-derived
            // grants on the target, and this driver does not call `list-users`.
            (None, Some((target_kind, target_id))) => {
                if effective {
                    debug!(
                        "openfga list_assignments: effective target-scoped listing returns \
                         stored (direct) tuples only; group-derived grants on the target are \
                         not resolved"
                    );
                }
                let objects = mapper.objects_for(target_kind, target_id);
                let role_relation_ref = &role_relation;
                let tasks: Vec<_> = objects
                    .iter()
                    .map(|object| async move {
                        let tuple_key = match role_relation_ref {
                            Some((_, relation)) => {
                                json!({ "relation": relation, "object": object })
                            }
                            None => json!({ "object": object }),
                        };
                        let mut out: Vec<Assignment> = Vec::new();
                        for tuple in self.openfga_read(cfg, tuple_key).await? {
                            if let Some(assignment) = tuple_to_assignment(cfg, mapper, &tuple) {
                                out.push(assignment);
                            }
                        }
                        Ok::<_, OpenFGADriverError>(out)
                    })
                    .collect();
                results.extend(fan_out(max_concurrency, tasks).await?);
            }
            (None, None) => {
                if role_relation.is_some() {
                    Err(OpenFGADriverError::ListingAssignmentsByRoleNotSupported)?;
                } else {
                    Err(OpenFGADriverError::ListingAllAssignmentsNotSupported)?;
                }
            }
        }

        // No cursor is pushed into OpenFGA (results are a fan-out union across
        // representations, target kinds and role relations). Pagination is
        // applied post-fetch over the fully materialised set, mirroring the SQL
        // driver: sort by the opaque marker, drop everything up to the caller's
        // marker, then over-fetch by one so the service layer can tell there is
        // a next page.
        let mut results = dedupe_assignments(results);
        results.sort_by_key(|a| a.pagination_marker());
        if let Some(marker) = &params.pagination.marker {
            if params.pagination.page_reverse {
                results.retain(|x| x.pagination_marker().as_str() < marker.as_str());
            } else {
                results.retain(|x| x.pagination_marker().as_str() > marker.as_str());
            }
        }
        if let Some(limit) = params.pagination.limit {
            let limit = (limit + 1) as usize;
            if params.pagination.page_reverse {
                if results.len() > limit {
                    results = results.split_off(results.len() - limit);
                }
            } else {
                results.truncate(limit);
            }
        }

        Ok(results)
    }

    /// Revoke a grant, fanning the delete out over every representation.
    ///
    /// Mirrors the SQL driver: revoking a grant that is not present is a no-op,
    /// not an error. Each representation is probed with a direct `read` first so
    /// OpenFGA's "tuple not found" delete error is never hit; only the
    /// representations that actually hold the tuple are deleted. A real OpenFGA
    /// error from either the `read` or the `delete` propagates as-is. The
    /// representations are probed concurrently, capped at `max_concurrency`.
    async fn revoke_grant(
        &self,
        state: &ServiceState,
        assignment: &Assignment,
    ) -> Result<(), AssignmentProviderError> {
        let cfg = self.config(state).await?;
        let mapper = ObjectMapper::from_config(&cfg);
        let relation = relation_for_role(&cfg, &assignment.role_id)?;
        let (actor_kind, target_kind) = assignment_type_kinds(&assignment.r#type);

        let users = mapper.objects_for(actor_kind, &assignment.actor_id);
        let objects = mapper.objects_for(target_kind, &assignment.target_id);
        let cfg_ref = &cfg;
        let relation_ref = &relation;
        let tasks: Vec<_> = users
            .iter()
            .flat_map(|user| objects.iter().map(move |object| (user, object)))
            .map(|(user, object)| async move {
                let held = self
                    .openfga_read(
                        cfg_ref,
                        json!({ "user": user, "relation": relation_ref, "object": object }),
                    )
                    .await?;
                if held.is_empty() {
                    return Ok(());
                }
                self.openfga_write(cfg_ref, user, relation_ref, object, true)
                    .await
            })
            .collect();

        run_all(cfg.max_concurrency, tasks).await?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
