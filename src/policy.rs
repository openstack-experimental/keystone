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
//! # Policy enforcement
//!
//! Policy enforcement in Keystone is delegated to the Open Policy Agent. It can
//! be invoked either with the HTTP request or as a WASM module.
#[cfg(test)]
use mockall::mock;
//#[cfg(feature = "wasm")]
//use opa_wasm::{
//    Runtime,
//    wasmtime::{Config, Engine, Module, OptLevel, Store},
//};
use reqwest::{Client, Url};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
//#[cfg(feature = "wasm")]
//use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;
use thiserror::Error;
//#[cfg(feature = "wasm")]
//use tokio::io::{AsyncRead, AsyncReadExt};
use tracing::{Level, debug, trace};

use crate::token::Token;

/// Policy related error.
#[derive(Debug, Error)]
pub enum PolicyError {
    /// Module compilation error.
    #[error("module compilation task crashed")]
    Compilation(#[from] eyre::Report),

    /// Forbidden error.
    #[error("{}", .0.violations.as_ref().map(
        |v| v.iter().cloned().map(|x| x.msg)
        .reduce(|acc, s| format!("{acc}, {s}"))
        .unwrap_or_default()
    ).unwrap_or("The request you made requires authentication.".into()))]
    Forbidden(PolicyEvaluationResult),

    #[error(transparent)]
    IO(#[from] std::io::Error),

    #[error(transparent)]
    Join(#[from] tokio::task::JoinError),

    /// Json serializaion error.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// HTTP client error.
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),

    /// Url parsing error.
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),
    //    #[cfg(feature = "wasm")]
    //    #[error(transparent)]
    //    Wasm(#[from] opa_wasm::wasmtime::Error),
}

/// Policy factory.
#[derive(Default)]
pub struct PolicyFactory {
    /// Requests client.
    http_client: Option<Arc<Client>>,
    /// OPA url address.
    base_url: Option<Url>,
    // #[cfg(feature = "wasm")]
    // /// WASM engine.
    // engine: Option<Engine>,
    // #[cfg(feature = "wasm")]
    // /// WASM module.
    // module: Option<Module>,
}

impl PolicyFactory {
    // #[cfg(feature = "wasm")]
    // #[tracing::instrument(name = "policy.from_defaults", err)]
    // pub async fn from_defaults() -> Result<Self, PolicyError> {
    //     let path =
    // std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("policy.wasm");
    //     let file = tokio::fs::File::open(path).await?;
    //     PolicyFactory::load(file).await
    // }

    // #[cfg(feature = "wasm")]
    // #[tracing::instrument(name = "policy.from_wasm", err)]
    // pub async fn from_wasm(path: &Path) -> Result<Self, PolicyError> {
    //     let file = tokio::fs::File::open(path).await?;
    //     PolicyFactory::load(file).await
    // }

    #[allow(clippy::needless_update)]
    #[tracing::instrument(name = "policy.http", err)]
    pub async fn http(url: Url) -> Result<Self, PolicyError> {
        let client = Client::builder()
            .tcp_keepalive(std::time::Duration::from_secs(60))
            .gzip(true)
            .deflate(true)
            .build()?;
        Ok(Self {
            http_client: Some(Arc::new(client)),
            base_url: Some(url.join("/v1/data/")?),
            ..Default::default()
        })
    }

    // #[cfg(feature = "wasm")]
    // #[tracing::instrument(name = "policy.load", skip(source), err)]
    // pub async fn load(
    //     mut source: impl AsyncRead + std::marker::Unpin,
    // ) -> Result<Self, PolicyError> {
    //     let mut config = Config::default();
    //     config.async_support(true);
    //     config.cranelift_opt_level(OptLevel::SpeedAndSize);

    //     let engine = Engine::new(&config)?;

    //     // Read and compile the module
    //     let mut buf = Vec::new();
    //     source.read_to_end(&mut buf).await?;
    //     // Compilation is CPU-bound, so spawn that in a blocking task
    //     let (engine, module) = tokio::task::spawn_blocking(move || {
    //         let module = Module::new(&engine, buf).map_err(PolicyError::from)?;
    //         Ok((engine, module))
    //     })
    //     .await?
    //     .map_err(PolicyError::Compilation)?;

    //     let factory = Self {
    //         http_client: None,
    //         base_url: None,
    //         engine: Some(engine),
    //         module: Some(module),
    //     };

    //     // Try to instantiate
    //     factory.instantiate().await?;

    //     Ok(factory)
    // }

    #[allow(clippy::needless_update)]
    #[tracing::instrument(name = "policy.instantiate", level = Level::TRACE, skip_all, err)]
    pub async fn instantiate(&self) -> Result<Policy, PolicyError> {
        // #[cfg(feature = "wasm")]
        // {
        //     if let (Some(engine), Some(module)) = (&self.engine, &self.module) {
        //         let mut store = Store::new(engine, ());
        //         let runtime = Runtime::new(&mut store, module).await?;

        //         let instance = runtime.without_data(&mut store).await?;
        //         return Ok(Policy {
        //             http_client: self.http_client.clone(),
        //             base_url: self.base_url.clone(),
        //             #[cfg(feature = "wasm")]
        //             store: Some(store),
        //             #[cfg(feature = "wasm")]
        //             instance: Some(instance),
        //         });
        //     }
        // }

        Ok(Policy {
            http_client: self.http_client.clone(),
            base_url: self.base_url.clone(),
            ..Default::default()
        })
    }
}

#[cfg(test)]
mock! {
    pub Policy {
        pub async fn enforce(
            &mut self,
            policy_name: &str,
            credentials: &Token,
            target: Value,
            current: Option<Value>
        ) -> Result<PolicyEvaluationResult, PolicyError>;
    }
}

#[cfg(test)]
mock! {
    pub PolicyFactory {
        pub async fn instantiate(&self) -> Result<MockPolicy, PolicyError>;
    }
}

#[derive(Default)]
pub struct Policy {
    http_client: Option<Arc<Client>>,
    base_url: Option<Url>,
    // #[cfg(feature = "wasm")]
    // store: Option<Store<()>>,
    // #[cfg(feature = "wasm")]
    // instance: Option<opa_wasm::Policy<opa_wasm::DefaultContext>>,
}

#[derive(Debug, Error)]
#[error("failed to evaluate policy")]
pub enum EvaluationError {
    Serialization(#[from] serde_json::Error),
    Evaluation(#[from] eyre::Report),
}

/// OpenPolicyAgent `Credentials` object
#[derive(Serialize, Debug)]
pub struct Credentials {
    pub user_id: String,
    pub roles: Vec<String>,
    #[serde(default)]
    pub project_id: Option<String>,
    #[serde(default)]
    pub domain_id: Option<String>,
    #[serde(default)]
    pub system: Option<String>,
}

impl From<&Token> for Credentials {
    fn from(token: &Token) -> Self {
        Self {
            user_id: token.user_id().clone(),
            roles: token
                .roles()
                .map(|x| x.iter().map(|role| role.name.clone()).collect::<Vec<_>>())
                .unwrap_or_default(),
            project_id: token.project().map(|val| val.id.clone()),
            domain_id: token.domain().map(|val| val.id.clone()),
            system: None,
        }
    }
}

impl Policy {
    #[tracing::instrument(
        name = "policy.evaluate",
        skip_all,
        fields(
            entrypoint = policy_name.as_ref(),
            input,
            result,
            duration_ms
        ),
        err,
        level = Level::DEBUG
    )]
    pub async fn enforce<P: AsRef<str>>(
        &mut self,
        policy_name: P,
        credentials: impl Into<Credentials>,
        target: Value,
        update: Option<Value>,
    ) -> Result<PolicyEvaluationResult, PolicyError> {
        let start = SystemTime::now();
        let creds: Credentials = credentials.into();
        let input = json!({
            "credentials": creds,
            "target": target,
            "update": update,
        });
        let span = tracing::Span::current();

        let wasm_res: Option<PolicyEvaluationResult> = None;

        // #[cfg(feature = "wasm")]
        // {
        //     opa_res = if let (Some(store), Some(instance)) = (&mut self.store,
        // &self.instance) {         tracing::Span::current().record("input",
        // serde_json::to_string(&input)?);         let [res]: [OpaResponse; 1]
        // = instance             .evaluate(store, policy_name.as_ref(), &input)
        //             .await?;

        //         Some(res.result)
        //     };
        // }

        let res = if let Some(opa_res) = wasm_res {
            opa_res
        } else if let (Some(client), Some(base_url)) = (&self.http_client, &self.base_url) {
            trace!("checking policy decision with OPA using http");
            let url = base_url.join(policy_name.as_ref())?;
            let res: OpaResponse = client
                .post(url)
                .json(&json!({"input": input}))
                .send()
                .await?
                .json()
                .await?;

            res.result
        } else {
            debug!("not enforcing policy due to the absence of initialized WASM data");
            PolicyEvaluationResult {
                allow: true,
                can_see_other_domain_resources: None,
                violations: None,
            }
        };
        let elapsed = SystemTime::now().duration_since(start).unwrap_or_default();
        span.record("result", serde_json::to_string(&res)?);
        span.record("duration_ms", elapsed.as_millis());
        debug!("authorized={}", res.allow());
        if !res.allow() {
            return Err(PolicyError::Forbidden(res));
        }
        Ok(res)
    }
}

/// A single violation of a policy.
#[derive(Clone, Deserialize, Debug, JsonSchema, Serialize)]
pub struct Violation {
    pub msg: String,
    pub field: Option<String>,
}

/// The OpenPolicyAgent response.
#[derive(Deserialize, Debug)]
pub struct OpaResponse {
    pub result: PolicyEvaluationResult,
}

/// The result of a policy evaluation.
#[derive(Clone, Deserialize, Debug, Serialize)]
pub struct PolicyEvaluationResult {
    /// Whether the user is allowed to perform the request or not.
    pub allow: bool,
    /// Whether the user is allowed to see resources of other domains.
    #[serde(default)]
    pub can_see_other_domain_resources: Option<bool>,
    /// List of violations.
    #[serde(rename = "violation")]
    pub violations: Option<Vec<Violation>>,
}

impl std::fmt::Display for PolicyEvaluationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut first = true;
        if let Some(violations) = &self.violations {
            for violation in violations {
                if first {
                    first = false;
                } else {
                    write!(f, ", ")?;
                }
                write!(f, "{}", violation.msg)?;
            }
        }
        Ok(())
    }
}

impl PolicyEvaluationResult {
    #[must_use]
    pub fn allow(&self) -> bool {
        self.allow
    }

    /// Returns true if the policy evaluation was successful.
    #[must_use]
    pub fn valid(&self) -> bool {
        self.violations
            .as_deref()
            .map(|x| x.is_empty())
            .unwrap_or(false)
    }

    #[cfg(test)]
    pub fn allowed() -> Self {
        Self {
            allow: true,
            can_see_other_domain_resources: None,
            violations: None,
        }
    }

    #[cfg(test)]
    pub fn allowed_admin() -> Self {
        Self {
            allow: true,
            can_see_other_domain_resources: Some(true),
            violations: None,
        }
    }

    #[cfg(test)]
    pub fn forbidden() -> Self {
        Self {
            allow: false,
            can_see_other_domain_resources: Some(false),
            violations: None,
        }
    }
}
