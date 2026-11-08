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
//! Loading and compiling the Rego policy tree.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use thiserror::Error;
use tracing::{debug, trace};

/// Errors raised while loading the policies.
#[derive(Debug, Error)]
pub enum RegorusError {
    /// IO error while reading the policy directory.
    #[error("reading policy files from {path}")]
    Io {
        /// The path being read.
        path: PathBuf,
        /// The source error.
        #[source]
        source: std::io::Error,
    },

    /// A policy file does not declare its package.
    #[error("policy file {0} has no `package` declaration")]
    MissingPackage(PathBuf),

    /// Rego parsing or compilation error.
    #[error("compiling policy package `{package}`: {message}")]
    Compile {
        /// The package that failed to compile.
        package: String,
        /// The compiler error.
        message: String,
    },

    /// The directory does not contain any entrypoint.
    #[error("no policies with an `allow` rule found in {0}")]
    Empty(PathBuf),
}

/// Compiled rules of a single entrypoint package (e.g. `identity.role.show`).
#[derive(Clone)]
pub(crate) struct Entrypoint {
    pub allow: regorus::CompiledPolicy,
    pub violation: Option<regorus::CompiledPolicy>,
    pub can_see_other_domain_resources: Option<regorus::CompiledPolicy>,
}

/// A compiled, immutable set of policies.
#[derive(Default)]
pub struct PolicySet {
    /// Entrypoints keyed by the OPA data path (`identity/role/show`).
    pub(crate) entrypoints: HashMap<String, Entrypoint>,
}

/// A policy source file.
#[derive(Clone, Debug)]
pub(crate) struct SourceFile {
    pub path: PathBuf,
    pub package: String,
    /// The module defines a top-level `allow` rule.
    pub is_entrypoint: bool,
    pub is_test: bool,
}

impl PolicySet {
    /// Number of the loaded entrypoints.
    pub fn len(&self) -> usize {
        self.entrypoints.len()
    }

    /// Whether the set has no entrypoints.
    pub fn is_empty(&self) -> bool {
        self.entrypoints.is_empty()
    }

    /// Whether the entrypoint (`identity/role/show`) exists.
    pub fn contains(&self, policy_name: &str) -> bool {
        self.entrypoints.contains_key(policy_name)
    }

    /// Compile all the policies from the directory (recursively).
    ///
    /// `*_test.rego` files are ignored.
    pub fn load(dir: &Path) -> Result<Self, RegorusError> {
        let files: Vec<SourceFile> = scan(dir)?.into_iter().filter(|f| !f.is_test).collect();
        let helpers: Vec<&SourceFile> = files.iter().filter(|f| !f.is_entrypoint).collect();
        let mut by_package: BTreeMap<&str, Vec<&SourceFile>> = BTreeMap::new();
        for f in files.iter().filter(|f| f.is_entrypoint) {
            by_package.entry(f.package.as_str()).or_default().push(f);
        }
        if by_package.is_empty() {
            return Err(RegorusError::Empty(dir.to_path_buf()));
        }

        let mut entrypoints = HashMap::with_capacity(by_package.len());
        for (package, modules) in by_package {
            let engine = engine_for(package, helpers.iter().copied().chain(modules))?;
            let ep = compile_entrypoint(package, engine)?;
            entrypoints.insert(package.replace('.', "/"), ep);
        }
        debug!(count = entrypoints.len(), "compiled policy entrypoints");
        Ok(Self { entrypoints })
    }
}

/// Build an engine with the given modules.
pub(crate) fn engine_for<'a>(
    package: &str,
    files: impl Iterator<Item = &'a SourceFile>,
) -> Result<regorus::Engine, RegorusError> {
    let mut engine = regorus::Engine::new();
    for f in files {
        trace!(path = %f.path.display(), "adding policy module");
        engine
            .add_policy_from_file(&f.path)
            .map_err(|e| RegorusError::Compile {
                package: package.to_string(),
                message: e.to_string(),
            })?;
    }
    Ok(engine)
}

fn compile_entrypoint(
    package: &str,
    mut engine: regorus::Engine,
) -> Result<Entrypoint, RegorusError> {
    let mut compile = |rule: &str| -> Result<regorus::CompiledPolicy, String> {
        let path: Arc<str> = format!("data.{package}.{rule}").into();
        engine
            .compile_with_entrypoint(&path)
            .map_err(|e| e.to_string())
    };
    let allow = compile("allow").map_err(|message| RegorusError::Compile {
        package: package.to_string(),
        message,
    })?;
    // The optional rules are absent in most of the packages.
    let violation = compile("violation").ok();
    let can_see_other_domain_resources = compile("can_see_other_domain_resources").ok();
    Ok(Entrypoint {
        allow,
        violation,
        can_see_other_domain_resources,
    })
}

/// Recursively collect the `.rego` files with their package.
pub(crate) fn scan(dir: &Path) -> Result<Vec<SourceFile>, RegorusError> {
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| RegorusError::Io { path, source }
    };
    let mut res = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).map_err(io(&d))? {
            let path = entry.map_err(io(&d))?.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rego") {
                let src = std::fs::read_to_string(&path).map_err(io(&path))?;
                let package = src
                    .lines()
                    .find_map(|l| l.strip_prefix("package "))
                    .map(|p| p.trim().to_string())
                    .ok_or_else(|| RegorusError::MissingPackage(path.clone()))?;
                let is_test = path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().ends_with("_test.rego"));
                let is_entrypoint = !is_test
                    && src
                        .lines()
                        .any(|l| l.starts_with("allow ") || l.starts_with("default allow"));
                res.push(SourceFile {
                    path,
                    package,
                    is_entrypoint,
                    is_test,
                });
            }
        }
    }
    res.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(res)
}
