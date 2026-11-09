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

use std::collections::{BTreeMap, HashMap, HashSet};
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
    /// Names of the rules declared at the top level of the module.
    pub rules: HashSet<String>,
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
            let engine = engine_for(
                package,
                helpers.iter().copied().chain(modules.iter().copied()),
            )?;
            let declares = |rule: &str| modules.iter().any(|f| f.rules.contains(rule));
            let ep = compile_entrypoint(package, engine, declares)?;
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
    declares: impl Fn(&str) -> bool,
) -> Result<Entrypoint, RegorusError> {
    let mut compile = |rule: &str| -> Result<regorus::CompiledPolicy, RegorusError> {
        let path: Arc<str> = format!("data.{package}.{rule}").into();
        engine
            .compile_with_entrypoint(&path)
            .map_err(|e| RegorusError::Compile {
                package: package.to_string(),
                message: format!("rule `{rule}`: {e}"),
            })
    };
    let allow = compile("allow")?;
    // The optional rules are absent in most of the packages. A rule that is
    // declared but does not compile is a hard error: swallowing it would
    // silently drop violations or narrow the list scope.
    let mut optional = |rule: &str| -> Result<Option<regorus::CompiledPolicy>, RegorusError> {
        if declares(rule) {
            compile(rule).map(Some)
        } else {
            Ok(None)
        }
    };
    let violation = optional("violation")?;
    let can_see_other_domain_resources = optional("can_see_other_domain_resources")?;
    Ok(Entrypoint {
        allow,
        violation,
        can_see_other_domain_resources,
    })
}

/// Name of the rule declared by a top-level line, if any.
///
/// Rule heads start in the first column (`opa fmt` indents the bodies), so
/// indented lines, comments and `package`/`import` lines are skipped.
fn rule_head(line: &str) -> Option<&str> {
    let line = line.strip_prefix("default ").unwrap_or(line);
    let end = line
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(line.len());
    let name = &line[..end];
    if name.is_empty() || matches!(name, "package" | "import") {
        return None;
    }
    Some(name)
}

/// Package path of the module, without a trailing comment.
fn package_name(src: &str) -> Option<String> {
    src.lines()
        .find_map(|l| l.strip_prefix("package "))
        .map(|p| p.split('#').next().unwrap_or(p).trim().to_string())
        .filter(|p| !p.is_empty())
}

/// Recursively collect the `.rego` files with their package.
///
/// Symlinks and hidden entries are skipped: Kubernetes ConfigMap volumes
/// expose every file again through `..data` and `..<timestamp>`, which would
/// load each module several times (and a symlink loop would never end).
pub(crate) fn scan(dir: &Path) -> Result<Vec<SourceFile>, RegorusError> {
    let io = |path: &Path| {
        let path = path.to_path_buf();
        move |source| RegorusError::Io { path, source }
    };
    let mut res = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).map_err(io(&d))? {
            let entry = entry.map_err(io(&d))?;
            let path = entry.path();
            if entry.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            let file_type = entry.file_type().map_err(io(&path))?;
            if file_type.is_symlink() {
                // A ConfigMap exposes its files as symlinks into `..data`.
                // Follow a link only when it is a regular file inside `dir`.
                let target = std::fs::canonicalize(&path).map_err(io(&path))?;
                let root = std::fs::canonicalize(dir).map_err(io(dir))?;
                if !target.is_file() || !target.starts_with(&root) {
                    trace!(path = %path.display(), "skipping symlink");
                    continue;
                }
            } else if file_type.is_dir() {
                stack.push(path);
                continue;
            }
            if path.extension().is_some_and(|e| e == "rego") {
                let src = std::fs::read_to_string(&path).map_err(io(&path))?;
                let package =
                    package_name(&src).ok_or_else(|| RegorusError::MissingPackage(path.clone()))?;
                let is_test = path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().ends_with("_test.rego"));
                let rules: HashSet<String> = src
                    .lines()
                    .filter_map(rule_head)
                    .map(str::to_string)
                    .collect();
                let is_entrypoint = !is_test && rules.contains("allow");
                res.push(SourceFile {
                    path,
                    package,
                    rules,
                    is_entrypoint,
                    is_test,
                });
            }
        }
    }
    res.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(res)
}
