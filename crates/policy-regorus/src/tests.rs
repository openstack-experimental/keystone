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
//! Tests running against the real `policy/` tree of the repository.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde_json::json;

use openstack_keystone_core::policy::PolicyError;

use crate::RegorusPolicyEnforcer;
use crate::loader::{SourceFile, engine_for, scan};

fn policy_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("POLICY_DIR") {
        return PathBuf::from(dir);
    }
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policy")
}

fn enforcer() -> RegorusPolicyEnforcer {
    RegorusPolicyEnforcer::new(&policy_dir()).expect("policy tree compiles")
}

#[test]
fn test_all_entrypoints_compile() {
    let e = enforcer();
    assert!(e.len() >= 180, "only {} entrypoints loaded", e.len());
    assert!(e.contains("identity/role/show"));
    // `identity.user.delete` was part of the cyclic evaluation error when
    // everything was loaded into a single engine.
    assert!(e.contains("identity/user/delete"));
}

#[test]
fn test_role_show_decisions() {
    let e = enforcer();
    let input = |roles: serde_json::Value, domain: &str| {
        json!({
            "credentials": {"roles": roles, "is_admin": false, "domain_id": domain},
            "target": null,
            "existing": {"role": {"id": "r", "domain_id": "d"}}
        })
    };
    // admin: always
    assert!(
        e.evaluate("identity/role/show", input(json!(["admin"]), "x"))
            .unwrap()
            .allow()
    );
    // manager: own domain role
    assert!(
        e.evaluate("identity/role/show", input(json!(["manager"]), "d"))
            .unwrap()
            .allow()
    );
    // manager of another domain
    assert!(
        !e.evaluate("identity/role/show", input(json!(["manager"]), "other"))
            .unwrap()
            .allow()
    );
    // no relevant role
    assert!(
        !e.evaluate("identity/role/show", input(json!(["member"]), "d"))
            .unwrap()
            .allow()
    );
}

#[test]
fn test_violations_are_returned() {
    let e = enforcer();
    let res = e
        .evaluate(
            "identity/user/delete",
            json!({
                "credentials": {"roles": ["member"], "is_admin": false, "domain_id": "d"},
                "target": null,
                "existing": {"user": {"id": "u", "domain_id": "d"}}
            }),
        )
        .unwrap();
    assert!(!res.allow());
    assert!(
        res.violations.as_ref().is_some_and(|v| !v.is_empty()),
        "{res:?}"
    );
}

#[test]
fn test_unknown_policy() {
    assert!(matches!(
        enforcer().evaluate("identity/nope/show", json!({})),
        Err(PolicyError::IO(_))
    ));
}

#[test]
fn test_reload_keeps_working() {
    let e = enforcer();
    let before = e.len();
    e.reload().unwrap();
    assert_eq!(before, e.len());
}

#[tokio::test]
async fn test_health_check() {
    use openstack_keystone_core::policy::PolicyEnforcer;
    enforcer().health_check().await.unwrap();
}

/// Run every `test_*` rule of the `*_test.rego` files (the suite `opa test
/// policy` runs in CI) with regorus. This is the parity check against OPA:
/// the suite is the specification of the policies.
#[test]
fn test_rego_test_suites_pass() {
    let files: Vec<SourceFile> = scan(&policy_dir()).unwrap();
    let helpers: Vec<&SourceFile> = files
        .iter()
        .filter(|f| !f.is_test && !f.is_entrypoint)
        .collect();
    let mut by_package: BTreeMap<&str, Vec<&SourceFile>> = BTreeMap::new();
    for f in files.iter().filter(|f| f.is_test) {
        by_package.entry(f.package.as_str()).or_default().push(f);
    }

    let (mut passed, mut failed) = (0usize, Vec::new());
    for (package, tests) in by_package {
        // The test files live in their own `test_*` package and import the
        // policy under test: add the modules of the imported packages.
        let sources: Vec<String> = tests
            .iter()
            .map(|t| std::fs::read_to_string(&t.path).unwrap())
            .collect();
        let imported: BTreeSet<&str> = sources
            .iter()
            .flat_map(|s| s.lines())
            .filter_map(|l| l.strip_prefix("import data."))
            .map(|i| i.split_whitespace().next().unwrap_or_default())
            .collect();
        let mut seen = BTreeSet::new();
        let modules: Vec<&SourceFile> = helpers
            .iter()
            .copied()
            .chain(
                files
                    .iter()
                    .filter(|f| !f.is_test && imported.contains(f.package.as_str())),
            )
            .chain(tests.iter().copied())
            .filter(|f| seen.insert(f.path.clone()))
            .collect();
        let mut engine = engine_for(package, modules.into_iter()).unwrap();
        for src in &sources {
            for name in src.lines().filter_map(|l| {
                l.strip_prefix("test_")
                    .map(|r| r.split(|c: char| !c.is_alphanumeric() && c != '_').next())
                    .map(|r| format!("test_{}", r.unwrap_or_default()))
            }) {
                match engine.eval_rule(format!("data.{package}.{name}")) {
                    Ok(regorus::Value::Bool(true)) => passed += 1,
                    other => failed.push(format!("data.{package}.{name}: {other:?}")),
                }
            }
        }
    }
    eprintln!("rego tests: {passed} passed, {} failed", failed.len());
    for f in failed.iter() {
        eprintln!("FAILED {f}");
    }
    assert!(passed > 0);
    assert!(failed.is_empty(), "{} rego tests failed", failed.len());
    assert!(passed >= 567, "only {passed} rego tests passed");
}

/// Helper of `tools/policy-diff.py`: evaluate the cases of `POLICY_DIFF_CASES`
/// and write the decisions (`null` on an evaluation error) to
/// `POLICY_DIFF_OUT`.
#[test]
#[ignore = "driven by tools/policy-diff.py"]
fn dump_decisions() {
    let (Ok(cases), Ok(out)) = (
        std::env::var("POLICY_DIFF_CASES"),
        std::env::var("POLICY_DIFF_OUT"),
    ) else {
        return;
    };
    let cases: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(cases).unwrap()).unwrap();
    let e = enforcer();
    let res: Vec<serde_json::Value> = cases
        .iter()
        .map(|c| {
            let name = c["package"].as_str().unwrap().replace('.', "/");
            match e.evaluate(&name, c["input"].clone()) {
                Ok(r) => json!({
                    "allow": r.allow,
                    "violation": r.violations,
                    "can_see_other_domain_resources": r.can_see_other_domain_resources,
                }),
                Err(err) => {
                    eprintln!("ERROR {name}: {err:?}");
                    serde_json::Value::Null
                }
            }
        })
        .collect();
    std::fs::write(out, serde_json::to_string(&res).unwrap()).unwrap();
}
