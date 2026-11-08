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
//! Evaluation cost of the in-process enforcer.
//!
//! Compare with the OPA sidecar by timing the same input against
//! `POST /v1/data/identity/role/show` (see `doc/src/contributor`).

#![allow(clippy::expect_used)]

use std::hint::black_box;
use std::path::Path;

use criterion::{Criterion, criterion_group, criterion_main};
use openstack_keystone_policy_regorus::RegorusPolicyEnforcer;
use serde_json::json;

fn bench(c: &mut Criterion) {
    let policies = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policy");
    let enforcer = RegorusPolicyEnforcer::new(&policies).expect("policies compile");
    let manager = json!({
        "credentials": {"roles": ["manager"], "is_admin": false, "domain_id": "d"},
        "target": null,
        "existing": {"role": {"id": "r", "domain_id": "d"}}
    });
    let denied = json!({
        "credentials": {"roles": ["member"], "is_admin": false, "domain_id": "d"},
        "target": null,
        "existing": {"role": {"id": "r", "domain_id": "d"}}
    });
    c.bench_function("evaluate allow (identity/role/show)", |b| {
        b.iter(|| enforcer.evaluate("identity/role/show", black_box(manager.clone())))
    });
    c.bench_function("evaluate deny (identity/role/show)", |b| {
        b.iter(|| enforcer.evaluate("identity/role/show", black_box(denied.clone())))
    });
    c.bench_function("load all policies", |b| {
        b.iter(|| RegorusPolicyEnforcer::new(&policies).expect("policies compile"))
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
