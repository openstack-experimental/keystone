#!/usr/bin/env python3
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
"""Gate B1: policy <-> handler existence checker (security review V3, #977).

`opa test policy` (Gate A) proves the Rego logic is internally consistent.
It says nothing about whether a `policy_name` string a handler passes to
`enforce()` actually resolves to a real policy package, whether that policy
carries a test, or whether every CRUD handler calls `enforce()` at all.  This
script closes that gap with five checks, failing the build on any orphan
found in any direction:

  1. missing policy  -- every `.enforce("<name>", ...)` call site's name must
     resolve to a `.rego` file that declares a matching `package` (OPA
     resolves `data.<package>` by package declaration, not by directory
     layout, so this cannot be done with a naive path join).
  2. missing test    -- that `.rego` file must have a sibling `<stem>_test.rego`
     in the same directory.
  3. orphan policy   -- every decision-endpoint policy (a package that
     defines `default allow`, as opposed to a shared helper module such as
     `credential/common.rego`) must be referenced by at least one `enforce()`
     call somewhere in the Rust tree.
  4. unenforced handler -- every CRUD handler module (`create.rs`, `show.rs`,
     `update.rs`, `delete.rs`, `list.rs`) under a known handler tree must
     contain at least one `enforce()` call, except a small, explicit,
     reviewed allowlist of endpoints that intentionally run pre-authn.
  5. unasserted input contract (Gate B2, security review V3a, issue #990) --
     every Rust source file that calls `.enforce(...)` must also reference
     `policy_contract` (`crates/core/src/api/policy_contract.rs`'s
     `assert_object_keys`/`assert_no_secrets`/`assert_existing_presence`),
     either directly or in a sibling `#[path = "...tests.rs"]` test module.
     Gate B1 (check 4) only proves a handler calls `enforce()` at all; it says
     nothing about whether the `(policy_name, target, existing)` triple it
     builds is actually asserted anywhere, which is exactly the seam V3a
     names. This check is the "make Gate B2 non-optional" ask from the
     2026-09-14 review re-evaluation. Existing handlers written before this
     check landed are carried in `ALLOWLIST_NO_POLICY_CONTRACT`, an explicit,
     reviewed backlog -- new handlers are not allowed to join it; shrink it by
     adding a policy_contract-asserting test and removing the entry.
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_ROOT = REPO_ROOT / "policy"
CRATES_ROOT = REPO_ROOT / "crates"

# Handler trees where OPA enforce() is expected to gate every CRUD verb.
# Persistence-layer crates (*-driver-sql) and CLI tooling (cli-manage) also
# have create/show/update/delete/list.rs modules, but enforcement happens
# once at the HTTP handler layer before a request reaches the backend, so
# they are intentionally not in this list.
HANDLER_ROOTS = [
    CRATES_ROOT / "keystone/src/api",
    CRATES_ROOT / "keystone/src/scim",
    CRATES_ROOT / "keystone/src/federation/api",
    CRATES_ROOT / "keystone/src/k8s_auth/api",
    CRATES_ROOT / "webauthn/src/api",
]

CRUD_FILENAMES = {"create.rs", "show.rs", "update.rs", "delete.rs", "list.rs"}

# Handlers that intentionally do not call enforce(): they run before any
# Credentials exist to key a policy decision on. Keep this list explicit and
# reviewed -- anything else missing enforce() is a bug, not an exception.
ALLOWLIST_NO_ENFORCE = {
    CRATES_ROOT / "keystone/src/api/v3/auth/token/create.rs",
}

ENFORCE_CALL_RE = re.compile(r"\.enforce\(\s*\"([\w/]+)\"")
PACKAGE_RE = re.compile(r"^package\s+([\w.]+)", re.MULTILINE)
DEFAULT_ALLOW_RE = re.compile(r"^default\s+allow\b", re.MULTILINE)
TEST_MOD_PATH_RE = re.compile(r'#\[path\s*=\s*"([^"]+tests\.rs)"\]')

# Gate B2 backlog (check 5, issue #990): handler modules that called
# enforce() before the check existed and don't yet assert the B2 input
# contract. This list only shrinks -- a new handler with .enforce() but no
# policy_contract reference must not be added here; it must ship the test.
# Regenerate the "does it still belong" question per entry with:
#   python3 tools/check_policy_handler_coverage.py
# and remove any entry the output no longer flags.
ALLOWLIST_NO_POLICY_CONTRACT = {
    CRATES_ROOT / p
    for p in [
        "keystone/src/api/v3/auth/project/list.rs",
        "keystone/src/api/v3/auth/token/delete.rs",
        "keystone/src/api/v3/auth/token/show.rs",
        "keystone/src/api/v3/domain/create.rs",
        "keystone/src/api/v3/domain/delete.rs",
        "keystone/src/api/v3/domain/list.rs",
        "keystone/src/api/v3/domain/show.rs",
        "keystone/src/api/v3/domain/update.rs",
        "keystone/src/api/v3/domain_config/create.rs",
        "keystone/src/api/v3/domain_config/default.rs",
        "keystone/src/api/v3/domain_config/delete.rs",
        "keystone/src/api/v3/domain_config/group.rs",
        "keystone/src/api/v3/domain_config/option.rs",
        "keystone/src/api/v3/domain_config/show.rs",
        "keystone/src/api/v3/domain_config/update.rs",
        "keystone/src/api/v3/endpoint/create.rs",
        "keystone/src/api/v3/endpoint/delete.rs",
        "keystone/src/api/v3/endpoint/list.rs",
        "keystone/src/api/v3/endpoint/show.rs",
        "keystone/src/api/v3/endpoint/update.rs",
        "keystone/src/api/v3/group/create.rs",
        "keystone/src/api/v3/group/delete.rs",
        "keystone/src/api/v3/group/list.rs",
        "keystone/src/api/v3/group/show.rs",
        "keystone/src/api/v3/group/update.rs",
        "keystone/src/api/v3/project/create.rs",
        "keystone/src/api/v3/project/delete.rs",
        "keystone/src/api/v3/project/list.rs",
        "keystone/src/api/v3/project/show.rs",
        "keystone/src/api/v3/project/update.rs",
        "keystone/src/api/v3/region/create.rs",
        "keystone/src/api/v3/region/delete.rs",
        "keystone/src/api/v3/region/list.rs",
        "keystone/src/api/v3/region/show.rs",
        "keystone/src/api/v3/region/update.rs",
        "keystone/src/api/v3/role/create.rs",
        "keystone/src/api/v3/role/delete.rs",
        "keystone/src/api/v3/role/imply/check.rs",
        "keystone/src/api/v3/role/imply/create.rs",
        "keystone/src/api/v3/role/imply/delete.rs",
        "keystone/src/api/v3/role/imply/get.rs",
        "keystone/src/api/v3/role/imply/list.rs",
        "keystone/src/api/v3/role/list.rs",
        "keystone/src/api/v3/role/show.rs",
        "keystone/src/api/v3/role/update.rs",
        "keystone/src/api/v3/role_assignment/list.rs",
        "keystone/src/api/v3/role_assignment/project/user/role/check.rs",
        "keystone/src/api/v3/role_assignment/project/user/role/grant.rs",
        "keystone/src/api/v3/role_assignment/project/user/role/list.rs",
        "keystone/src/api/v3/role_assignment/project/user/role/revoke.rs",
        "keystone/src/api/v3/role_assignment/system/user/role/check.rs",
        "keystone/src/api/v3/role_assignment/system/user/role/grant.rs",
        "keystone/src/api/v3/role_assignment/system/user/role/list.rs",
        "keystone/src/api/v3/role_assignment/system/user/role/revoke.rs",
        "keystone/src/api/v3/role_inferences.rs",
        "keystone/src/api/v3/service/create.rs",
        "keystone/src/api/v3/service/delete.rs",
        "keystone/src/api/v3/service/list.rs",
        "keystone/src/api/v3/service/show.rs",
        "keystone/src/api/v3/service/update.rs",
        "keystone/src/api/v3/user/application_credential/create.rs",
        "keystone/src/api/v3/user/application_credential/delete.rs",
        "keystone/src/api/v3/user/application_credential/list.rs",
        "keystone/src/api/v3/user/application_credential/show.rs",
        "keystone/src/api/v3/user/create.rs",
        "keystone/src/api/v3/user/delete.rs",
        "keystone/src/api/v3/user/groups.rs",
        "keystone/src/api/v3/user/list.rs",
        "keystone/src/api/v3/user/show.rs",
        "keystone/src/api/v3/user/update.rs",
        "keystone/src/api/v4/api_key/create.rs",
        "keystone/src/api/v4/api_key/list.rs",
        "keystone/src/api/v4/api_key/revoke.rs",
        "keystone/src/api/v4/api_key/show.rs",
        "keystone/src/api/v4/api_key/simulate_access.rs",
        "keystone/src/api/v4/api_key/update.rs",
        "keystone/src/api/v4/auth_plugin/identity_link/create.rs",
        "keystone/src/api/v4/auth_plugin/identity_link/delete.rs",
        "keystone/src/api/v4/auth_plugin/revoke_all.rs",
        "keystone/src/api/v4/mapping/ruleset/create.rs",
        "keystone/src/api/v4/mapping/ruleset/delete.rs",
        "keystone/src/api/v4/mapping/ruleset/list.rs",
        "keystone/src/api/v4/mapping/ruleset/mutate.rs",
        "keystone/src/api/v4/mapping/ruleset/show.rs",
        "keystone/src/api/v4/mapping/ruleset/update.rs",
        "keystone/src/api/v4/oauth2/clients/create.rs",
        "keystone/src/api/v4/oauth2/clients/delete.rs",
        "keystone/src/api/v4/oauth2/clients/list.rs",
        "keystone/src/api/v4/oauth2/clients/rotate_secret.rs",
        "keystone/src/api/v4/oauth2/clients/show.rs",
        "keystone/src/api/v4/oauth2/clients/update.rs",
        "keystone/src/api/v4/oauth2/confirm_rotate_signing_key.rs",
        "keystone/src/api/v4/oauth2/ensure_signing_key.rs",
        "keystone/src/api/v4/oauth2/local_emergency_key.rs",
        "keystone/src/api/v4/oauth2/rotate_signing_key.rs",
        "keystone/src/api/v4/scim_realm/create.rs",
        "keystone/src/api/v4/scim_realm/list.rs",
        "keystone/src/api/v4/scim_realm/purge.rs",
        "keystone/src/api/v4/scim_realm/show.rs",
        "keystone/src/api/v4/scim_realm/update.rs",
        "keystone/src/api/v4/token/restriction/create.rs",
        "keystone/src/api/v4/token/restriction/delete.rs",
        "keystone/src/api/v4/token/restriction/list.rs",
        "keystone/src/api/v4/token/restriction/show.rs",
        "keystone/src/api/v4/token/restriction/update.rs",
        "keystone/src/api/v4/user/create.rs",
        "keystone/src/api/v4/user/delete.rs",
        "keystone/src/api/v4/user/groups.rs",
        "keystone/src/api/v4/user/list.rs",
        "keystone/src/api/v4/user/show.rs",
        "keystone/src/api/v4/user/update.rs",
        "keystone/src/api/v4/vendordata.rs",
        "keystone/src/federation/api/identity_provider/create.rs",
        "keystone/src/federation/api/identity_provider/delete.rs",
        "keystone/src/federation/api/identity_provider/list.rs",
        "keystone/src/federation/api/identity_provider/show.rs",
        "keystone/src/federation/api/identity_provider/update.rs",
        "keystone/src/k8s_auth/api/instance/create.rs",
        "keystone/src/k8s_auth/api/instance/delete.rs",
        "keystone/src/k8s_auth/api/instance/list.rs",
        "keystone/src/k8s_auth/api/instance/show.rs",
        "keystone/src/k8s_auth/api/instance/update.rs",
        "keystone/src/scim/group/create.rs",
        "keystone/src/scim/group/delete.rs",
        "keystone/src/scim/group/list.rs",
        "keystone/src/scim/group/patch.rs",
        "keystone/src/scim/group/show.rs",
        "keystone/src/scim/group/update.rs",
        "keystone/src/scim/user/create.rs",
        "keystone/src/scim/user/delete.rs",
        "keystone/src/scim/user/list.rs",
        "keystone/src/scim/user/patch.rs",
        "keystone/src/scim/user/show.rs",
        "keystone/src/scim/user/update.rs",
        "webauthn/src/api/register/finish.rs",
        "webauthn/src/api/register/start.rs",
    ]
}


def extract_enforced_policy_names():
    """Map enforce() policy_name -> set of Rust source files calling it."""
    names = {}
    for src_root in CRATES_ROOT.glob("*/src"):
        for path in src_root.rglob("*.rs"):
            text = path.read_text()
            for m in ENFORCE_CALL_RE.finditer(text):
                names.setdefault(m.group(1), set()).add(path.relative_to(REPO_ROOT))
    return names


def index_decision_policies():
    """Map dotted package name -> .rego file, for non-test decision endpoints.

    A decision-endpoint policy is one that declares `default allow`; shared
    helper modules (e.g. `credential/common.rego`) import other policies'
    package but don't define one themselves, and are not enforce() targets.
    """
    packages = {}
    duplicates = []
    for path in sorted(POLICY_ROOT.rglob("*.rego")):
        if path.stem.endswith("_test"):
            continue
        text = path.read_text()
        m = PACKAGE_RE.search(text)
        if not m:
            continue
        if not DEFAULT_ALLOW_RE.search(text):
            continue
        pkg = m.group(1)
        if pkg in packages:
            duplicates.append((pkg, packages[pkg], path))
            continue
        packages[pkg] = path
    return packages, duplicates


def check_enforced_names_resolve(names, packages):
    errors = []
    for name, sites in sorted(names.items()):
        sites_str = ", ".join(str(s) for s in sorted(sites))
        pkg = name.replace("/", ".")
        rego_path = packages.get(pkg)
        if rego_path is None:
            errors.append(
                f'enforce("{name}") called from [{sites_str}] but no '
                f".rego file declares `package {pkg}` with `default allow`"
            )
            continue
        test_path = rego_path.with_name(rego_path.stem + "_test.rego")
        if not test_path.exists():
            errors.append(
                f'enforce("{name}") resolves to {rego_path.relative_to(REPO_ROOT)} '
                f"but its sibling test file {test_path.relative_to(REPO_ROOT)} "
                "does not exist"
            )
    return errors


def check_no_orphan_policies(names, packages):
    errors = []
    for pkg, path in sorted(packages.items()):
        name = pkg.replace(".", "/")
        if name not in names:
            errors.append(
                f"{path.relative_to(REPO_ROOT)} declares `package {pkg}` with "
                f'`default allow` but no handler calls enforce("{name}")'
            )
    return errors


def check_duplicate_packages(duplicates):
    errors = []
    for pkg, first, second in duplicates:
        errors.append(
            f"package `{pkg}` with `default allow` is declared in both "
            f"{first.relative_to(REPO_ROOT)} and {second.relative_to(REPO_ROOT)}"
        )
    return errors


def check_handler_coverage():
    errors = []
    for handler_root in HANDLER_ROOTS:
        if not handler_root.exists():
            continue
        for path in sorted(handler_root.rglob("*.rs")):
            if path.name not in CRUD_FILENAMES:
                continue
            if path in ALLOWLIST_NO_ENFORCE:
                continue
            text = path.read_text()
            if not ENFORCE_CALL_RE.search(text):
                errors.append(
                    f"{path.relative_to(REPO_ROOT)} is a CRUD handler module "
                    "but contains no .enforce(...) call"
                )
    return errors


def check_input_contract_coverage(names):
    """Gate B2 (security review V3a, issue #990), check 5: every file that
    calls enforce() must reference `policy_contract` -- directly, or in a
    sibling `#[path = "...tests.rs"]` test module -- unless explicitly
    allowlisted.
    """
    file_to_names = {}
    for name, sites in names.items():
        for site in sites:
            file_to_names.setdefault(REPO_ROOT / site, set()).add(name)

    errors = []
    for path, policy_names in sorted(file_to_names.items()):
        if path in ALLOWLIST_NO_POLICY_CONTRACT:
            continue
        text = path.read_text()
        if "policy_contract" in text:
            continue
        m = TEST_MOD_PATH_RE.search(text)
        if m:
            sibling = path.parent / m.group(1)
            if sibling.exists() and "policy_contract" in sibling.read_text():
                continue
        names_str = ", ".join(f'"{n}"' for n in sorted(policy_names))
        errors.append(
            f"{path.relative_to(REPO_ROOT)} calls enforce({names_str}) but "
            "neither it nor its test module references `policy_contract` "
            "(Gate B2 input-contract assertions) -- add a "
            "policy_contract-asserting test, or if this is a pre-existing "
            "handler being triaged, add it to ALLOWLIST_NO_POLICY_CONTRACT "
            "with a reason; new handlers may not be added to that list"
        )
    return errors


def main():
    names = extract_enforced_policy_names()
    packages, duplicates = index_decision_policies()

    errors = []
    errors.extend(check_duplicate_packages(duplicates))
    errors.extend(check_enforced_names_resolve(names, packages))
    errors.extend(check_no_orphan_policies(names, packages))
    errors.extend(check_handler_coverage())
    errors.extend(check_input_contract_coverage(names))

    if errors:
        print("Gate B1 (policy<->handler existence check) failed:\n")
        for e in errors:
            print(f"  - {e}")
        print(f"\n{len(errors)} issue(s) found.")
        return 1

    file_count = len({site for sites in names.values() for site in sites})
    allowlisted = len(ALLOWLIST_NO_POLICY_CONTRACT)
    print(
        f"Gate B1 OK: {len(names)} enforce() call site(s) all resolve to a "
        f"policy + test; all {len(packages)} decision-endpoint policies are "
        "referenced; all CRUD handler modules call enforce(). "
        f"Gate B2 OK: {file_count - allowlisted} of {file_count} "
        "enforce()-calling files assert the policy_contract input contract "
        f"({allowlisted} pre-existing handlers tracked in "
        "ALLOWLIST_NO_POLICY_CONTRACT)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
