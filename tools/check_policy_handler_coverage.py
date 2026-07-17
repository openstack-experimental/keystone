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
script closes that gap with three checks, failing the build on any orphan
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


def main():
    names = extract_enforced_policy_names()
    packages, duplicates = index_decision_policies()

    errors = []
    errors.extend(check_duplicate_packages(duplicates))
    errors.extend(check_enforced_names_resolve(names, packages))
    errors.extend(check_no_orphan_policies(names, packages))
    errors.extend(check_handler_coverage())

    if errors:
        print("Gate B1 (policy<->handler existence check) failed:\n")
        for e in errors:
            print(f"  - {e}")
        print(f"\n{len(errors)} issue(s) found.")
        return 1

    print(
        f"Gate B1 OK: {len(names)} enforce() call site(s) all resolve to a "
        f"policy + test; all {len(packages)} decision-endpoint policies are "
        "referenced; all CRUD handler modules call enforce()."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
