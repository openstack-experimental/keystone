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
"""Gate E: Rego lint for the undefined-argument footgun (security review V3, #985).

`doc/src/security.md` I2: a delegation-boundary helper function's argument
must never be `undefined` -- Rego evaluates a function's argument before
dispatching to either of its rule bodies, so an undefined argument makes
even the "not delegated" fast path (which never reads it) undefined too.
Callers must wrap the argument in `object.get(parent, "key", null)`, never
pass a bare dotted path like `input.target.credential.project_id` (which is
`undefined`, not `null`, whenever an intermediate key is absent or the
object itself is `null`).

This scans every non-test `.rego` file under `policy/` for call sites of the
known delegation-boundary helper functions and flags any argument that is a
bare dotted-path expression instead of an `object.get(...)` call.
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_ROOT = REPO_ROOT / "policy"

# Delegation-boundary helper functions whose argument contract (security.md
# I2) requires object.get(...)-wrapped access -- see the doc comment on
# `not_delegated_or_bound_to_own_project` in policy/credential/common.rego.
# Extend this list if a new helper with the same contract is added.
GUARDED_FUNCTIONS = [
    "bound_to_own_delegation_project",
    "not_delegated_or_bound_to_own_project",
]

CALL_RE = re.compile(
    r"(?:[\w.]+\.)?(" + "|".join(re.escape(f) for f in GUARDED_FUNCTIONS) + r")\(([^)]*)\)"
)


def find_violations():
    violations = []
    for path in sorted(POLICY_ROOT.rglob("*.rego")):
        if path.stem.endswith("_test"):
            continue
        text = path.read_text()
        for lineno, line in enumerate(text.splitlines(), start=1):
            for m in CALL_RE.finditer(line):
                func_name, arg = m.group(1), m.group(2).strip()
                # A bare identifier is either the function's own definition
                # (`fn(project_id) if {`) or a call site passing a local
                # variable that may already have been derived safely
                # elsewhere -- neither is checkable by this regex-based
                # scan, so only dotted-path expressions are flagged.
                if "." not in arg:
                    continue
                if "object.get(" in arg:
                    continue
                violations.append(
                    f"{path.relative_to(REPO_ROOT)}:{lineno}: {func_name}({arg}) is "
                    "called with a bare path argument, not object.get(..., null) -- "
                    "an undefined argument silently makes every rule using this "
                    "function undefined too (security.md I2)"
                )
    return violations


def main():
    violations = find_violations()
    if violations:
        print("Gate E (Rego undefined-argument footgun) failed:\n")
        for v in violations:
            print(f"  - {v}")
        print(f"\n{len(violations)} issue(s) found.")
        return 1
    print(f"Gate E OK: every {', '.join(GUARDED_FUNCTIONS)} call site uses object.get(...).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
