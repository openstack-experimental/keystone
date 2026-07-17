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
"""Gate C: invariant-test presence check for delegated policies (security
review V1/V2, issue #982).

security.md I3: a delegated caller's rules must assert
`credentials.project_id == credentials.delegated_project_id`, failing closed
on divergence (the scope-drift tripwire) -- and every delegated policy's
test suite should carry a negative case proving that tripwire actually
fires, not just the "delegation bound to the wrong project" case. This
scans every decision-endpoint `.rego` file that is delegation-sensitive
(imports `credential_common`, or references `is_delegated` directly) and
requires its sibling `_test.rego` to contain a `not <alias>.allow` case
whose `credentials` object sets `project_id` and `delegated_project_id` to
different values with `is_delegated: true` -- the scope-drift shape itself,
not just a same-value-mismatched-project case.
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_ROOT = REPO_ROOT / "policy"

DELEGATION_MARKERS = ("credential_common", "is_delegated")


def extract_braced_value(text: str, key_index: int) -> str | None:
    """Given the index of a `"key":` match, return the `{...}` object that
    follows it (the first `{` after the colon), or None if not an object.
    """
    brace = text.find("{", key_index)
    if brace == -1:
        return None
    depth = 0
    for i in range(brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace : i + 1]
    return None


def has_scope_drift_case(test_text: str) -> bool:
    for m in re.finditer(r'"credentials"\s*:', test_text):
        creds = extract_braced_value(test_text, m.end())
        if creds is None:
            continue
        # The assertion must be a negative case (`not <alias>.allow`) --
        # find the nearest `not ... allow` on the same source line.
        line_start = test_text.rfind("\n", 0, m.start()) + 1
        line_end = test_text.find("\n", m.start())
        line = test_text[line_start : line_end if line_end != -1 else len(test_text)]
        if not re.search(r"\bnot\s+\S+\.allow\b", line):
            continue
        if not re.search(r'"is_delegated"\s*:\s*true', creds):
            continue
        pid_m = re.search(r'"project_id"\s*:\s*"([^"]*)"', creds)
        delegated_m = re.search(r'"delegated_project_id"\s*:\s*"([^"]*)"', creds)
        if pid_m and delegated_m and pid_m.group(1) != delegated_m.group(1):
            return True
    return False


def is_delegation_sensitive(text: str) -> bool:
    return any(marker in text for marker in DELEGATION_MARKERS)


def main():
    violations = []
    for path in sorted(POLICY_ROOT.rglob("*.rego")):
        if path.stem.endswith("_test"):
            continue
        text = path.read_text()
        if "default allow" not in text:
            continue  # not a decision-endpoint policy (e.g. common.rego)
        if not is_delegation_sensitive(text):
            continue
        test_path = path.with_name(path.stem + "_test.rego")
        if not test_path.exists():
            # Gate B1 already catches a missing test file outright.
            continue
        if not has_scope_drift_case(test_path.read_text()):
            violations.append(
                f"{test_path.relative_to(REPO_ROOT)}: {path.relative_to(REPO_ROOT)} is "
                "delegation-sensitive but its test suite has no scope-drift negative "
                "case (a `not <alias>.allow` with credentials.project_id != "
                "delegated_project_id and is_delegated: true) -- security.md I3"
            )
    if violations:
        print("Gate C (delegated-policy scope-drift test presence) failed:\n")
        for v in violations:
            print(f"  - {v}")
        print(f"\n{len(violations)} issue(s) found.")
        return 1
    print("Gate C OK: every delegation-sensitive policy's test suite has a scope-drift negative case.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
