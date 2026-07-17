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
"""Gate J: grep-based SAST for the security.md Section 7 reviewer checklist
(security review V1/V2, issue #986).

Most of the Section 7 checklist needs a human reviewer's judgement. Two
items are mechanically checkable and are exactly what this script encodes:

1. A wildcard `_ =>` arm in a match over `AuthenticationContext` or
   `ScopeInfo` inside one of the five security-critical projections
   (`Credentials::try_from`, `from_security_context`,
   `build_authz_info_from_fernet_token`, `validate_scope_boundaries`,
   `calculate_effective_roles`) is exactly V2's "a contributor adds a new
   auth method or scope shape and updates 6 of the 7 places that must
   change; the missed one silently widens authority" -- a wildcard arm
   compiles cleanly for a variant nobody has thought about yet, unlike an
   explicit arm-per-variant match, which fails to compile.
2. `input.credentials.project_id` used as a delegation boundary in a Rego
   rule that also checks `is_delegated` -- security.md I1/I2 require
   delegation boundaries to key on `delegated_project_id` (the chain), never
   `project_id` (the attacker-influenceable token scope).
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
POLICY_ROOT = REPO_ROOT / "policy"

# The five security-critical projections (security review V2 / security.md
# I1-I5) that must name every AuthenticationContext/ScopeInfo variant
# explicitly, never fall back to a wildcard arm.
CRITICAL_FUNCTIONS = [
    (REPO_ROOT / "crates/core/src/policy.rs", "fn try_from("),
    (REPO_ROOT / "crates/core-types/src/token.rs", "pub fn from_security_context("),
    (
        REPO_ROOT / "crates/core/src/token/service.rs",
        "async fn build_authz_info_from_fernet_token(",
    ),
    (REPO_ROOT / "crates/core-types/src/auth.rs", "pub fn validate_scope_boundaries("),
    (REPO_ROOT / "crates/core/src/auth.rs", "async fn calculate_effective_roles("),
]

TARGET_ENUMS = ("AuthenticationContext::", "ScopeInfo::")
# A wildcard arm's pattern, capturing everything up to the next top-level
# arm/closing-brace so its body can be inspected.
WILDCARD_ARM_RE = re.compile(r"(?:^|\n)[ \t]*_[ \t]*(?:if[^=]*)?=>(?P<body>.*?)(?=\n[ \t]*\S.*=>|\n[ \t]*\})", re.DOTALL)


def extract_braced_block(text: str, open_brace_index: int) -> str:
    """Return the `{...}` block (inclusive) starting at `open_brace_index`."""
    depth = 0
    for i in range(open_brace_index, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace_index : i + 1]
    return text[open_brace_index:]


def find_function_body(text: str, signature: str) -> str | None:
    sig_index = text.find(signature)
    if sig_index == -1:
        return None
    brace_index = text.find("{", sig_index)
    if brace_index == -1:
        return None
    return extract_braced_block(text, brace_index)


def strip_line_comments(text: str) -> str:
    """Blank out `//...` line comments so a stray "match"/"=>" in prose
    (e.g. a doc comment discussing match arms) can't be mistaken for code.
    Preserves line/character offsets by replacing with spaces, not deleting.
    """
    return re.sub(r"//[^\n]*", lambda m: " " * len(m.group(0)), text)


def find_match_blocks(body: str):
    """Yield (start_offset, block_text) for every `match ... { ... }` block
    in `body`, where `start_offset` is the block's absolute position within
    `body` -- used to dedupe a wildcard arm found via more than one
    enclosing match (an outer match legitimately nests inner ones).
    """
    code = strip_line_comments(body)
    for m in re.finditer(r"\bmatch\b[^{]*\{", code):
        start = m.end() - 1
        yield start, extract_braced_block(body, start)


def check_wildcard_arms():
    violations = []
    for path, signature in CRITICAL_FUNCTIONS:
        text = path.read_text()
        body = find_function_body(text, signature)
        if body is None:
            violations.append(
                f"{path.relative_to(REPO_ROOT)}: could not locate `{signature.strip()}` "
                "-- update CRITICAL_FUNCTIONS in tools/check_security_checklist_sast.py "
                "if it moved or was renamed"
            )
            continue
        seen_offsets = set()
        for block_start, block in find_match_blocks(body):
            if not any(enum in block for enum in TARGET_ENUMS):
                continue
            for wm in WILDCARD_ARM_RE.finditer(strip_line_comments(block)):
                arm_body = wm.group("body")
                # A wildcard arm that fails closed (denies) is not the V2
                # risk -- adding a variant still gets rejected by default,
                # not silently granted. Only an arm that can succeed
                # (Ok(...)/allow, or a no-op default) is a silent-widening
                # risk worth flagging.
                if re.search(r"\bErr\s*\(", arm_body) or "return Err" in arm_body:
                    continue
                # Absolute offset of the wildcard within `body`, so the same
                # arm found through both an outer and an inner enclosing
                # match (the outer one legitimately nests the inner one) is
                # only reported once.
                absolute_offset = block_start + wm.start()
                key = (path, absolute_offset)
                if key in seen_offsets:
                    continue
                seen_offsets.add(key)
                violations.append(
                    f"{path.relative_to(REPO_ROOT)}: `{signature.strip()}` contains a "
                    "wildcard `_ =>` arm in a match over AuthenticationContext/ScopeInfo "
                    "that does not fail closed -- name every variant explicitly so a new "
                    "one is a compile error, not a silent default (security.md V2)"
                )
    return violations


def check_rego_project_id_as_delegation_boundary():
    violations = []
    for path in sorted(POLICY_ROOT.rglob("*.rego")):
        if path.stem.endswith("_test"):
            continue
        text = path.read_text()
        if "is_delegated" not in text or "credentials.project_id" not in text:
            continue
        # Scope to each `... if { ... }` rule body so the co-occurrence is
        # actually within one rule, not just somewhere else in the file.
        for m in re.finditer(r"\bif\s*\{", text):
            block = extract_braced_block(text, m.end() - 1)
            if "is_delegated" not in block:
                continue
            for lineno_offset, line in enumerate(block.splitlines()):
                if re.search(r"credentials\.project_id\b", line) and "delegated_project_id" not in line:
                    line_no = text[: m.start()].count("\n") + 1 + lineno_offset
                    violations.append(
                        f"{path.relative_to(REPO_ROOT)}:{line_no}: `credentials.project_id` "
                        "(token scope) used inside an is_delegated rule body -- delegation "
                        "boundaries must key on `credentials.delegated_project_id` (the "
                        "chain), not the attacker-influenceable scope (security.md I1/I2)"
                    )
    return violations


def main():
    violations = check_wildcard_arms() + check_rego_project_id_as_delegation_boundary()
    if violations:
        print("Gate J (security.md §7 checklist SAST) failed:\n")
        for v in violations:
            print(f"  - {v}")
        print(f"\n{len(violations)} issue(s) found.")
        return 1
    print("Gate J OK: no wildcard arms in the 5 critical projections; no Rego rule "
          "uses credentials.project_id as a delegation boundary.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
