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
"""Gate I companion (security review V9, issue #987): structural check that
`EventPayload` (`crates/core-types/src/events.rs`) never grows a
secret-bearing field.

`EventPayload` variants feed the ADR 0023 audit trail (via `EventDispatcher`
/ `AuditHook`). Every variant today carries only ID-shaped fields, which is
exactly what makes the audit trail safe -- there is no decrypted credential
`blob`, password, or seed to leak. `EventPayload` deliberately does not
derive `Serialize` (a dynamic serialization test analogous to the
`Credentials` one in `crates/core/src/policy.rs` isn't possible without
adding it, which would be a bigger, riskier change than this check
warrants), so this is a source-level structural scan instead: it parses
every variant's field declarations and rejects a denylisted field name,
catching a future variant addition that reintroduces one.
"""

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EVENTS_RS = REPO_ROOT / "crates/core-types/src/events.rs"

# Same secret-field denylist as crates/core/src/api/policy_contract.rs.
SECRET_FIELD_NAMES = {
    "blob",
    "encrypted_blob",
    "key_hash",
    "password",
    "secret",
    "client_secret",
    "totp_seed",
    "seed",
    "access_token",
    "refresh_token",
}

FIELD_RE = re.compile(r"^\s*(\w+)\s*:\s*[^,{}]+,?\s*$")


def extract_enum_body(text: str, enum_name: str) -> str:
    marker = f"pub enum {enum_name} "
    start = text.find(marker)
    if start == -1:
        raise SystemExit(f"could not find `{marker}` in {EVENTS_RS}")
    brace = text.find("{", start)
    depth = 0
    for i in range(brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[brace : i + 1]
    raise SystemExit(f"unbalanced braces parsing `{enum_name}` in {EVENTS_RS}")


def find_field_violations(body: str):
    violations = []
    for line in body.splitlines():
        m = FIELD_RE.match(line)
        if not m:
            continue
        field_name = m.group(1)
        if field_name.lower() in SECRET_FIELD_NAMES:
            violations.append(field_name)
    return violations


def main():
    text = EVENTS_RS.read_text()
    body = extract_enum_body(text, "EventPayload")
    violations = find_field_violations(body)
    if violations:
        print("Gate I (EventPayload secret-field check) failed:\n")
        for v in violations:
            print(
                f"  - EventPayload has a field named `{v}`, which looks like it "
                "carries secret material into the ADR 0023 audit trail "
                "(security.md I7/V9)"
            )
        print(f"\n{len(violations)} issue(s) found.")
        return 1
    print("Gate I OK: no EventPayload variant has a secret-shaped field name.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
