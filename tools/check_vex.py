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
"""Check that every advisory ignored in deny.toml has an OpenVEX statement.

CRA Annex I Part II requires an exploitability assessment for known
vulnerabilities in components. `deny.toml` silences an advisory; the
statement in supply-chain/vex/keystone.openvex.json says why that is safe (or
what the operator must do). Exit status 1 lists the gaps.
"""
import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}


def main() -> int:
    deny = tomllib.loads((ROOT / "deny.toml").read_text())
    ignored = set()
    for entry in deny.get("advisories", {}).get("ignore", []):
        ignored.add(entry if isinstance(entry, str) else entry.get("id"))
    ignored.discard(None)

    vex = json.loads((ROOT / "supply-chain/vex/keystone.openvex.json").read_text())
    problems = []
    covered = set()
    for st in vex.get("statements", []):
        name = st.get("vulnerability", {}).get("name")
        covered.add(name)
        status = st.get("status")
        if status not in STATUSES:
            problems.append(f"{name}: invalid status {status!r}")
        elif status == "not_affected" and not (
            st.get("justification") or st.get("impact_statement")
        ):
            problems.append(f"{name}: not_affected needs a justification")
        elif status == "affected" and not st.get("action_statement"):
            problems.append(f"{name}: affected needs an action_statement")

    for missing in sorted(ignored - covered):
        problems.append(f"{missing}: ignored in deny.toml but has no VEX statement")

    for p in problems:
        print(f"VEX check: {p}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
