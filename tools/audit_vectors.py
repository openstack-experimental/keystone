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
"""Independent (non-Rust) reference verifier for the audit HMAC vectors.

Verifies every vector in ``tests/audit/hmac_vectors.jsonl`` by re-deriving
the RFC 8785 (JCS) canonical form and HMAC-SHA256 in pure Python, so the
"cross-language" contract of ADR 0023 is exercised by a second implementation.

Usage:
    tools/audit_vectors.py verify      # check every vector (exit 1 on mismatch)
    tools/audit_vectors.py generate    # append the missing vectors

The event fields used by the vectors are strings, integers and objects only,
for which ``json.dumps(sort_keys=True, separators=(",", ":"),
ensure_ascii=False)`` is the JCS form (no floats).
"""

import hashlib
import hmac
import json
import pathlib
import sys

VECTORS = pathlib.Path(__file__).resolve().parent.parent / "tests/audit/hmac_vectors.jsonl"
KEY_HEX = "746573742d6b65792d33322d62797465732d3031323334353637383961626364"


def jcs(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sign(event: dict, key: bytes) -> str:
    body = {k: v for k, v in event.items() if k != "signature"}
    return hmac.new(key, jcs(body).encode(), hashlib.sha256).hexdigest()


def wire_event(n: int, initiator: dict, reason: str | None) -> dict:
    """A record in the DSP0262 layout.

    Correlation id is a ``tags`` entry; the fields DSP0262 has no place for are
    carried in the ``integrity`` attachment.
    """
    event = {
        "typeURI": "http://schemas.dmtf.org/cloud/audit/1.0/event",
        "eventType": "activity",
        "id": f"test-node:550e8400-e29b-41d4-a716-{n:012x}",
        "eventTime": "2026-06-16T00:00:00+00:00",
        "action": "authenticate",
        "outcome": "failure",
        "initiator": {**initiator, "typeURI": "service/security/account/user"},
        "target": {"id": "keystone", "typeURI": "service/security/keystone/auth"},
        "observer": {
            "id": "service/security/keystone/test-node",
            "typeURI": "service/security/keystone",
        },
        "tags": [f"correlation_id:req-{n:032x}"],
        "attachments": [
            {
                "name": "integrity",
                "contentType": "application/json",
                "content": {
                    "seq": n,
                    "boot_session_id": "00000000-0000-0000-0000-000000000001",
                    "hmac_key_version": 1,
                    "version": "1.1",
                    "domain": initiator.get("domain_id") or "unknown",
                    "observer_node_id": "test-node",
                },
            }
        ],
    }
    if reason is not None:
        event["reason"] = {"reasonType": "keystone", "reasonCode": reason}
    return event


WIRE_CASES = {
    "dsp0262_failure_with_reason_and_host": ("Unauthorized", {"id": "AKIAABCDEFGHIJKLMNOP", "address": "203.0.113.9"}),
    "dsp0262_success_without_reason_or_host": (None, None),
    "dsp0262_pending_with_host_address": (None, {"address": "203.0.113.9"}),
}


def generate_wire() -> list[dict]:
    key = bytes.fromhex(KEY_HEX)
    out = []
    for i, (name, (reason, host)) in enumerate(WIRE_CASES.items(), start=20):
        initiator = {
            "domain_id": "0123456789abcdef0123456789abcdef",
            "id": "unknown",
            "project_id": None,
        }
        if host is not None:
            initiator["host"] = host
        event = wire_event(i, initiator, reason)
        if name.startswith("dsp0262_success"):
            event["outcome"] = "success"
        if name.startswith("dsp0262_pending"):
            event["outcome"] = "pending"
        event["signature"] = sign(event, key)
        body = {k: v for k, v in event.items() if k != "signature"}
        out.append(
            {
                "description": name,
                "key_hex": KEY_HEX,
                "canonical": jcs(body),
                "expected_signature": event["signature"],
                "event": event,
            }
        )
    return out


def load() -> list[dict]:
    return [json.loads(line) for line in VECTORS.read_text().splitlines() if line.strip()]


def verify() -> int:
    bad = 0
    for v in load():
        key = bytes.fromhex(v["key_hex"])
        event = v["event"]
        ok = (
            jcs({k: x for k, x in event.items() if k != "signature"}) == v["canonical"]
            and sign(event, key) == v["expected_signature"] == event["signature"]
        )
        print(("ok   " if ok else "FAIL ") + v["description"])
        bad += not ok
    return 1 if bad else 0


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "verify"
    if cmd == "verify":
        return verify()
    if cmd == "generate":
        have = {v["description"] for v in load()}
        new = [v for v in generate_wire() if v["description"] not in have]
        with VECTORS.open("a") as f:
            for v in new:
                f.write(json.dumps(v, separators=(",", ":"), ensure_ascii=False) + "\n")
        print(f"appended {len(new)} vectors")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
