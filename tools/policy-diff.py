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
"""Differential test of OPA against the in-process regorus enforcer.

Every `with input as {...}` document used by the `*_test.rego` suites is
sent to the package under test in both engines and the decisions
(`allow`, `violation`, `can_see_other_domain_resources`) are compared.

Usage: [POLICY_DIR=dir] tools/policy-diff.py [--opa PATH] [--report FILE]
"""
import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POLICY = os.environ.get("POLICY_DIR") or os.path.join(ROOT, "policy")
REF = re.compile(r"(\w+)\.(allow|violation|can_see_other_domain_resources)\b")


def balanced(src, start):
    """Return the balanced `{...}` literal starting at src[start]."""
    depth, i, in_str = 0, start, False
    while i < len(src):
        c = src[i]
        if in_str:
            if c == "\\":
                i += 1
            elif c == '"':
                in_str = False
        elif c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return src[start : i + 1]
        i += 1
    return None


def extract_cases():
    cases, skipped = [], 0
    for dp, _, fns in os.walk(POLICY):
        for fn in sorted(fns):
            if not fn.endswith("_test.rego"):
                continue
            path = os.path.join(dp, fn)
            src = open(path).read()
            aliases = {}
            for m in re.finditer(r"^import data\.([\w.]+)(?: as (\w+))?", src, re.M):
                pkg = m.group(1)
                aliases[m.group(2) or pkg.split(".")[-1]] = pkg
            for m in re.finditer(r"with input as\s*(\{)", src):
                lit = balanced(src, m.start(1))
                # the alias is the last `alias.rule` before `with` on its statement
                head = src[max(0, src.rfind("\n\n", 0, m.start())) : m.start()]
                refs = [r for r in REF.findall(head) if r[0] in aliases]
                if not lit or not refs:
                    skipped += 1
                    continue
                try:
                    inp = json.loads(lit)
                except ValueError:
                    skipped += 1
                    continue
                cases.append(
                    {
                        "package": aliases[refs[-1][0]],
                        "input": inp,
                        "file": os.path.relpath(path, POLICY),
                    }
                )
    return cases, skipped


def norm(d):
    if d is None:
        return None
    viol = d.get("violation")
    return {
        "allow": bool(d.get("allow")),
        "violation": None
        if viol is None
        else sorted(json.dumps(v, sort_keys=True) for v in viol),
        "can_see": d.get("can_see_other_domain_resources"),
    }


def opa_decisions(opa, cases):
    port = 18181
    proc = subprocess.Popen(
        [opa, "run", "-s", POLICY, "--addr", f"127.0.0.1:{port}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1)
                break
            except Exception:
                time.sleep(0.1)
        out = []
        for c in cases:
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/v1/data/{c['package'].replace('.', '/')}",
                data=json.dumps({"input": c["input"]}).encode(),
                headers={"Content-Type": "application/json"},
            )
            out.append(norm(json.load(urllib.request.urlopen(req)).get("result")))
        return out
    finally:
        proc.terminate()


def regorus_decisions(cases):
    with tempfile.TemporaryDirectory() as tmp:
        cin, cout = os.path.join(tmp, "in.json"), os.path.join(tmp, "out.json")
        json.dump(cases, open(cin, "w"))
        env = dict(os.environ, POLICY_DIFF_CASES=cin, POLICY_DIFF_OUT=cout)
        subprocess.run(
            ["cargo", "test", "-q", "-p", "openstack-keystone-policy-regorus",
             "dump_decisions", "--", "--ignored", "--nocapture"],
            cwd=ROOT, env=env, check=True, stdout=subprocess.DEVNULL,
        )
        return [norm(d) for d in json.load(open(cout))]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--opa", default="opa")
    ap.add_argument("--report")
    args = ap.parse_args()
    cases, skipped = extract_cases()
    print(f"{len(cases)} cases extracted ({skipped} inputs skipped: not plain JSON)")
    ref = opa_decisions(args.opa, cases)
    got = regorus_decisions(cases)
    diffs = []
    for c, a, b in zip(cases, ref, got):
        if a != b:
            diffs.append({**c, "opa": a, "regorus": b})
    by_pkg = {}
    for d in diffs:
        by_pkg.setdefault(d["package"], []).append(d)
    print(f"{len(diffs)} divergences in {len(by_pkg)} packages")
    for pkg, ds in sorted(by_pkg.items()):
        kinds = {("error" if d["regorus"] is None else "decision") for d in ds}
        print(f"  {pkg}: {len(ds)} ({','.join(sorted(kinds))})")
    if args.report:
        json.dump(diffs, open(args.report, "w"), indent=1)
    sys.exit(1 if diffs else 0)


if __name__ == "__main__":
    main()
