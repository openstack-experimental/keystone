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
"""Throughput and latency against the user count of a ramp run.

Reads the JSON report of goose (`--report-file ... --report-graph-data`,
written by `tools/compare-memory.sh --ramp-time` as `report-<target>.json`)
and prints one row per time window: the users running, requests per second,
mean response time and the share of failed requests, plus the same
rate and latency split into the requests that hash a password (auth) and
the rest.

    tools/ramp-knee.py reports/ramp-rs/report-rs.json [window-seconds]
"""
import json
import sys


def main() -> None:
    graphs = json.load(open(sys.argv[1]))["graphs"]
    window = int(sys.argv[2]) if len(sys.argv) > 2 else 20

    seconds = len(graphs["users_per_second"]["data"])
    count = [0] * seconds
    weighted = [0.0] * seconds
    # Requests that hash a password (password and application credential
    # login) run on the dedicated hashing pool; everything else is "rest".
    auth_count = [0] * seconds
    auth_weighted = [0.0] * seconds
    for name, series in graphs["average_response_time"].items():
        hashes = "(password)" in name or "(application credential)" in name
        for i, (n, avg) in enumerate(series["data"][:seconds]):
            count[i] += n
            weighted[i] += n * avg
            if hashes:
                auth_count[i] += n
                auth_weighted[i] += n * avg
    failed = [0] * seconds
    for series in graphs["errors_per_second"].values():
        for i, n in enumerate(series["data"][:seconds]):
            failed[i] += n
    users = graphs["users_per_second"]["data"]

    print(
        "window_s  users   rps   mean_ms  failed_%"
        "  auth_rps  auth_ms  rest_rps  rest_ms"
    )
    peak = (0.0, 0)
    for start in range(0, seconds, window):
        end = min(start + window, seconds)
        n = sum(count[start:end])
        if n == 0:
            continue
        rps = n / (end - start)
        span = end - start
        an = sum(auth_count[start:end])
        rn = n - an
        a_ms = sum(auth_weighted[start:end]) / an if an else 0.0
        r_ms = (sum(weighted[start:end]) - sum(auth_weighted[start:end])) / rn if rn else 0.0
        print(
            f"{start:7d} {max(users[start:end]):6d} {rps:7.0f} "
            f"{sum(weighted[start:end]) / n:8.1f} "
            f"{100 * sum(failed[start:end]) / n:8.2f} "
            f"{an / span:9.1f} {a_ms:8.1f} {rn / span:9.0f} {r_ms:8.1f}"
        )
        if rps > peak[0]:
            peak = (rps, max(users[start:end]))
    print(f"\npeak {peak[0]:.0f} rps at {peak[1]} users")


if __name__ == "__main__":
    main()
