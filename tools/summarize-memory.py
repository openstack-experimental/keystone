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
"""Summarize the CSV written by tools/compare-memory.sh as Markdown.

Per pod: first/max/last of each series and the growth slope (MiB/h, least
squares over the second half of the samples, so warmup is excluded). A slope
that stays positive for RssAnon after warmup is a leak or fragmentation; a
plateau is a cache or allocator high-water mark.
"""
import csv
import sys
from collections import defaultdict

COLS = ["working_set_mib", "rss_mib", "rss_anon_mib", "rss_file_mib"]


def slope_per_hour(points):
    """Least squares slope of (seconds, MiB) points, in MiB/hour."""
    n = len(points)
    if n < 3:
        return float("nan")
    mx = sum(x for x, _ in points) / n
    my = sum(y for _, y in points) / n
    den = sum((x - mx) ** 2 for x, _ in points)
    if den == 0:
        return float("nan")
    return sum((x - mx) * (y - my) for x, y in points) / den * 3600


def main(path):
    series = defaultdict(list)
    with open(path) as fh:
        for row in csv.DictReader(fh):
            try:
                vals = {c: float(row[c]) for c in COLS if row[c] != ""}
            except ValueError:
                continue
            series[(row["target"], row["pod"])].append((int(row["ts"]), vals))

    print("| target | pod | metric | first | max | last | slope MiB/h (2nd half) |")
    print("|---|---|---|---:|---:|---:|---:|")
    totals = defaultdict(float)
    for (target, pod), samples in sorted(series.items()):
        samples.sort()
        t0 = samples[0][0]
        for col in COLS:
            pts = [(ts - t0, v[col]) for ts, v in samples if col in v]
            if not pts:
                continue
            ys = [y for _, y in pts]
            tail = pts[len(pts) // 2 :]
            print(
                f"| {target} | {pod} | {col} | {ys[0]:.0f} | {max(ys):.0f} "
                f"| {ys[-1]:.0f} | {slope_per_hour(tail):+.1f} |"
            )
            if col == "working_set_mib":
                totals[target] += ys[-1]
    print()
    for target, total in sorted(totals.items()):
        print(f"- {target}: sum of last working set over pods = {total:.0f} MiB")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: summarize-memory.py memory.csv")
    main(sys.argv[1])
