# Rust vs Python Keystone comparison

This page compares the Rust Keystone (`keystone-rs`) with the Python Keystone
(`keystone-py`) under the same synthetic load on the same machine. It answers
one question: how much more load does the Rust implementation serve than the
Python one on the same hardware, and what does it cost in memory.

The numbers are a snapshot from one development machine. Each load step ran
once, so differences of a few percent are noise. Treat the figures as relative,
not absolute.

## Summary

One pod of each implementation, both with `requests = limits = 24` CPU on a
single-node k3s host with 32 cores, the same Postgres, and a closed-loop
virtual-user (VU) load that is stepped up until the 95th percentile (p95)
latency reaches 500 ms.

|                                              |          Rust |     Python | Rust advantage |
| -------------------------------------------- | ------------: | ---------: | -------------: |
| VUs at p95 = 500 ms, default mix (3% logins) |          ~673 |       ~188 |           3.6x |
| Throughput at that point, default mix        |  ~1,730 req/s | ~515 req/s |           3.4x |
| VUs at p95 = 500 ms, no password logins      |        ~1,364 |       ~187 |           7.3x |
| VUs per CPU core, no password logins         |          56.8 |        7.8 |           7.3x |
| Memory, idle                                 |      ~155 MiB |   ~2.7 GiB |      ~17x less |
| Memory, 600 VUs (average / max)              | 194 / 223 MiB |          - |                |
| Memory, 2,100 VUs (average / max)            | 297 / 428 MiB |          - |                |

What this shows:

- **Capacity.** With the default mix Rust carries about 3.5x the VUs and
  throughput of Python at the same p95 limit. The no-login figures are the
  better comparison of the implementations, see
  [Why password hashing is reduced](#why-password-hashing-is-reduced-for-the-comparison).
  The password logins are the expensive part for Rust (hashing is CPU-bound and
  runs in a bounded pool), so removing them moves Rust from ~673 to ~1,364 VUs.
  Python does not move (~188 to ~187), which means its limit is not the hashing.
- **Memory.** Rust runs in one process and shares everything between async
  tasks. Python pays a full copy of the application for each of its 24 worker
  processes. The Rust figure is roughly 155 to 430 MiB for the whole range of
  loads tested.
- **Reliability.** Rust had no failed requests at any step of the sweeps. Python
  returned about 2% HTTP 500 and 502 responses under load.
- **Python ceiling.** Python's throughput is flat at about 500 req/s regardless
  of the VU count. It may not be CPU-bound.

## Why password hashing is reduced for the comparison

Password hashing is an external load, not a property of either implementation.
Verifying a password costs a fixed amount of CPU, set by the hashing algorithm
and its cost parameters (the configured work factor), and it deliberately takes
tens of milliseconds. Both servers have to do the same work for every login, and
the cost does not depend on the language, the web framework, the database access
or the caching.

When logins are a noticeable share of the mix, that fixed cost dominates the CPU
budget. In the default mix only 3% of the operations are logins, but each one
costs far more CPU than any other operation (removing them roughly doubles the
VUs Rust carries), so the VU count at p95 = 500 ms partly measures how many
hashes the machine can compute. The other operations (token validation, reads,
role assignment) are what the implementations differ in, and their differences
are hidden behind the hashing.

The comparison therefore reports two views:

- **Default mix (3% logins).** Closer to a deployment where users log in with
  passwords all the time. It shows the result with the hashing cost included.
- **No password logins (`LOADTEST_VU_HASH_PCT=0`).** Isolates the logic and the
  framework: request handling, authorization, database round trips and
  revocation checks. This is the better measure of the performance benefit of
  the implementation, and it is the figure used for the VUs-per-core comparison.

Production deployments also reduce the share of password logins by design:
clients keep a token until it expires instead of a password for each request. A
mix dominated by hashing is not typical of the steady state, so the
reduced-hashing numbers are the more realistic indication of the benefit.

The Rust implementation also bounds the hashing in a separate pool (with the
queue set to `wait` in these runs), so that hashing does not starve the other
requests; the Python implementation hashes in the request worker. This is one
more reason the default mix mixes two effects: the cost of the hash itself and
how each implementation schedules it.

## Method

- Cluster: single-node k3s (32 cores) deployed with skaffold, see
  [Local development](development.md). Both implementations use the same
  Postgres (CloudNativePG).
- Rust: StatefulSet with one pod, `--release` build, jemalloc via `LD_PRELOAD`,
  telemetry off, `[database] max_pool_size` as in the skaffold setup, audit
  chain capped, password hashing pool queue full behaviour set to `wait` (queue
  instead of answering 503), CPU `requests = limits = 24`.
- Python: Deployment with one pod, uwsgi with 24 single-threaded processes, one
  memcached shared by all workers, CPU `requests = limits = 24`.
- Python threads (`--enable-threads`) were tried earlier and are not
  recommended: a 4-process x 4-thread variant used less memory per pod but
  returned thousands of HTTP 502 responses returned by the wsgi server.
- Load: `tests/loadtest` (Goose 0.19) with `LOADTEST_PROFILE=vu`. Every VU is an
  end user of a tenant of its own, with its own project, role assignments and
  token, so the caches of the server see realistic variety. Operations are
  picked per request according to the mix below.
- Sweep: the VU count is raised step by step (600, 900, 1200, 1500, 1800, 2100
  for Rust; much lower for Python), 2 minutes per step plus warm-up. The sweep
  stops when p95 exceeds 800 ms. The VU count at p95 = 500 ms is interpolated
  between the two steps that bracket it.
- Metric: per-pod working set from `kubectl top`, sampled during the run.

### VU operation mix

The mix is configurable through environment variables. Defaults:

| Variable                     | Default | Operation                                |
| ---------------------------- | ------: | ---------------------------------------- |
| `LOADTEST_VU_VALIDATE_PCT`   |      75 | Validate a token (`GET /v3/auth/tokens`) |
| `LOADTEST_VU_ADMIN_READ_PCT` |      13 | Admin read                               |
| `LOADTEST_VU_HASH_PCT`       |       3 | Password login (hashing)                 |
| `LOADTEST_VU_ASSIGN_PCT`     |       2 | Role assignment                          |
| `LOADTEST_VU_CREATE_PCT`     |     0.2 | Create resources                         |
| `LOADTEST_VU_REVOKE_PCT`     |    0.02 | Revoke a token                           |

The remainder is spread over other reads. "No password logins" means
`LOADTEST_VU_HASH_PCT=0`.

## Rust results

### Default mix

p95 = 500 ms is reached at about 673 VUs and about 1,730 req/s. CPU is the
limit: the 24 cores are saturated, and a password login costs far more CPU than
any other operation.

### No password logins

Throughput, p95 and p99 per step. There were no failed requests at any step.

|   VUs | Throughput (req/s) | p95 (ms) | p99 (ms) |
| ----: | -----------------: | -------: | -------: |
|   600 |              2,877 |      221 |      331 |
|   900 |              2,816 |      327 |      696 |
| 1,200 |              2,733 |      446 |    1,040 |
| 1,500 |              2,679 |      557 |    1,458 |
| 1,800 |              2,624 |      663 |    1,867 |
| 2,100 |              2,552 |      835 |    2,260 |

p95 = 500 ms at about 1,340 VUs, which is 55.8 VUs per core.

Throughput slowly decreases as VUs grow while the latency rises linearly. That
is the shape of a CPU-bound server with a closed-loop client: extra VUs only
queue.

### Where the CPU goes

A request costs about 3.6 ms of CPU without hashing. From a CPU profile under
load:

- Around 12.6% of CPU is in the kernel, mostly socket I/O to Postgres.
- A validate issues about 14 database queries in about 10 sequential steps
  (about 20 ms of wall time at low load, of which the database spends only 0.014
  to 0.064 ms per query). The queries are round trips, not work.
- For comparison, Python Keystone validating the same token with a cold cache
  (memcached flushed, caller and subject being the same token) issues 36 to 39
  data `SELECT` statements (36 with the catalog, 39 with `nocatalog`, measured
  once each). They run in about 20 transactions, each with a connection
  pre-ping, so Postgres sees about 99 statements (`BEGIN`, `ROLLBACK`,
  `SELECT 1` and the data queries) and the validation takes 70 to 290 ms. Per
  resource it loads the project, its options and tags, the role, its options and
  the implied roles four times each, the assignments three times, the user and
  its options twice, then groups, federation data, endpoint filters and the
  revocation events. With a warm cache the same validation issues no queries at
  all (29 ms); everything comes from memcached. Rust Keystone deliberately has
  no cross-request cache to guarantee immediate access revocation, so it pays
  its 14 queries on every request, while Python pays 36 to 39 only on a miss.
  This is why the cache hit rate (64% in the earlier shared-memcached runs,
  where the load creates new keys faster than any cache size keeps them) decides
  how much database work Python does per request.
- The revocation check is one `SELECT EXISTS` over a `UNION ALL` of one branch
  per token dimension (audit id, user, project, domain, role, trust).

Removing latency alone does not raise the ceiling of a CPU-bound server. Fewer
queries per request reduce client and kernel CPU and would, by a few percent.

## Python results

Python reached p95 = 500 ms at about 188 VUs (default mix) and about 187 VUs (no
logins), at about 7.8 VUs per core and about 515 req/s. About 2% of the requests
failed with HTTP 500 or 502 under load.

A shared cache is the only valid Python topology, see
[Python cache topology](#python-cache-topology).

## Memory

| State                     | Rust (1 pod)  | Python (1 pod, 24 processes) |
| ------------------------- | ------------- | ---------------------------- |
| Idle                      | ~155 MiB      | ~2.7 GiB                     |
| 600 VUs (average / max)   | 194 / 223 MiB | -                            |
| 2,100 VUs (average / max) | 297 / 428 MiB | -                            |

Rust memory grows with the number of connections and in-flight requests, not
with the number of workers. Python memory is dominated by the per-process copy
of the application and does not depend on the cache: earlier 15-minute runs with
three pods and 10 processes each measured 1.2 GiB per pod with the cache off,
with a small cache and with a large one.

To deploy `keystone-rs` with a small footprint: set a CPU limit (tokio sizes its
pool from the cgroup quota), keep telemetry sampled or off, and use jemalloc
(tested through `LD_PRELOAD` of the Debian `libjemalloc2`; shipping it would
mean using `tikv-jemallocator` as the global allocator).

## Python cache topology

Python Keystone must use **one cache shared by all pods**. Token validation
relies on the revocation events being visible to every API instance. A memcached
instance per pod gives every pod a private cache: a token revoked through one
pod stays valid in the caches of the others until it expires. That breaks token
revocation, is an anti-pattern, and must not be used in a real deployment. All
Python figures on this page use the shared memcached.

## Limitations

- Single run per load step, on one development machine. The load generator runs
  on the same host as both servers and Postgres.
- The load is closed-loop, so request counts depend on latency. The VU count at
  a fixed p95 is the comparison metric, not the raw request count.
- The two sides do not serve identical APIs: the load is restricted to `/v3`
  operations that both implement.
- The Python failures (about 2% HTTP 500 and 502) and its flat ~500 req/s
  ceiling were not investigated.
- Python has no no-login throughput figure in this page, only the VU count.
- Rust runs with telemetry off; Python with no telemetry either.

## Reproducing

```bash
cd tests/loadtest
# needs the admin credentials in OS_* variables or OS_CLOUD
LOADTEST_PROFILE=vu \
LOADTEST_VU_HASH_PCT=0 \
cargo run --release -- --host <url> --users 1200 --run-time 2m \
  --report-file reports/<name>.md
```

Raise `--users` step by step, keep each step in its own report, and read the p95
from the report. Sample memory during the run with
`tests/loadtest/sample_metrics.sh`. Redirect the output to a file and do not
pipe the run through `tail`.
