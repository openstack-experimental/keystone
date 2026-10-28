# Rust vs Python Keystone comparison

This page compares the Rust Keystone (`keystone-rs`) with the Python Keystone
(`keystone-py`) under the same synthetic load on the same machine, and records
what it takes to get the Rust memory footprint down.

The numbers are a snapshot from one development machine, from single 15-minute
runs. Treat them as relative, not absolute.

## Summary

Same load, same Postgres, three pods each, 50 users, 15 minutes, freshly started
pods. Rust is the release build with jemalloc, telemetry off and a CPU limit of
10 per pod. Python is uwsgi with 10 single-threaded processes and no CPU limit
per pod.

|                                            |              Rust |                         Python | Rust advantage |
| ------------------------------------------ | ----------------: | -----------------------------: | -------------: |
| Memory, 3 pods, end of run                 |       **581 MiB** |                 **~3,653 MiB** |      6.3x less |
| Memory per pod                             |    174 to 207 MiB |                     ~1,218 MiB |        6x less |
| Requests served                            |           578,521 |                        155,730 |      3.7x more |
| Throughput (offered-load bound, see below) |         639 req/s |                      171 req/s |    3.7x higher |
| Memory per unit of throughput              | 0.9 MiB per req/s |             21.4 MiB per req/s |     23x better |
| Latency p50                                |             30 ms |                         150 ms |       5x lower |
| Latency p95                                |            280 ms |                         700 ms |     2.5x lower |
| Latency p99                                |            300 ms |                       1,000 ms |     3.3x lower |
| Failed requests                            |       15 (0.003%) |                   1,101 (0.7%) |    ~270x fewer |
| Memory trend, second half                  |   flat to falling | +85 to +97 MiB/h, still rising |                |

What this shows:

- **Memory.** Rust holds the same workload in about a sixth of the memory.
  Python pays for every worker process with a full copy of the application:
  going from 4 to 10 processes per pod raised throughput by about 16% (134k to
  156k requests) and memory by about 2.5x (1,478 to ~3,653 MiB). Rust is one
  process per pod and shares everything between its async tasks.
- **Latency.** Rust answers the median request in 30 ms and the tail within 300
  ms. The Python median is 5x higher and its p99 reaches one second. The gap is
  widest on authentication (p50 31 ms against 280 ms), which is the CPU-heavy
  path (password hashing and token handling).
- **Reliability under load.** Python returned 465 HTTP 500 and 672 HTTP 502
  responses, spread across the auth, revoke and group endpoints. Rust had 15
  failures, all transport timeouts on one read endpoint. The failures are
  counted by the loadtest itself; the expected 401/404 negative-test responses
  are excluded.
- **Steady state.** Rust memory is stable or falling once the working set is
  warm. Python was still growing at the end of the run, at roughly 90 MiB/h per
  pod. Whether it would plateau was not measured.

The load is closed-loop (50 users with think-time), so a slower server also
receives fewer requests per second. The request and throughput rows therefore
reflect latency under a fixed offered load, **not capacity**. Rust is not
saturated by this load: its throughput stayed at about 637 to 639 req/s whether
it had a CPU limit of 4, 10 or none, and with the audit log on or off. They are
not a maximum-throughput comparison; see [Saturation test](#saturation-test) for
that. The memory, latency and failure figures at this load do not depend on it.

## Method

- Cluster: single-node k3s (32 cores) deployed with skaffold, see
  [Local development](development.md). Both implementations use the same
  Postgres.
- Load: `tests/loadtest` (Goose), `/v3` scenarios only, because the Python
  implementation has no `/v4` API. The mix covers password and token auth,
  validation, role assignment, and group, catalog, credential and trust churn,
  with 250 ms think-time on reads.
- Driver: `tools/compare-memory.sh` runs the load against one or both targets
  and samples per-pod memory. `tools/summarize-memory.py` turns the samples into
  first/max/last values and a slope (MiB/h over the second half of the run).
- Metric: container working set from `kubectl top`, plus RSS split into anon and
  file from `/proc/<pid>/status`.
- Each run: 15 minutes, 50 users, **freshly restarted pods**. An earlier
  measurement of about 700 MiB per `keystone-rs` pod was taken after the soak
  test and is not comparable.

Deployments under test:

| Implementation | Setup                                                                                                                                                                                    |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `keystone-rs`  | StatefulSet, 3 pods, `--release` build, jemalloc via `LD_PRELOAD` (`background_thread:true,dirty_decay_ms:1000,muzzy_decay_ms:0`), `OS_OTEL__ENABLED=false`, CPU request 1 and limit 10. |
| `keystone-py`  | Deployment, 3 pods, uwsgi with 10 single-threaded worker processes each, caching in an external memcached, no CPU limit.                                                                 |

Python threads (`--enable-threads`) were tried and are not recommended: a
4-process x 4-thread variant used about 530 MiB per pod and returned 9,569 HTTP
502 responses. The cause was not investigated deeper.

## Rust memory: what moves the number

Working set per pod at the end of the run, in MiB. All Rust rows are three pods,
fresh start, 15 minutes, 50 users.

| Run                                                                   | Pod 0 / 1 / 2   |   Total | Requests | Failed |
| --------------------------------------------------------------------- | --------------- | ------: | -------: | -----: |
| Untuned (telemetry on, no CPU limit)                                  | 499 / 519 / 578 |   1,596 |     704k |     23 |
| CPU limit 4 + 4 tokio workers + telemetry off                         | 227 / 254 / 267 |     748 |     346k |      7 |
| CPU limit 4, telemetry off                                            | 234 / 253 / 274 |     761 |     341k |      3 |
| CPU limit 4, telemetry off, `MALLOC_ARENA_MAX=2`                      | 205 / 222 / 235 |     662 |     296k |      1 |
| CPU limit 4, telemetry off, jemalloc                                  | 180 / 222 / 202 |     604 |     361k |      6 |
| CPU limit 4, telemetry off, jemalloc, tuned decay                     | 160 / 199 / 214 |     573 |     338k |      3 |
| **Release build, CPU limit 10, telemetry off, jemalloc, tuned decay** | 174 / 207 / 200 | **581** | **579k** | **15** |
| Release build, **no CPU limit**, audit off, telemetry off, jemalloc   | 210 / 242 / 232 |     684 |     577k |     18 |
| Python, 4 processes per pod                                           | 492 to 494      |   1,478 |     134k |    495 |
| Python, 10 processes per pod                                          | 1,217 to 1,218  |  ~3,653 |     156k |  1,101 |

Findings:

- **Audit log and CPU limit do not change throughput at this load.** Removing
  the CPU limit and disabling the audit framework (`[audit] enabled = false`)
  gave 637 req/s against 639 req/s, with identical latency (p50 30 ms, p95 280
  ms, p99 300 ms). The cost of no limit is memory: 684 MiB against 581 MiB
  (about 18% more), from more tokio workers and allocator arenas. The reason
  throughput does not move is that the load is not heavy enough to saturate
  Rust, see [Saturation test](#saturation-test).
- **Raising the CPU limit costs no memory.** Moving from a limit of 4 to a limit
  of 10 gave about 1.7x the requests (338k to 579k) at the same memory (573 to
  581 MiB). Rust memory does not scale with the number of workers the way the
  Python deployment does.
- **A CPU limit is the most effective single setting.** Without one, the
  container sees all 32 host cores, tokio starts a worker per core (79 threads
  per pod) and glibc creates up to 8 allocation arenas per core, so freed memory
  stays scattered. With a limit, tokio reads the cgroup quota and sizes its pool
  from it. A `TOKIO_WORKER_THREADS` override is not needed. The measured saving
  is about 50% (1,596 to 761 MiB), together with telemetry off.
- **Telemetry.** At the default sampling rate of 1.0 and span level debug,
  OpenTelemetry adds allocation churn. Disabling it alone saved about 25% on an
  otherwise untuned run. Sample or disable it when measuring memory.
- **Allocator.** glibc does not read the cgroup quota, so it still benefits from
  tuning. `MALLOC_ARENA_MAX=2` saved about 13%. jemalloc saved about 20 to 25%
  against glibc with the same CPU limit. It has a similar peak but returns
  memory to the OS afterwards, so its end-of-run figure and its slope are lower.
  The negative slopes in the jemalloc runs are that release, not a leak signal.
- **Release build.** The last Rust run is the only one built with `--release`
  (thin LTO). The earlier runs used the `skaffold` profile, which disables LTO.
  The release build did not change memory measurably; the throughput gain over
  the CPU-limit-4 run comes from the higher limit.

## Conclusions

- On this workload Rust needs about a sixth of the memory of Python for three
  pods (581 against ~3,653 MiB), serves the same users with a fifth of the
  median latency, and have no direct failures (all seen failures are the client
  failures).
- The Python memory bill scales with the number of worker processes and pods.
  Adding processes buys little throughput. Rust scales by raising the CPU limit
  with no memory cost.
- To deploy `keystone-rs` with a small footprint: set a CPU limit, keep
  telemetry sampled or off, and use jemalloc. Shipping jemalloc would mean using
  `tikv-jemallocator` as the global allocator; it was tested here through
  `LD_PRELOAD` of the Debian `libjemalloc2`.

## Limitations

- Single runs, one per variant (15 minutes, 5 minutes for the saturation test).
  Differences of a few tens of MiB, such as jemalloc default against tuned, are
  within noise.
- Python was run with its default setup: no CPU limit, no telemetry, no tuning
  other than the process count. Rust CPU was capped at 10 per pod; Python was
  not capped and had access to all 32 cores.
- The two sides do not serve identical APIs: the loadtest is restricted to `/v3`
  scenarios that both implement.
- The loadtest is closed-loop, so request counts depend on latency, see the
  Summary. The 15 Rust failures are load-generator artefacts, see
  [Rust client timeouts](#rust-client-timeouts).
- Python failures were counted but their cause was not investigated.

## Saturation test

The 50-user runs above do not saturate Rust. Each user waits 250 ms between read
requests, so the offered load is fixed by the user count. Rust answers in about
30 ms, which leaves most of each user's time idle. That is why its throughput
stayed at 637 to 639 req/s whether it had a CPU limit of 4, 10 or none, and
whether the audit log was on or off: the server was never the limit, the load
generator's think-time was. Python, with a 150 ms median at the same load, was
already close to its limit, so its lower throughput does reflect capacity.

To compare capacity, the same `/v3` mix was run flat out: 150 users, no
think-time, 5 minutes per target, same three pods each, through Traefik. Rust
had no CPU limit, audit off, telemetry off and jemalloc; Python was 10 processes
per pod. Both were already warm, so memory is not a fresh-pod value.

|                            |      Rust |     Python | Rust advantage |
| -------------------------- | --------: | ---------: | -------------: |
| Requests served            |   137,638 |     37,640 |      3.7x more |
| Throughput                 | 451 req/s |  123 req/s |    3.7x higher |
| Latency p50                |    310 ms |     800 ms |     2.6x lower |
| Latency p95                |    700 ms |   3,000 ms |     4.3x lower |
| Latency p99                |    900 ms |   8,000 ms |     8.9x lower |
| Failed requests            |         0 | 585 (1.6%) |                |
| Memory, 3 pods, end of run |   767 MiB |  3,585 MiB |      4.7x less |

Python's failures were 524 HTTP 502 and 63 HTTP 500 responses.

What this shows:

- **Rust is saturated here, the earlier runs were not.** At 50 users with
  think-time the median was 30 ms. With 150 users and none it is 310 ms:
  requests now queue, which is what saturation looks like. Throughput (451
  req/s) is lower than in the think-time runs (637 req/s) because the mix is
  different: think-time only applies to reads, so without it the cheap reads no
  longer dilute the password-hashing and write requests, and the average request
  costs more.
- **The gap holds at capacity.** Rust serves 3.7x the requests of Python, the
  same ratio as in the offered-load runs, with a tail 9x shorter and no
  failures. Python's p99 of 8 seconds and its 502s are what overload looks like
  in uwsgi.
- **Rust memory stays small under overload.** Per pod it peaked at 365 to 392
  MiB and ended at 239 to 266 MiB, against about 1,200 MiB for each Python pod.
- **What limits Rust here was not isolated.** It may be CPU, Postgres (shared by
  both targets), Traefik, or the load generator on the same host. Treat 451
  req/s as a lower bound for Rust's capacity on this machine, and the ratio to
  Python as the meaningful figure, since both sides share those limits.

## Rust client timeouts

All Rust failures were 60 s client timeouts on
`GET /v3/auth/tokens (validate new)`, the request right after a token is issued.
They are not a Keystone problem. They happen at about 0.03 to 0.1% of
`tokenlifecycle` iterations and were reproduced with the `tokenlifecycle`
scenario alone:

| Users | Iterations | Timeouts |
| ----: | ---------: | -------: |
|     5 |     19,087 |        1 |
|    20 |     41,420 |       19 |
|    50 |   ~128,000 |      129 |

Evidence that the request is never sent:

- Bypassing Traefik (ClusterIP) gives the same failures.
- With a "request started" log added to the access log, every request that
  reached a pod also finished (169,777 started, 169,777 finished, slowest 339
  ms). The pods saw exactly as many `GET` requests as the client sent minus the
  timeouts.
- A packet capture on `cni0` during a 20-user run (389k packets, none dropped)
  shows, for every matched timeout, a healthy connection that completes the
  `POST` for the new token, goes silent for exactly 60 s, then sends the
  `DELETE`. No packet carrying the `validate new` token exists before that
  `DELETE`.
- Disabling idle connection reuse in the client did not remove the failures; it
  only added port-exhaustion connect errors.
- A plain Python keep-alive loop running the same sequence against each pod
  showed no hangs in about 190k iterations.

So the Goose 0.18.1 / reqwest client occasionally stalls before writing the
request, and its 60 s total timeout then fires. Treat these as load-generator
errors when reading the failure counts above.

## Reproducing

```bash
# needs the admin password in OS_PASSWORD
tools/compare-memory.sh --targets rs --run-time 15m --users 50 --out tests/loadtest/reports/<name>
tools/compare-memory.sh --targets py --run-time 15m --users 50 --out tests/loadtest/reports/<name>
python3 tools/summarize-memory.py tests/loadtest/reports/<name>/memory.csv
```

Result directories hold `load-<target>.json|log|md`, `memory.csv` and
`summary.md`. `summarize-memory.py` sums the last working set of every pod in
the CSV, including pods that were terminating during a rollout, so compute the
total by hand after redeploying.
