# Performance Comparison

The repository contains a Goose-based load-test crate that exercises selected
API paths while recording latency and throughput. Pull-request benchmark
workflows use it to detect regressions; results depend on the selected scenario,
database, machine, concurrency, and build profile.

Treat benchmark artifacts from the current CI run as authoritative. Do not
compare an isolated historical number with a different deployment or workload.
The benchmark workflows under `.github/workflows/benchmark*.yml` record the
commands and environment used for each result.
