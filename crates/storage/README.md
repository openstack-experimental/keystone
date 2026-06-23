# Distributed storage for Keystone

Distributed storage backend for the OpenStack Keystone, backed by the Raft
consensus protocol ([openraft](https://crates.io/crates/openraft)) and the
Fjall KV database.

## Overview

Central RDBMS is preventing OpenStack Keystone from being deployed as a
flexible and distributed system. Major IAM systems are built with Raft-based
storage to make them fully distributed and highly available. This crate
provides such storage with guaranteed consistency between multiple instances,
while relying on a KV database that is modified under Raft control and
readable by every instance at very high speed.

## Architecture

The crate is split into two layers:

- **[`openstack-keystone-storage-api`](../storage-api/)** — thin, object-safe
  `StorageApi` trait and lightweight types. This is the only dependency
  `core` has on the storage layer.

- **This crate (`openstack-keystone-distributed-storage`)** — full
  implementation: Raft node, Fjall state machine, tonic-based gRPC
  transport, TLS config watcher, and mock storage for tests.

## Key components

- **`Storage`** — the Raft node wrapper, implements `StorageApi`. Handles
  leader forwarding, log replication, and state machine application.
- **`FjallStateMachine`** — Raft state machine backed by Fjall KV. Applies
  committed mutations (set, remove, create-if-absent, index ops).
- **`FjallLogStore`** — Raft log store backed by Fjall.
- **`MockStorage`** — in-memory storage for testing (enabled via `mock`
  feature flag).

## Usage

```rust
// Initialize storage from config
let storage = Storage::new(
    config.storage.as_ref().unwrap().clone(),
    std::env::temp_dir(),
).await?;

// Coerce to trait object for core
let api: Arc<dyn StorageApi> = storage.into_trait()?;
```

## Features

- **`mock`** — enables `MockStorage` for unit tests
- **`bench_internals`** — enables internal types for benchmarks
