# Keystone storage API

Lightweight, object-safe trait and types for interacting with the Keystone
distributed storage backend.

## Purpose

The `core` crate must remain decoupled from heavy storage dependencies
(`openraft`, `tonic`, `fjall`). This crate provides the thin [`StorageApi`]
trait and its types, so `core::Service` can hold `Option<Arc<dyn StorageApi>>`
without pulling in the storage implementation.

## Design

The trait uses concrete `Vec<u8>` types instead of generics to stay object-safe.
Callers serialize at the boundary using `StoreDataEnvelope::try_serialize` and
deserialize with `StoreDataEnvelope::try_deserialize`.

## Key types

- **[`StorageApi`]** — the trait interface (read, write, transaction,
  cluster init)
- **[`StoreDataEnvelope`]** — data envelope with metadata, bridges typed
  payload to raw bytes
- **[`StoreError`]** — lightweight error (impl-specific errors map to `Other`)
- **[`StoreResponse`]** — write operation response with violations
- **[`Mutation`]** — batch transaction operations
- **[`Metadata`]** — revision and timestamp tracking
- **[`Node`]** — Raft cluster node descriptor
