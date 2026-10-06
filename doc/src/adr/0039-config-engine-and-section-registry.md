# 39. Config engine and section registry

**Date:** 2026-10-05

## Status

Accepted.

## Reference

Tracking issue #1416. Builds on ADR 0018 (linker-anchored backend registration),
ADR 0025, ADR 0033 and ADR 0034.

## Context

`openstack-keystone-config` mixes a generic engine (INI + site-vars + `OS_*`
overlay, Vault resolution, `ConfigManager` watch/reload) with the Keystone
schema (~45 sections in one `Config`). Seventeen crates depend on it, including
`core-types`. Driver config types (OpenFGA, distributed storage) live centrally
and drivers import them back, so every driver option is a change to the central
crate. Moving the storage types into the storage crate would create a `config`
-> `storage` -> `config` cycle while `Config` still has a `distributed_storage`
field. `BackendRegistration` takes `&Config`, so drivers reach into the
monolith.

## Decision

Option A of #1416: a generic engine crate plus a link-time section registry.
Rejected: a runtime-typed global bag (loses typed core access), an extension
`flatten` bag (no hooks, untyped), and the status quo (does not scale).

### Crates

The engine crate is named `oslo-config`, after the Python library whose model
(modules register their own option groups, one file, live reload) it implements.

```text
oslo-config                      engine, no feature dependencies
  ^
openstack-keystone-config        Keystone schema: core sections, ConfigView alias
  ^
core, keystone
  ^
*-driver-*                       own section type + register_backend!
```

A section stays in the schema crate (or a shared leaf) when the core or more
than one crate reads it (e.g. `database`, `identity`, `token`, and
`LdapProvider`, which `core-types` uses for API-stored domain config). Only
single-owner sections move to their crate. A section whose owner is a library
crate rather than a driver (`distributed_storage`, owned by
`openstack-keystone-distributed-storage`) is registered the same way. It is not
a section type that every consumer needs from a shared leaf: the schema crate
drops the field, so the cycle above disappears, and the startup code, the raft
listener and `keystone-manage` read it with
`view.section::<DistributedStorageConfiguration>()`.

### ConfigSection

The INI section name is bound to the type, so a lookup can never be a type
mismatch. Absence follows today's serde behaviour: a section type that
implements `Default` is optional and is materialized from `S::default()` when
its INI section is missing (the `#[serde(default)]` case); a section type
without `Default` is required, like `auth` today. The type therefore decides,
and the driver never handles `Option`:

```rust
pub trait ConfigSection: DeserializeOwned + Send + Sync + 'static {
    const NAME: &'static str;
    fn finish(&mut self, _ctx: &LoadCtx) -> Result<(), ConfigError> { Ok(()) }
    fn watch_files(&self) -> Vec<PathBuf> { vec![] }
    fn validate_with(&self, _sections: &SectionBag) -> Result<(), ConfigError> { Ok(()) }
}
```

`validate_with` runs in a second pass after all registered sections are
materialized and sees its siblings through the `SectionBag`. (It is not named
`validate` to avoid clashing with `validator::Validate` on types that derive
both.) Cross-checks that need the core schema stay in `CoreSchema::finish_load`.

### Registration

A driver crate registers its section type with `register_section!` (link-time,
`inventory`, same linkage rule as ADR 0018). `BackendRegistration<B>` stays
non-generic and its `selected`/`build` hooks receive a `&ConfigView`, so a
driver reads its own section with `view.section::<S>()` (or
`view.require::<S>()` for an error naming the missing section) next to the core
config. A section type with a `Default` is materialized from it when absent
(`register_section!(S, default)`); one without is absent from the bag. A driver
that needs a required section reads it with `view.require::<S>()` in its
`build`, so selecting the driver without the section fails the startup with an
error naming the section (OpenFGA does this; its `selected` predicate keeps the
section optional for deployments that do not select the global driver).

```rust
pub struct BackendRegistration<B: ?Sized + 'static> {
    pub name: &'static str,
    pub selected: fn(&ConfigView<'_>) -> bool,
    pub build: fn(&ConfigView<'_>) -> BuildFuture<B>,
}
```

### Loading

Raw pipeline (file, site-vars, env; prefix parameterized) -> Vault resolution ->
core parse -> every linked registered section -> validation pass. All linked
sections are parsed, selected or not, so a malformed section of an unselected
driver fails the load, as it did with the central schema. Env override,
site-vars and Vault therefore apply to driver sections unchanged. The `vault`
cargo feature of `oslo-config` (on by default) gates the resolution; without it
a configuration that contains a `vault://` reference fails the load instead of
passing the literal string on. `ConfigManager<C>` keeps the core struct and the
section bag in one snapshot, so reload swaps both atomically (last-known-good,
deadlock avoidance and Vault teardown behaviour are unchanged). Registered
sections are re-parsed and re-validated on every reload and watched files of
driver sections are part of the watch set, so a driver section reloads like any
core section.

Vault token lifecycle: the live runtime is created with the initial load,
replaced on every reload, and revoked on `ConfigManager::shutdown`. A runtime
that is replaced or dropped without a shutdown (one-shot loaders, the
predecessor of a reload) is not revoked and its token lives out its TTL.

### Per-domain blocks

`AssignmentBackendConfig` becomes
`Sql | Named { driver, config: ParsedSection }`. A driver registers the type its
blocks are parsed into with
`register_block!("assignment.backends", "openfga", S)`; the schema deserializes
the `driver` discriminator and delegates the rest to the registered type at load
time. The block is downcast to the driver's own type at dispatch, so the same
type serves `[openfga]` and `[assignment.backends.<name>]`. A block naming a
driver that is not linked fails the load.

### Fail-loud rules

- Driver selected => its section is materialized: from the INI when present,
  from `Default` when absent (as today); a required section without `Default`
  that is absent is a startup error raised by the driver's `build` through
  `view.require`.
- Unclaimed top-level section (neither a core section nor a registered one, for
  example a misspelled `[openfga_typo]`) => warning on every load of the
  watching manager (server startup and each reload). One-shot loaders
  (`load_snapshot_from`, e.g. `keystone-manage`) skip the warning: their
  link-time claim set is smaller than the server's (`keystone-manage` links
  neither the JWS token driver nor the OpenFGA assignment driver), so a valid
  `[jws_tokens]` or `[openfga]` section would be reported as unclaimed; a
  misspelling still surfaces on the server's next load. It is a warning, not an
  error, so a reload of a configuration that carries a section of a driver this
  binary does not link keeps working. A present section whose driver is not
  selected is not reported.
- Duplicate `NAME` across descriptors, and reserved names (`DEFAULT`,
  `database`, `auth`, ...) => startup error.
- Startup assertion that expected section names are registered (catches
  `anchor()` regressions). `keystone/build.rs` anchors only `*-driver-*` crates,
  `webauthn` and `distributed-storage`, so a section registered by any other
  crate (the next one is `audit`, owned by `cadf`) must, in the same change,
  expose `anchor()`, be added to the `build.rs` allow-list and be listed in the
  `assert_registered` call in `server/startup.rs`. `keystone-manage` does not
  use the generated anchors and calls the owner's `anchor()` itself. Otherwise a
  linker-stripped registration silently materializes a default section.
- `CoreSchema::reserved_sections()` mirrors the fields of the core schema; a
  unit test in the schema crate fails when the two drift apart.

## Non-goals

Section _registration_ is link-time only (no loading of section types after
link). This is not a limit on reloading: live reload of the whole configuration,
driver sections included, works exactly as it does today (see Loading). No
change to INI/env/site-vars semantics; no change to per-domain assignment
semantics or wire format.

## Consequences

- A new driver is one crate with no central-config diff.
- `core-types` stops depending on the Keystone schema (it depends on
  `oslo-config` and shared leaf section types only). Not yet true: it still
  imports `Config` and the identity/LDAP/security-compliance types. That part of
  WP-5 remains. `crates/storage` no longer reads `Config` fields: it takes the
  `[distributed_storage]` section (the ConfigManager only supplies the snapshot
  and the reload notification).
- Plugin interface changes from `&Config` to `&ConfigView` across ~31 files
  (mechanical).
- Any linked crate can register a section name; same trust level as backend
  registration, mitigated by the rules above.

A `ConfigManager` built with `not_watched(Config)` has an empty section bag,
unlike `watched()` which materializes the registered sections. Tests of a driver
that requires its section must assemble a `SectionBag` (or use
`load_snapshot_from`); the storage crate offers `config::config_manager` and
`config::config_manager_with` for that.
