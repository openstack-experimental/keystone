# 39. Config engine and section registry

**Date:** 2026-10-05

## Status

Proposed.

## Reference

Tracking issue #1416. Builds on ADR 0018 (linker-anchored backend
registration), ADR 0025, ADR 0033 and ADR 0034.

## Context

`openstack-keystone-config` mixes a generic engine (INI + site-vars + `OS_*`
overlay, Vault resolution, `ConfigManager` watch/reload) with the Keystone
schema (~45 sections in one `Config`). Seventeen crates depend on it, including
`core-types`. Driver config types (OpenFGA, distributed storage) live centrally
and drivers import them back, so every driver option is a change to the central
crate, and moving storage types out creates a `config` -> `storage` -> `config`
cycle. `BackendRegistration` takes `&Config`, so drivers reach into the
monolith.

## Decision

Option A of #1416: a generic engine crate plus a link-time section registry.
Rejected: a runtime-typed global bag (loses typed core access), an extension
`flatten` bag (no hooks, untyped), and the status quo (does not scale).

### Crates

The engine crate is named `oslo-config`, after the Python library whose model
(modules register their own option groups, one file, live reload) it
implements.

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
single-owner sections move to their crate.

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
    fn validate(&self, _view: &ConfigView) -> Result<(), ConfigError> { Ok(()) }
}
```

`validate` runs in a second pass after all sections are materialized.

### Registration

`BackendRegistration<B>` stays non-generic over the section type
(`inventory::collect!` is per concrete type, so `BackendRegistration<B, S>`
cannot share one registry). It carries an erased `SectionDescriptor`; a
`register_backend!` macro generates a non-capturing trampoline that fetches
`&S` from the view and calls the driver's `build: |s: &S| ...`. A missing
section for a selected driver is materialized from the section's default,
exactly as today; a section type that has no default and is absent is a startup
error attributed to the driver.

```rust
pub struct BackendRegistration<B: ?Sized + 'static> {
    pub name: &'static str,
    pub section: Option<SectionDescriptor>,
    pub selected: fn(&ConfigView) -> bool,
    pub build: fn(&ConfigView) -> BuildFuture<B>,
}
```

### Loading

Raw pipeline (file, site-vars, env; prefix parameterized) -> Vault resolution
-> core parse -> registered sections of selected drivers -> validation pass.
Env override, site-vars and Vault therefore apply to driver sections unchanged.
`ConfigManager<C>` keeps the core struct and the section bag in one snapshot, so
reload swaps both atomically (last-known-good, deadlock avoidance and Vault
teardown behaviour are unchanged). Registered sections are re-parsed and
re-validated on every reload and watched files of driver sections are part of
the watch set, so a driver section reloads like any core section.

### Per-domain blocks

`NamedAssignmentBackendRegistration` carries the driver's `SectionDescriptor`.
`AssignmentBackendConfig` becomes `Named { driver, config: ParsedSection }`,
parsed at load time with the driver's own section type and downcast at
dispatch. The same type serves `[openfga]` and `[assignment.backends.<name>]`.

### Fail-loud rules

- Driver selected => its section is materialized: from the INI when present,
  from `Default` when absent (as today); a required section without `Default`
  that is absent is an error attributed to the driver.
- Present section whose driver is not selected, or unclaimed name => warn/error.
- Duplicate `NAME` across descriptors, and reserved names (`DEFAULT`,
  `database`, `auth`, ...) => startup error.
- Startup assertion that expected section names are registered (catches
  `anchor()` regressions).

## Non-goals

Section *registration* is link-time only (no loading of section types after
link). This is not a limit on reloading: live reload of the whole
configuration, driver sections included, works exactly as it does today (see
Loading). No change to INI/env/site-vars semantics; no change to per-domain
assignment semantics or wire format.

## Consequences

- A new driver is one crate with no central-config diff.
- `core-types` stops depending on the Keystone schema (it depends on
  `oslo-config` and shared leaf section types only).
- Plugin interface changes from `&Config` to `&ConfigView` across ~31 files
  (mechanical).
- Any linked crate can register a section name; same trust level as backend
  registration, mitigated by the rules above.

## Work packages

See #1416: WP-1 engine extraction (reload tests first), WP-2 section trait and
hooks, WP-3 registry + OpenFGA pilot, WP-4 remaining driver sections and
per-domain blocks, WP-5 storage section, WP-6 optional multi-service support.
