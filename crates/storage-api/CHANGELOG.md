# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-storage-api-v0.1.0) - 2026-10-10

### Added

- Enable OpenTelemetry metrics and traces support ([#1456](https://github.com/openstack-experimental/keystone/pull/1456))
- *(storage)* Gate readiness on Raft health ([#1450](https://github.com/openstack-experimental/keystone/pull/1450))
- *(storage)* Add ephemeral state machine records ([#1198](https://github.com/openstack-experimental/keystone/pull/1198))
- *(adr0026)* Phase 1 crypto engine & JWKS endpoint ([#1011](https://github.com/openstack-experimental/keystone/pull/1011))
- *(storage)* Cert validity and SVID TTL enforcement ([#886](https://github.com/openstack-experimental/keystone/pull/886))
- *(storage)* SPIFFE checks, RBAC, rate limiting, auto-join ([#861](https://github.com/openstack-experimental/keystone/pull/861))
- *(storage)* Complete ADR-0016-v2 ([#844](https://github.com/openstack-experimental/keystone/pull/844))
- *(storage)* implement ADR 0016-v2 Phases 1-4 — encrypted storage with quarantine ([#840](https://github.com/openstack-experimental/keystone/pull/840))

### Fixed

- *(raft)* Fail closed on stale ReadIndex reads ([#1341](https://github.com/openstack-experimental/keystone/pull/1341))
- *(webauthn)* Rotate raft ceremony-state keyspaces ([#890](https://github.com/openstack-experimental/keystone/pull/890))

### Other

- *(storage)* Split large modules and tests ([#1466](https://github.com/openstack-experimental/keystone/pull/1466))
- Extend workspace unsafe/unwrap/expect lints ([#1120](https://github.com/openstack-experimental/keystone/pull/1120))
- *(storage)* Decouple core from storage ([#832](https://github.com/openstack-experimental/keystone/pull/832))
