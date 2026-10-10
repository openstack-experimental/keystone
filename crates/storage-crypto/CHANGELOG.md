# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-storage-crypto-v0.1.0) - 2026-10-10

### Added

- *(storage)* Gate readiness on Raft health ([#1450](https://github.com/openstack-experimental/keystone/pull/1450))
- *(storage)* Rotate the DEK automatically ([#1441](https://github.com/openstack-experimental/keystone/pull/1441))
- *(scim)* ADR 0024 - Phase 3 ([#928](https://github.com/openstack-experimental/keystone/pull/928))
- *(storage)* Add PKCS#11 KEK provider crate ([#917](https://github.com/openstack-experimental/keystone/pull/917))
- *(storage)* Cert validity and SVID TTL enforcement ([#886](https://github.com/openstack-experimental/keystone/pull/886))
- *(audit)* Implement CADF audit framework Phase 2 ([#872](https://github.com/openstack-experimental/keystone/pull/872))
- *(storage)* SPIFFE checks, RBAC, rate limiting, auto-join ([#861](https://github.com/openstack-experimental/keystone/pull/861))
- *(storage)* Harden preflight and erase dev KEK ([#860](https://github.com/openstack-experimental/keystone/pull/860))
- *(storage)* Complete ADR-0016-v2 ([#844](https://github.com/openstack-experimental/keystone/pull/844))
- *(storage)* implement ADR 0016-v2 Phases 1-4 — encrypted storage with quarantine ([#840](https://github.com/openstack-experimental/keystone/pull/840))

### Fixed

- *(storage)* Route admin RPCs to the Raft leader ([#1447](https://github.com/openstack-experimental/keystone/pull/1447))
- *(raft)* Data durability and correctness ([#1342](https://github.com/openstack-experimental/keystone/pull/1342))

### Other

- *(storage)* Split large modules and tests ([#1466](https://github.com/openstack-experimental/keystone/pull/1466))
- Fix clippy lints across workspace ([#1361](https://github.com/openstack-experimental/keystone/pull/1361))
- Bump deps and whitelist rustsec advisory ([#1140](https://github.com/openstack-experimental/keystone/pull/1140))
- *(deps)* Batch update dependencies ([#875](https://github.com/openstack-experimental/keystone/pull/875))
