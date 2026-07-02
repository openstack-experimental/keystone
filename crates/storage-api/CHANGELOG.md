# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-storage-api-v0.1.0) - 2026-07-02

### Added

- *(storage)* Cert validity and SVID TTL enforcement ([#886](https://github.com/openstack-experimental/keystone/pull/886))
- *(storage)* SPIFFE checks, RBAC, rate limiting, auto-join ([#861](https://github.com/openstack-experimental/keystone/pull/861))
- *(storage)* Complete ADR-0016-v2 ([#844](https://github.com/openstack-experimental/keystone/pull/844))
- *(storage)* implement ADR 0016-v2 Phases 1-4 — encrypted storage with quarantine ([#840](https://github.com/openstack-experimental/keystone/pull/840))

### Fixed

- *(webauthn)* Rotate raft ceremony-state keyspaces ([#890](https://github.com/openstack-experimental/keystone/pull/890))

### Other

- *(storage)* Decouple core from storage ([#832](https://github.com/openstack-experimental/keystone/pull/832))
