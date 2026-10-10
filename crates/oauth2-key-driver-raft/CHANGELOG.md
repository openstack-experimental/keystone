# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-oauth2-key-driver-raft-v0.1.0) - 2026-10-10

### Added

- Enable OpenTelemetry metrics and traces support ([#1456](https://github.com/openstack-experimental/keystone/pull/1456))
- *(oauth2)* Rotate signing keys automatically ([#1440](https://github.com/openstack-experimental/keystone/pull/1440))
- *(oauth2)* Add RFC 7009 token revocation endpoint ([#1369](https://github.com/openstack-experimental/keystone/pull/1369))
- Auto-register backend drivers via inventory ([#1105](https://github.com/openstack-experimental/keystone/pull/1105))
- *(adr0028)* Add local-quorum-bypass emergency rotation ([#1032](https://github.com/openstack-experimental/keystone/pull/1032))
- *(adr0026)* Add previous-key and JTI-revocation janitor ([#1021](https://github.com/openstack-experimental/keystone/pull/1021))
- *(adr0026)* Phase 6a ([#1017](https://github.com/openstack-experimental/keystone/pull/1017))
- *(adr0026)* Phase 1 crypto engine & JWKS endpoint ([#1011](https://github.com/openstack-experimental/keystone/pull/1011))

### Fixed

- *(tests)* Fix some test failures ([#1430](https://github.com/openstack-experimental/keystone/pull/1430))

### Other

- *(audit)* Rename audit crate to cadf ([#1399](https://github.com/openstack-experimental/keystone/pull/1399))
- *(deps)* Bump sea-orm and sea-orm-migration to 2.0 ([#1089](https://github.com/openstack-experimental/keystone/pull/1089))
