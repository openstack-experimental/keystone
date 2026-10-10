# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-token-driver-jws-v0.1.0) - 2026-10-10

### Added

- *(oslo.config)* Generalize oslo-config crate ([#1429](https://github.com/openstack-experimental/keystone/pull/1429))
- Auto-register backend drivers via inventory ([#1105](https://github.com/openstack-experimental/keystone/pull/1105))
- *(adr0026)* Add Phase 5 offline token verification ([#1016](https://github.com/openstack-experimental/keystone/pull/1016))
- *(adr0026)* Add client_credentials token endpoint ([#1014](https://github.com/openstack-experimental/keystone/pull/1014))
- *(adr0026)* Phase 1 crypto engine & JWKS endpoint ([#1011](https://github.com/openstack-experimental/keystone/pull/1011))
- *(adr0026)* Phase 0 token abstraction and JWS driver ([#1010](https://github.com/openstack-experimental/keystone/pull/1010))

### Fixed

- *(deps)* Bump p256 to 0.14, unpin rand_core ([#1247](https://github.com/openstack-experimental/keystone/pull/1247))

### Other

- Fix clippy lints across workspace ([#1361](https://github.com/openstack-experimental/keystone/pull/1361))
- *(api)* Harden v3 authorization and authentication coverage ([#1166](https://github.com/openstack-experimental/keystone/pull/1166))
