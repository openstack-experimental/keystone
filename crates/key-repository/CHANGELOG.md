# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-key-repository-v0.1.0) - 2026-07-24

### Added

- *(adr0026)* Add previous-key and JTI-revocation janitor ([#1021](https://github.com/openstack-experimental/keystone/pull/1021))
- *(adr0026)* Add Phase 5 offline token verification ([#1016](https://github.com/openstack-experimental/keystone/pull/1016))
- *(adr0026)* Add client_credentials token endpoint ([#1014](https://github.com/openstack-experimental/keystone/pull/1014))
- *(adr0026)* Phase 0 token abstraction and JWS driver ([#1010](https://github.com/openstack-experimental/keystone/pull/1010))
- *(scim)* ADR 0024 - Phase 1+2 ([#925](https://github.com/openstack-experimental/keystone/pull/925))
- *(fernet)* Unify credential/token key repositories ([#915](https://github.com/openstack-experimental/keystone/pull/915))

### Fixed

- Widen Fernet key index from i8 to u32 ([#1080](https://github.com/openstack-experimental/keystone/pull/1080))
- Support macOS dev builds and fs watcher shutdown ([#1009](https://github.com/openstack-experimental/keystone/pull/1009))

### Other

- *(deps)* bump pkcs8 from 0.10.2 to 0.11.0 ([#1061](https://github.com/openstack-experimental/keystone/pull/1061))
