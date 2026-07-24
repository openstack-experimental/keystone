# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-credential-driver-sql-v0.1.0) - 2026-07-24

### Added

- Generalize marker pagination for v3/v4 lists ([#1086](https://github.com/openstack-experimental/keystone/pull/1086))
- *(adr0026)* Phase 1 crypto engine & JWKS endpoint ([#1011](https://github.com/openstack-experimental/keystone/pull/1011))
- *(adr0026)* Phase 0 token abstraction and JWS driver ([#1010](https://github.com/openstack-experimental/keystone/pull/1010))
- *(fernet)* Unify credential/token key repositories ([#915](https://github.com/openstack-experimental/keystone/pull/915))
- *(credential)* Enforce Null Key check at startup ([#913](https://github.com/openstack-experimental/keystone/pull/913))
- *(credential)* Implement Phase 3 of ADR 0019 ([#909](https://github.com/openstack-experimental/keystone/pull/909))
- *(credential)* Implement ADR 0019 phases 1-2 ([#897](https://github.com/openstack-experimental/keystone/pull/897))

### Fixed

- Widen Fernet key index from i8 to u32 ([#1080](https://github.com/openstack-experimental/keystone/pull/1080))

### Other

- *(deps)* Bump sea-orm and sea-orm-migration to 2.0 ([#1089](https://github.com/openstack-experimental/keystone/pull/1089))
