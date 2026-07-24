# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-identity-driver-sql-v0.1.0) - 2026-07-24

### Added

- Generalize marker pagination for v3/v4 lists ([#1086](https://github.com/openstack-experimental/keystone/pull/1086))
- *(identity)* Add per-user auth rate limiting ([#996](https://github.com/openstack-experimental/keystone/pull/996))
- *(identity)* Implement user password change endpoint ([#970](https://github.com/openstack-experimental/keystone/pull/970))
- *(security)* Wrap secrets with secrecy crate ([#369](https://github.com/openstack-experimental/keystone/pull/369)) ([#912](https://github.com/openstack-experimental/keystone/pull/912))
- *(scim)* ADR 0024 - Phase 5 ([#951](https://github.com/openstack-experimental/keystone/pull/951))
- *(scim)* ADR 0024 - Phase 3 ([#928](https://github.com/openstack-experimental/keystone/pull/928))
- *(scim)* ADR 0024 - Phase 1+2 ([#925](https://github.com/openstack-experimental/keystone/pull/925))
- *(auth)* Password hashing parity with Python Keystone ([#859](https://github.com/openstack-experimental/keystone/pull/859))
- *(mapping)* ADR-0020 (mapping engine) phase 1 ([#794](https://github.com/openstack-experimental/keystone/pull/794))
- Add inter-provider event notification system ([#784](https://github.com/openstack-experimental/keystone/pull/784))
- Add timing attack protection and failed auth tracking ([#758](https://github.com/openstack-experimental/keystone/pull/758))
- Add role-imply rest api ([#750](https://github.com/openstack-experimental/keystone/pull/750))
- Add user update functionality ([#747](https://github.com/openstack-experimental/keystone/pull/747))
- Make drivers more dynamic ([#737](https://github.com/openstack-experimental/keystone/pull/737))

### Fixed

- *(api)* Default enabled/domain_id on create ([#1073](https://github.com/openstack-experimental/keystone/pull/1073))
- *(federation)* Allow long external unique_id values ([#1033](https://github.com/openstack-experimental/keystone/pull/1033))
- *(identity)* Support federated existence checks ([#1012](https://github.com/openstack-experimental/keystone/pull/1012))
- Validate password complexity before storing password ([#845](https://github.com/openstack-experimental/keystone/pull/845))
- Align "extra" property handling ([#787](https://github.com/openstack-experimental/keystone/pull/787))

### Other

- *(deps)* Bump sea-orm and sea-orm-migration to 2.0 ([#1089](https://github.com/openstack-experimental/keystone/pull/1089))
- Extract password hashing into own crate ([#1055](https://github.com/openstack-experimental/keystone/pull/1055))
- Silence some clippy warnings ([#1030](https://github.com/openstack-experimental/keystone/pull/1030))
- Move jsonwebtoken to keystone crate ([#820](https://github.com/openstack-experimental/keystone/pull/820))
- Consolidate password update flows ([#778](https://github.com/openstack-experimental/keystone/pull/778))
- Further align workspace features ([#772](https://github.com/openstack-experimental/keystone/pull/772))
