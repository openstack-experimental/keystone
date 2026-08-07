# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-appcred-driver-sql-v0.1.0) - 2026-08-07

### Added

- Auto-register backend drivers via inventory ([#1105](https://github.com/openstack-experimental/keystone/pull/1105))
- *(security)* Wrap secrets with secrecy crate ([#369](https://github.com/openstack-experimental/keystone/pull/369)) ([#912](https://github.com/openstack-experimental/keystone/pull/912))
- Add access rule CRD to appcred provider ([#806](https://github.com/openstack-experimental/keystone/pull/806))
- Make drivers more dynamic ([#737](https://github.com/openstack-experimental/keystone/pull/737))

### Fixed

- Ensure appcred are unique over name+user_id ([#1150](https://github.com/openstack-experimental/keystone/pull/1150))

### Other

- Feature/expose app credential ([#948](https://github.com/openstack-experimental/keystone/pull/948))
- *(deps)* Bump sea-orm and sea-orm-migration to 2.0 ([#1089](https://github.com/openstack-experimental/keystone/pull/1089))
- Extract password hashing into own crate ([#1055](https://github.com/openstack-experimental/keystone/pull/1055))
- *(core)* Eliminate XxxProvider enums ([#830](https://github.com/openstack-experimental/keystone/pull/830))
- Move jsonwebtoken to keystone crate ([#820](https://github.com/openstack-experimental/keystone/pull/820))
- Further align workspace features ([#772](https://github.com/openstack-experimental/keystone/pull/772))
