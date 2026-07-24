# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-resource-driver-sql-v0.1.0) - 2026-07-24

### Added

- Generalize marker pagination for v3/v4 lists ([#1086](https://github.com/openstack-experimental/keystone/pull/1086))
- *(identity)* Add PATCH to few resources ([#1076](https://github.com/openstack-experimental/keystone/pull/1076))
- *(test)* Add tempest identity compatibility ([#998](https://github.com/openstack-experimental/keystone/pull/998))
- Add bootstrap cli command ([#809](https://github.com/openstack-experimental/keystone/pull/809))
- Make drivers more dynamic ([#737](https://github.com/openstack-experimental/keystone/pull/737))

### Fixed

- *(ci)* Prepare workflows for merge queue ([#902](https://github.com/openstack-experimental/keystone/pull/902))

### Other

- *(deps)* Bump sea-orm and sea-orm-migration to 2.0 ([#1089](https://github.com/openstack-experimental/keystone/pull/1089))
- Wrap ServiceState under ExecutionContext ([#856](https://github.com/openstack-experimental/keystone/pull/856))
- Move jsonwebtoken to keystone crate ([#820](https://github.com/openstack-experimental/keystone/pull/820))
