# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-resource-driver-sql-v0.1.0) - 2026-10-10

### Added

- Enable OpenTelemetry metrics and traces support ([#1456](https://github.com/openstack-experimental/keystone/pull/1456))
- *(resource)* Add enabled filter to project list ([#1453](https://github.com/openstack-experimental/keystone/pull/1453))
- *(core)* Reconnect database connection on new config ([#1188](https://github.com/openstack-experimental/keystone/pull/1188))
- Auto-register backend drivers via inventory ([#1105](https://github.com/openstack-experimental/keystone/pull/1105))
- Add immutable option for project, domain, role ([#1097](https://github.com/openstack-experimental/keystone/pull/1097))
- Generalize marker pagination for v3/v4 lists ([#1086](https://github.com/openstack-experimental/keystone/pull/1086))
- *(identity)* Add PATCH to few resources ([#1076](https://github.com/openstack-experimental/keystone/pull/1076))
- *(test)* Add tempest identity compatibility ([#998](https://github.com/openstack-experimental/keystone/pull/998))
- Add bootstrap cli command ([#809](https://github.com/openstack-experimental/keystone/pull/809))
- Make drivers more dynamic ([#737](https://github.com/openstack-experimental/keystone/pull/737))

### Fixed

- *(resource)* Reject project names over 64 chars ([#1455](https://github.com/openstack-experimental/keystone/pull/1455))
- *(ci)* Prepare workflows for merge queue ([#902](https://github.com/openstack-experimental/keystone/pull/902))

### Other

- Fix clippy lints across workspace ([#1361](https://github.com/openstack-experimental/keystone/pull/1361))
- *(deps)* Bump sea-orm and sea-orm-migration to 2.0 ([#1089](https://github.com/openstack-experimental/keystone/pull/1089))
- Wrap ServiceState under ExecutionContext ([#856](https://github.com/openstack-experimental/keystone/pull/856))
- Move jsonwebtoken to keystone crate ([#820](https://github.com/openstack-experimental/keystone/pull/820))
