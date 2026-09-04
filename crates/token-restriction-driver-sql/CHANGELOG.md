# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-token-restriction-driver-sql-v0.1.0) - 2026-09-04

### Added

- *(core)* Reconnect database connection on new config ([#1188](https://github.com/openstack-experimental/keystone/pull/1188))
- Auto-register backend drivers via inventory ([#1105](https://github.com/openstack-experimental/keystone/pull/1105))
- Generalize marker pagination for v3/v4 lists ([#1086](https://github.com/openstack-experimental/keystone/pull/1086))
- Make drivers more dynamic ([#737](https://github.com/openstack-experimental/keystone/pull/737))

### Other

- *(api)* Cover v4 handlers and fix role assignment routing ([#1153](https://github.com/openstack-experimental/keystone/pull/1153))
- *(deps)* Bump sea-orm and sea-orm-migration to 2.0 ([#1089](https://github.com/openstack-experimental/keystone/pull/1089))
- Move jsonwebtoken to keystone crate ([#820](https://github.com/openstack-experimental/keystone/pull/820))
