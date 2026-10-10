# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-oauth2-session-driver-raft-v0.1.0) - 2026-10-10

### Added

- *(oauth2)* Remember consent per client ([#1476](https://github.com/openstack-experimental/keystone/pull/1476))
- *(oauth2)* Add SSO session and RP logout ([#1475](https://github.com/openstack-experimental/keystone/pull/1475))
- *(oauth2)* Add federated sign-in to OP login ([#1474](https://github.com/openstack-experimental/keystone/pull/1474))
- *(oauth2)* Add TOTP second factor to OP login ([#1473](https://github.com/openstack-experimental/keystone/pull/1473))
- Enable OpenTelemetry metrics and traces support ([#1456](https://github.com/openstack-experimental/keystone/pull/1456))
- *(oauth2)* Revoke refresh families on lifecycle ([#1404](https://github.com/openstack-experimental/keystone/pull/1404))
- *(oauth2)* Cap refresh families and revalidate user ([#1360](https://github.com/openstack-experimental/keystone/pull/1360))
- *(oauth2-session)* Add expired record janitor ([#1359](https://github.com/openstack-experimental/keystone/pull/1359))
- *(oauth2)* Add secondary indexes to raft driver ([#1327](https://github.com/openstack-experimental/keystone/pull/1327))
- Auto-register backend drivers via inventory ([#1105](https://github.com/openstack-experimental/keystone/pull/1105))
- *(adr0026)* Add RFC 8628 Device Authorization Grant ([#1023](https://github.com/openstack-experimental/keystone/pull/1023))
- *(adr0026)* Add authorization code flow with PKCE ([#1015](https://github.com/openstack-experimental/keystone/pull/1015))

### Fixed

- *(oauth2-session)* Tombstone revoked refresh families ([#1358](https://github.com/openstack-experimental/keystone/pull/1358))
- *(storage)* Adopt leader's DEK when nodes join ([#1328](https://github.com/openstack-experimental/keystone/pull/1328))

### Other

- Fix clippy lints across workspace ([#1361](https://github.com/openstack-experimental/keystone/pull/1361))
