# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/cadf-v0.1.0) - 2026-10-10

### Added

- Enable OpenTelemetry metrics and traces support ([#1456](https://github.com/openstack-experimental/keystone/pull/1456))
- *(cadf)* Use DSP0262 names on the wire ([#1419](https://github.com/openstack-experimental/keystone/pull/1419))
- *(audit)* Add opt-in per-request perimeter record ([#1415](https://github.com/openstack-experimental/keystone/pull/1415))

### Fixed

- *(oauth2)* Check client on device grant redeem ([#1435](https://github.com/openstack-experimental/keystone/pull/1435))
- *(audit)* Polish the CADF crate ([#1424](https://github.com/openstack-experimental/keystone/pull/1424))

### Other

- *(audit)* Assert live audit spool records ([#1422](https://github.com/openstack-experimental/keystone/pull/1422))
- *(audit)* Cover startup seal, quarantine, hooks ([#1410](https://github.com/openstack-experimental/keystone/pull/1410))
- *(cadf)* Move audit startup into runtime ([#1406](https://github.com/openstack-experimental/keystone/pull/1406))
- *(cadf)* Own the audit configuration ([#1405](https://github.com/openstack-experimental/keystone/pull/1405))
- *(cadf)* Parameterize the service identity ([#1400](https://github.com/openstack-experimental/keystone/pull/1400))
- *(audit)* Rename audit crate to cadf ([#1399](https://github.com/openstack-experimental/keystone/pull/1399))
