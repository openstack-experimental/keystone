# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-domain-config-driver-fs-v0.1.0) - 2026-10-10

### Added

- Enable OpenTelemetry metrics and traces support ([#1456](https://github.com/openstack-experimental/keystone/pull/1456))
- *(oslo.config)* Generalize oslo-config crate ([#1429](https://github.com/openstack-experimental/keystone/pull/1429))
- Hot-reload fs per-domain config files ([#1225](https://github.com/openstack-experimental/keystone/pull/1225))
- *(adr0034)* Gate sources on domain_config ([#1217](https://github.com/openstack-experimental/keystone/pull/1217))
- *(adr0034)* Add per-domain driver config surface ([#1216](https://github.com/openstack-experimental/keystone/pull/1216))
- *(domain-config)* Add filesystem driver ([#1197](https://github.com/openstack-experimental/keystone/pull/1197))

### Other

- Fix clippy lints across workspace ([#1361](https://github.com/openstack-experimental/keystone/pull/1361))
