# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-audit-v0.1.0) - 2026-10-03

### Added

- *(audit)* Ship sealed spool segments to a sink ([#1374](https://github.com/openstack-experimental/keystone/pull/1374))
- *(audit)* Complete ADR-0023 audit implementation ([#887](https://github.com/openstack-experimental/keystone/pull/887))
- Audit framework (ADR-0023) phase 3 ([#880](https://github.com/openstack-experimental/keystone/pull/880))
- *(audit)* Implement CADF audit framework Phase 2 ([#872](https://github.com/openstack-experimental/keystone/pull/872))

### Fixed

- *(audit)* Stop spool replay from looping into itself ([#1350](https://github.com/openstack-experimental/keystone/pull/1350))
- Fix ID sanitizer and capture client IP in audit ([#1126](https://github.com/openstack-experimental/keystone/pull/1126))

### Other

- Fix clippy lints across workspace ([#1361](https://github.com/openstack-experimental/keystone/pull/1361))
- Extend workspace unsafe/unwrap/expect lints ([#1120](https://github.com/openstack-experimental/keystone/pull/1120))
