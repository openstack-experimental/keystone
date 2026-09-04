# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-assignment-driver-sql-v0.1.0) - 2026-09-04

### Added

- *(core)* Reconnect database connection on new config ([#1188](https://github.com/openstack-experimental/keystone/pull/1188))
- *(pagination)* Add pagination to remaining places ([#1106](https://github.com/openstack-experimental/keystone/pull/1106))
- Auto-register backend drivers via inventory ([#1105](https://github.com/openstack-experimental/keystone/pull/1105))
- *(audit)* Implement CADF audit framework Phase 2 ([#872](https://github.com/openstack-experimental/keystone/pull/872))
- Add role-imply rest api ([#750](https://github.com/openstack-experimental/keystone/pull/750))
- Make drivers more dynamic ([#737](https://github.com/openstack-experimental/keystone/pull/737))

### Fixed

- Respect group_id param in assignment list ([#953](https://github.com/openstack-experimental/keystone/pull/953))
- *(ci)* Prepare workflows for merge queue ([#902](https://github.com/openstack-experimental/keystone/pull/902))

### Other

- Extend workspace unsafe/unwrap/expect lints ([#1120](https://github.com/openstack-experimental/keystone/pull/1120))
- *(db)* 3 optimizations for DB queries ([#1111](https://github.com/openstack-experimental/keystone/pull/1111))
- Wrap ServiceState under ExecutionContext ([#856](https://github.com/openstack-experimental/keystone/pull/856))
- *(storage)* Decouple core from storage ([#832](https://github.com/openstack-experimental/keystone/pull/832))
- Move jsonwebtoken to keystone crate ([#820](https://github.com/openstack-experimental/keystone/pull/820))
- Further align workspace features ([#772](https://github.com/openstack-experimental/keystone/pull/772))
- Make resolve_implied_roles optional ([#764](https://github.com/openstack-experimental/keystone/pull/764))
