# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-cli-manage-v0.1.0) - 2026-07-24

### Added

- *(config)* Add Vault-backed configuration ([#1051](https://github.com/openstack-experimental/keystone/pull/1051))
- *(adr0028)* Add local-quorum-bypass emergency rotation ([#1032](https://github.com/openstack-experimental/keystone/pull/1032))
- *(cli-manage)* Make catalog create idempotent ([#1031](https://github.com/openstack-experimental/keystone/pull/1031))
- Add catalog CRUD API and bootstrap support ([#1029](https://github.com/openstack-experimental/keystone/pull/1029))
- *(adr0026)* Extend keystone-manage oauth2 CLI ([#1020](https://github.com/openstack-experimental/keystone/pull/1020))
- *(fernet)* Unify credential/token key repositories ([#915](https://github.com/openstack-experimental/keystone/pull/915))
- *(credential)* Implement Phase 3 of ADR 0019 ([#909](https://github.com/openstack-experimental/keystone/pull/909))
- *(storage)* SPIFFE checks, RBAC, rate limiting, auto-join ([#861](https://github.com/openstack-experimental/keystone/pull/861))
- *(storage)* Add SPIFFE mTLS support to Raft gRPC ([#852](https://github.com/openstack-experimental/keystone/pull/852))
- *(cli)* Add cli storage subcommands per ADR 0016-v2 ([#850](https://github.com/openstack-experimental/keystone/pull/850))
- *(storage)* implement ADR 0016-v2 Phases 1-4 — encrypted storage with quarantine ([#840](https://github.com/openstack-experimental/keystone/pull/840))
- Add bootstrap cli command ([#809](https://github.com/openstack-experimental/keystone/pull/809))
- Make drivers more dynamic ([#737](https://github.com/openstack-experimental/keystone/pull/737))
- Introduce SecurityContext ([#710](https://github.com/openstack-experimental/keystone/pull/710))
- Add skeleton for the spiffe mTLS integration ([#695](https://github.com/openstack-experimental/keystone/pull/695))
- Implement ConfigManager for config watching ([#691](https://github.com/openstack-experimental/keystone/pull/691))
- Add raft support under skaffold ([#667](https://github.com/openstack-experimental/keystone/pull/667))
- Introduce the keystone-manage cli managing raft ([#656](https://github.com/openstack-experimental/keystone/pull/656))

### Fixed

- *(ci)* Prepare workflows for merge queue ([#902](https://github.com/openstack-experimental/keystone/pull/902))

### Other

- *(test)* Improve testing of the oauth2 OP ([#1024](https://github.com/openstack-experimental/keystone/pull/1024))
- Move jsonwebtoken to keystone crate ([#820](https://github.com/openstack-experimental/keystone/pull/820))
- Unify sea-orm features ([#769](https://github.com/openstack-experimental/keystone/pull/769))
