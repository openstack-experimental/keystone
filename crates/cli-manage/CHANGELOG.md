# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-cli-manage-v0.1.0) - 2026-10-10

### Added

- *(storage)* Transfer leadership on demote ([#1462](https://github.com/openstack-experimental/keystone/pull/1462))
- *(storage)* Show DEK state in list-peers ([#1460](https://github.com/openstack-experimental/keystone/pull/1460))
- *(oslo.config)* Generalize oslo-config crate ([#1429](https://github.com/openstack-experimental/keystone/pull/1429))
- *(audit)* Add HMAC key rotation and node checks ([#1382](https://github.com/openstack-experimental/keystone/pull/1382))
- *(raft)* Add backup restore ([#1352](https://github.com/openstack-experimental/keystone/pull/1352))
- *(cli-manage)* Add mapping ruleset commands ([#1244](https://github.com/openstack-experimental/keystone/pull/1244))
- *(devstack)* Pilot ksm SPIFFE mTLS transport ([#1239](https://github.com/openstack-experimental/keystone/pull/1239))
- Add immutable option for project, domain, role ([#1097](https://github.com/openstack-experimental/keystone/pull/1097))
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

- *(storage)* Adopt cluster DEK in storage join ([#1463](https://github.com/openstack-experimental/keystone/pull/1463))
- *(resource)* Align domain and project response shape ([#1454](https://github.com/openstack-experimental/keystone/pull/1454))
- *(storage)* Route admin RPCs to the Raft leader ([#1447](https://github.com/openstack-experimental/keystone/pull/1447))
- *(cli-manage)* Pin admin client SVID to admin_svid ([#1428](https://github.com/openstack-experimental/keystone/pull/1428))
- *(storage)* Authorize Raft and Storage gRPC callers ([#1418](https://github.com/openstack-experimental/keystone/pull/1418))
- *(ci)* Prepare workflows for merge queue ([#902](https://github.com/openstack-experimental/keystone/pull/902))

### Other

- *(cadf)* Own the audit configuration ([#1405](https://github.com/openstack-experimental/keystone/pull/1405))
- *(audit)* Rename audit crate to cadf ([#1399](https://github.com/openstack-experimental/keystone/pull/1399))
- Fix clippy lints across workspace ([#1361](https://github.com/openstack-experimental/keystone/pull/1361))
- Upgrade comfy-table to v8 ([#1164](https://github.com/openstack-experimental/keystone/pull/1164))
- *(test)* Improve testing of the oauth2 OP ([#1024](https://github.com/openstack-experimental/keystone/pull/1024))
- Move jsonwebtoken to keystone crate ([#820](https://github.com/openstack-experimental/keystone/pull/820))
- Unify sea-orm features ([#769](https://github.com/openstack-experimental/keystone/pull/769))
