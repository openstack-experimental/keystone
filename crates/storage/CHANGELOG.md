# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/openstack-experimental/keystone/compare/openstack-keystone-distributed-storage-v0.1.0...openstack-keystone-distributed-storage-v0.1.1) - 2026-07-02

### Added

- Implement background DEK re-encryption pipeline ([#898](https://github.com/openstack-experimental/keystone/pull/898))
- ADR 0021 admin surface, simulate-access, and janitor ([#896](https://github.com/openstack-experimental/keystone/pull/896))
- *(storage)* Cert validity and SVID TTL enforcement ([#886](https://github.com/openstack-experimental/keystone/pull/886))
- *(storage)* SPIFFE checks, RBAC, rate limiting, auto-join ([#861](https://github.com/openstack-experimental/keystone/pull/861))
- *(storage)* Harden preflight and erase dev KEK ([#860](https://github.com/openstack-experimental/keystone/pull/860))
- *(storage)* Add SPIFFE mTLS support to Raft gRPC ([#852](https://github.com/openstack-experimental/keystone/pull/852))
- *(cli)* Add cli storage subcommands per ADR 0016-v2 ([#850](https://github.com/openstack-experimental/keystone/pull/850))
- *(storage)* Complete ADR-0016-v2 ([#844](https://github.com/openstack-experimental/keystone/pull/844))
- *(storage)* implement ADR 0016-v2 Phases 1-4 — encrypted storage with quarantine ([#840](https://github.com/openstack-experimental/keystone/pull/840))
- *(mapping)* ADR-0020 phase 2 ([#807](https://github.com/openstack-experimental/keystone/pull/807))
- *(adr)* Add updated revision of the DS ADR ([#795](https://github.com/openstack-experimental/keystone/pull/795))
- *(mapping)* ADR-0020 (mapping engine) phase 1 ([#794](https://github.com/openstack-experimental/keystone/pull/794))
- Add skeleton for the spiffe mTLS integration ([#695](https://github.com/openstack-experimental/keystone/pull/695))
- Implement ConfigManager for config watching ([#691](https://github.com/openstack-experimental/keystone/pull/691))
- Improve the code ([#686](https://github.com/openstack-experimental/keystone/pull/686))
- Add k8s-auth raft driver ([#676](https://github.com/openstack-experimental/keystone/pull/676))
- Add SetIndex/RemoveIndex storage commands ([#675](https://github.com/openstack-experimental/keystone/pull/675))
- Add basic healthcheck endpoint ([#671](https://github.com/openstack-experimental/keystone/pull/671))
- Add metadata for raft data ([#670](https://github.com/openstack-experimental/keystone/pull/670))
- Add transaction support for Raft storage ([#669](https://github.com/openstack-experimental/keystone/pull/669))
- Add initial benchmarks for the storage ([#668](https://github.com/openstack-experimental/keystone/pull/668))
- Add raft support under skaffold ([#667](https://github.com/openstack-experimental/keystone/pull/667))
- Introduce raft backend for webauthn ([#658](https://github.com/openstack-experimental/keystone/pull/658))
- Prepare raft storage promotion ([#659](https://github.com/openstack-experimental/keystone/pull/659))
- Make raft storage available through state ([#657](https://github.com/openstack-experimental/keystone/pull/657))
- Introduce the keystone-manage cli managing raft ([#656](https://github.com/openstack-experimental/keystone/pull/656))

### Fixed

- *(ci)* Prepare workflows for merge queue ([#902](https://github.com/openstack-experimental/keystone/pull/902))
- Further polish storage crate ([#892](https://github.com/openstack-experimental/keystone/pull/892))
- *(webauthn)* Rotate raft ceremony-state keyspaces ([#890](https://github.com/openstack-experimental/keystone/pull/890))
- Resolve raft replication state races ([#884](https://github.com/openstack-experimental/keystone/pull/884))

### Other

- *(deps)* Batch update dependencies ([#875](https://github.com/openstack-experimental/keystone/pull/875))
- *(core)* Remove spiffe crate dependency ([#858](https://github.com/openstack-experimental/keystone/pull/858))
- Add SpiFFE Raft integration test by skaffold ([#854](https://github.com/openstack-experimental/keystone/pull/854))
- Wrap ServiceState under ExecutionContext ([#856](https://github.com/openstack-experimental/keystone/pull/856))
- *(storage)* Decouple core from storage ([#832](https://github.com/openstack-experimental/keystone/pull/832))
- Update raft drivers mocking ([#791](https://github.com/openstack-experimental/keystone/pull/791))
- Add mock raft storage for unittest ([#790](https://github.com/openstack-experimental/keystone/pull/790))
- Make core crates a workspace dependency ([#736](https://github.com/openstack-experimental/keystone/pull/736))
- Redesign SecurityContext with two-phase validation ([#717](https://github.com/openstack-experimental/keystone/pull/717))
- *(deps)* Bump openraft to alpha17 ([#641](https://github.com/openstack-experimental/keystone/pull/641))
