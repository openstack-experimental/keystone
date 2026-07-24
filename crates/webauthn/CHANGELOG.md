# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-webauthn-v0.1.0) - 2026-07-24

### Added

- *(test)* Add tempest identity compatibility ([#998](https://github.com/openstack-experimental/keystone/pull/998))
- Prepare PKCS#11/TPM KEK support in storage ([#907](https://github.com/openstack-experimental/keystone/pull/907))
- *(audit)* Implement CADF audit framework Phase 2 ([#872](https://github.com/openstack-experimental/keystone/pull/872))
- *(storage)* SPIFFE checks, RBAC, rate limiting, auto-join ([#861](https://github.com/openstack-experimental/keystone/pull/861))
- *(storage)* Harden preflight and erase dev KEK ([#860](https://github.com/openstack-experimental/keystone/pull/860))
- Security improvements in the webauthn crate ([#838](https://github.com/openstack-experimental/keystone/pull/838))
- Add inter-provider event notification system ([#784](https://github.com/openstack-experimental/keystone/pull/784))
- Make drivers more dynamic ([#737](https://github.com/openstack-experimental/keystone/pull/737))
- Introduce SecurityContext ([#710](https://github.com/openstack-experimental/keystone/pull/710))
- Add skeleton for the spiffe mTLS integration ([#695](https://github.com/openstack-experimental/keystone/pull/695))
- Implement ConfigManager for config watching ([#691](https://github.com/openstack-experimental/keystone/pull/691))
- Improve the code ([#686](https://github.com/openstack-experimental/keystone/pull/686))
- Add k8s-auth raft driver ([#676](https://github.com/openstack-experimental/keystone/pull/676))
- Add metadata for raft data ([#670](https://github.com/openstack-experimental/keystone/pull/670))
- Add raft support under skaffold ([#667](https://github.com/openstack-experimental/keystone/pull/667))
- Introduce raft backend for webauthn ([#658](https://github.com/openstack-experimental/keystone/pull/658))

### Fixed

- *(passkey)* Prevent user enumeration ([#905](https://github.com/openstack-experimental/keystone/pull/905))
- *(ci)* Prepare workflows for merge queue ([#902](https://github.com/openstack-experimental/keystone/pull/902))
- *(webauthn)* Rotate raft ceremony-state keyspaces ([#890](https://github.com/openstack-experimental/keystone/pull/890))

### Other

- *(deps)* Bump sea-orm and sea-orm-migration to 2.0 ([#1089](https://github.com/openstack-experimental/keystone/pull/1089))
- *(deps)* Batch update dependencies ([#875](https://github.com/openstack-experimental/keystone/pull/875))
- Wrap ServiceState under ExecutionContext ([#856](https://github.com/openstack-experimental/keystone/pull/856))
- *(storage)* Decouple core from storage ([#832](https://github.com/openstack-experimental/keystone/pull/832))
- Update raft drivers mocking ([#791](https://github.com/openstack-experimental/keystone/pull/791))
- Add mock raft storage for unittest ([#790](https://github.com/openstack-experimental/keystone/pull/790))
- Make core crates a workspace dependency ([#736](https://github.com/openstack-experimental/keystone/pull/736))
- Redesign SecurityContext with two-phase validation ([#717](https://github.com/openstack-experimental/keystone/pull/717))
- Split the core-types crate ([#640](https://github.com/openstack-experimental/keystone/pull/640))
- Move assignment parameters resolution to driver ([#625](https://github.com/openstack-experimental/keystone/pull/625))
- Introduce features in api-types crate ([#624](https://github.com/openstack-experimental/keystone/pull/624))
- Split out webauthn into crate ([#621](https://github.com/openstack-experimental/keystone/pull/621))
