# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-core-types-v0.1.1) - 2026-07-02

### Added

- *(credential)* Implement ADR 0019 phases 1-2 ([#897](https://github.com/openstack-experimental/keystone/pull/897))
- Implement stateless SCIM ingress auth (ADR 0021) ([#891](https://github.com/openstack-experimental/keystone/pull/891))
- Audit framework (ADR-0023) phase 3 ([#880](https://github.com/openstack-experimental/keystone/pull/880))
- *(audit)* Implement CADF audit framework Phase 2 ([#872](https://github.com/openstack-experimental/keystone/pull/872))
- Migrate federation to new mapping engine ([#839](https://github.com/openstack-experimental/keystone/pull/839))
- Add access rule CRD to appcred provider ([#806](https://github.com/openstack-experimental/keystone/pull/806))
- ADR-0020 mapping phase 4 ([#818](https://github.com/openstack-experimental/keystone/pull/818))
- *(mapping)* ADR-0020 (mapping engine) phase 1 ([#794](https://github.com/openstack-experimental/keystone/pull/794))
- Add endpoint CRUD to catalog provider ([#785](https://github.com/openstack-experimental/keystone/pull/785))
- Add inter-provider event notification system ([#784](https://github.com/openstack-experimental/keystone/pull/784))
- Add service CRUD to the catalog provider ([#773](https://github.com/openstack-experimental/keystone/pull/773))
- Validate password for compliance conformity ([#774](https://github.com/openstack-experimental/keystone/pull/774))
- Return 401 on roleless scoped contexts ([#742](https://github.com/openstack-experimental/keystone/pull/742))
- Add region CRUD to catalog SQL driver ([#761](https://github.com/openstack-experimental/keystone/pull/761))
- Add role-imply rest api ([#750](https://github.com/openstack-experimental/keystone/pull/750))
- Add role imply API ([#749](https://github.com/openstack-experimental/keystone/pull/749))
- Add user update functionality ([#747](https://github.com/openstack-experimental/keystone/pull/747))
- Add spiffe binding API ([#740](https://github.com/openstack-experimental/keystone/pull/740))
- Add Admin interface over the UDS ([#735](https://github.com/openstack-experimental/keystone/pull/735))
- Add spiffe provider ([#733](https://github.com/openstack-experimental/keystone/pull/733))
- Expand role info in `expand_implied_roles` ([#730](https://github.com/openstack-experimental/keystone/pull/730))
- Introduce SecurityContext ([#710](https://github.com/openstack-experimental/keystone/pull/710))
- Improve the code ([#686](https://github.com/openstack-experimental/keystone/pull/686))
- Add k8s-auth raft driver ([#676](https://github.com/openstack-experimental/keystone/pull/676))
- Introduce the keystone-manage cli managing raft ([#656](https://github.com/openstack-experimental/keystone/pull/656))

### Fixed

- Resolve raft replication state races ([#884](https://github.com/openstack-experimental/keystone/pull/884))
- *(k8s_auth)* Flatten k8s.aud claim from JWT TokenReview ([#834](https://github.com/openstack-experimental/keystone/pull/834))
- Align "extra" property handling ([#787](https://github.com/openstack-experimental/keystone/pull/787))

### Other

- Move jsonwebtoken to keystone crate ([#820](https://github.com/openstack-experimental/keystone/pull/820))
- mapping engine phase 3 - migrate SPIFFE ([#811](https://github.com/openstack-experimental/keystone/pull/811))
- Rename identity_mapping to idmapping ([#788](https://github.com/openstack-experimental/keystone/pull/788))
- Make resolve_implied_roles optional ([#764](https://github.com/openstack-experimental/keystone/pull/764))
- Redesign SecurityContext with two-phase validation ([#717](https://github.com/openstack-experimental/keystone/pull/717))
- Unify state initialization in test ([#642](https://github.com/openstack-experimental/keystone/pull/642))
- Small optimization of the derives ([#638](https://github.com/openstack-experimental/keystone/pull/638))
- Split the core-types crate ([#640](https://github.com/openstack-experimental/keystone/pull/640))
