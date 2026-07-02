# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2](https://github.com/openstack-experimental/keystone/compare/openstack-keystone-core-v0.1.1...openstack-keystone-core-v0.1.2) - 2026-07-02

### Added

- *(credential)* Implement ADR 0019 phases 1-2 ([#897](https://github.com/openstack-experimental/keystone/pull/897))
- ADR 0021 admin surface, simulate-access, and janitor ([#896](https://github.com/openstack-experimental/keystone/pull/896))
- Implement stateless SCIM ingress auth (ADR 0021) ([#891](https://github.com/openstack-experimental/keystone/pull/891))
- *(audit)* Complete ADR-0023 audit implementation ([#887](https://github.com/openstack-experimental/keystone/pull/887))
- *(storage)* Cert validity and SVID TTL enforcement ([#886](https://github.com/openstack-experimental/keystone/pull/886))
- Audit framework (ADR-0023) phase 3 ([#880](https://github.com/openstack-experimental/keystone/pull/880))
- *(auth)* Password hashing parity with Python Keystone ([#859](https://github.com/openstack-experimental/keystone/pull/859))
- *(audit)* Implement CADF audit framework Phase 2 ([#872](https://github.com/openstack-experimental/keystone/pull/872))
- Migrate federation to new mapping engine ([#839](https://github.com/openstack-experimental/keystone/pull/839))
- Add access rule CRD to appcred provider ([#806](https://github.com/openstack-experimental/keystone/pull/806))
- ADR-0020 mapping phase 4 ([#818](https://github.com/openstack-experimental/keystone/pull/818))
- Add bootstrap cli command ([#809](https://github.com/openstack-experimental/keystone/pull/809))
- *(mapping)* ADR-0020 (mapping engine) phase 1 ([#794](https://github.com/openstack-experimental/keystone/pull/794))
- Add endpoint CRUD to catalog provider ([#785](https://github.com/openstack-experimental/keystone/pull/785))
- Add inter-provider event notification system ([#784](https://github.com/openstack-experimental/keystone/pull/784))
- Add service CRUD to the catalog provider ([#773](https://github.com/openstack-experimental/keystone/pull/773))
- Validate password for compliance conformity ([#774](https://github.com/openstack-experimental/keystone/pull/774))
- Return 401 on roleless scoped contexts ([#742](https://github.com/openstack-experimental/keystone/pull/742))
- Add region CRUD to catalog SQL driver ([#761](https://github.com/openstack-experimental/keystone/pull/761))
- Add timing attack protection and failed auth tracking ([#758](https://github.com/openstack-experimental/keystone/pull/758))
- Add role-imply rest api ([#750](https://github.com/openstack-experimental/keystone/pull/750))
- Add role imply API ([#749](https://github.com/openstack-experimental/keystone/pull/749))
- Add user update functionality ([#747](https://github.com/openstack-experimental/keystone/pull/747))
- Add domain CRUD operations ([#743](https://github.com/openstack-experimental/keystone/pull/743))
- Add spiffe binding API ([#740](https://github.com/openstack-experimental/keystone/pull/740))
- Normalize the policy enforcer structure ([#741](https://github.com/openstack-experimental/keystone/pull/741))
- Make drivers more dynamic ([#737](https://github.com/openstack-experimental/keystone/pull/737))
- Add Admin interface over the UDS ([#735](https://github.com/openstack-experimental/keystone/pull/735))
- Add spiffe provider ([#733](https://github.com/openstack-experimental/keystone/pull/733))
- Expand role info in `expand_implied_roles` ([#730](https://github.com/openstack-experimental/keystone/pull/730))
- Introduce SecurityContext ([#710](https://github.com/openstack-experimental/keystone/pull/710))
- Talk to OPA over unix socket ([#701](https://github.com/openstack-experimental/keystone/pull/701))
- Add skeleton for the spiffe mTLS integration ([#695](https://github.com/openstack-experimental/keystone/pull/695))
- Implement ConfigManager for config watching ([#691](https://github.com/openstack-experimental/keystone/pull/691))
- Improve the code ([#686](https://github.com/openstack-experimental/keystone/pull/686))
- Add k8s-auth raft driver ([#676](https://github.com/openstack-experimental/keystone/pull/676))
- Add basic healthcheck endpoint ([#671](https://github.com/openstack-experimental/keystone/pull/671))
- Make raft storage available through state ([#657](https://github.com/openstack-experimental/keystone/pull/657))

### Fixed

- *(ci)* Prepare workflows for merge queue ([#902](https://github.com/openstack-experimental/keystone/pull/902))
- Resolve raft replication state races ([#884](https://github.com/openstack-experimental/keystone/pull/884))
- *(core)* Eliminate mapping race condition ([#876](https://github.com/openstack-experimental/keystone/pull/876))
- *(k8s_auth)* Flatten k8s.aud claim from JWT TokenReview ([#834](https://github.com/openstack-experimental/keystone/pull/834))
- *(auth)* Close admin SVID impersonation gap ([#833](https://github.com/openstack-experimental/keystone/pull/833))

### Other

- Reorganize dockerfile and deps ([#857](https://github.com/openstack-experimental/keystone/pull/857))
- *(core)* Remove spiffe crate dependency ([#858](https://github.com/openstack-experimental/keystone/pull/858))
- Wrap ServiceState under ExecutionContext ([#856](https://github.com/openstack-experimental/keystone/pull/856))
- *(storage)* Decouple core from storage ([#832](https://github.com/openstack-experimental/keystone/pull/832))
- *(core)* Eliminate XxxProvider enums ([#830](https://github.com/openstack-experimental/keystone/pull/830))
- Move jsonwebtoken to keystone crate ([#820](https://github.com/openstack-experimental/keystone/pull/820))
- mapping engine phase 3 - migrate SPIFFE ([#811](https://github.com/openstack-experimental/keystone/pull/811))
- *(deps)* bump hmac from 0.12.1 to 0.13.0 ([#801](https://github.com/openstack-experimental/keystone/pull/801))
- Rename identity_mapping to idmapping ([#788](https://github.com/openstack-experimental/keystone/pull/788))
- Consolidate password update flows ([#778](https://github.com/openstack-experimental/keystone/pull/778))
- Further align workspace features ([#772](https://github.com/openstack-experimental/keystone/pull/772))
- Make resolve_implied_roles optional ([#764](https://github.com/openstack-experimental/keystone/pull/764))
- Redesign SecurityContext with two-phase validation ([#717](https://github.com/openstack-experimental/keystone/pull/717))
- *(deps)* bump jsonwebtoken from 10.3.0 to 10.4.0 ([#707](https://github.com/openstack-experimental/keystone/pull/707))
- Introduce dynamic plugins ([#643](https://github.com/openstack-experimental/keystone/pull/643))
- Small optimization of the derives ([#638](https://github.com/openstack-experimental/keystone/pull/638))
- Split the core-types crate ([#640](https://github.com/openstack-experimental/keystone/pull/640))
- Split out remaining sql drivers ([#633](https://github.com/openstack-experimental/keystone/pull/633))
- Split more drivers to separate crates ([#632](https://github.com/openstack-experimental/keystone/pull/632))
- Drop unnecessary derives to help compilation ([#631](https://github.com/openstack-experimental/keystone/pull/631))
- Drop unnecessary tracing directives ([#627](https://github.com/openstack-experimental/keystone/pull/627))
- Split config into standalone crate ([#628](https://github.com/openstack-experimental/keystone/pull/628))
- Rework http client pool ([#629](https://github.com/openstack-experimental/keystone/pull/629))
- Make assignment sql driver a standalone crate ([#626](https://github.com/openstack-experimental/keystone/pull/626))
- Move assignment parameters resolution to driver ([#625](https://github.com/openstack-experimental/keystone/pull/625))
- Introduce features in api-types crate ([#624](https://github.com/openstack-experimental/keystone/pull/624))
- Slim down api-types crate ([#622](https://github.com/openstack-experimental/keystone/pull/622))
- Split out webauthn into crate ([#621](https://github.com/openstack-experimental/keystone/pull/621))
- Split out token-fernet driver ([#620](https://github.com/openstack-experimental/keystone/pull/620))
- Prepare slit out of the FernetTokenProvider ([#619](https://github.com/openstack-experimental/keystone/pull/619))
- Move benchmark into the proper crate ([#614](https://github.com/openstack-experimental/keystone/pull/614))
