# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2](https://github.com/openstack-experimental/keystone/compare/openstack-keystone-core-v0.1.1...openstack-keystone-core-v0.1.2) - 2026-06-13

### Added

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

### Other

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
