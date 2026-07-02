# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/openstack-experimental/keystone/compare/openstack-keystone-api-types-v0.1.0...openstack-keystone-api-types-v0.1.1) - 2026-07-02

### Added

- ADR 0021 admin surface, simulate-access, and janitor ([#896](https://github.com/openstack-experimental/keystone/pull/896))
- Implement stateless SCIM ingress auth (ADR 0021) ([#891](https://github.com/openstack-experimental/keystone/pull/891))
- Migrate federation to new mapping engine ([#839](https://github.com/openstack-experimental/keystone/pull/839))
- ADR-0020 mapping phase 4 ([#818](https://github.com/openstack-experimental/keystone/pull/818))
- *(mapping)* ADR-0020 phase 2 ([#807](https://github.com/openstack-experimental/keystone/pull/807))
- *(mapping)* ADR-0020 (mapping engine) phase 1 ([#794](https://github.com/openstack-experimental/keystone/pull/794))
- Validate password for compliance conformity ([#774](https://github.com/openstack-experimental/keystone/pull/774))
- Add system-user-role assignments API ([#762](https://github.com/openstack-experimental/keystone/pull/762))
- Add role-imply rest api ([#750](https://github.com/openstack-experimental/keystone/pull/750))
- Add user update functionality ([#747](https://github.com/openstack-experimental/keystone/pull/747))
- Add api to list user roles on project ([#639](https://github.com/openstack-experimental/keystone/pull/639))
- Add domain CRUD operations ([#743](https://github.com/openstack-experimental/keystone/pull/743))
- Add spiffe binding API ([#740](https://github.com/openstack-experimental/keystone/pull/740))
- Add spiffe provider ([#733](https://github.com/openstack-experimental/keystone/pull/733))
- Introduce SecurityContext ([#710](https://github.com/openstack-experimental/keystone/pull/710))
- Add skeleton for the spiffe mTLS integration ([#695](https://github.com/openstack-experimental/keystone/pull/695))
- Improve the code ([#686](https://github.com/openstack-experimental/keystone/pull/686))

### Other

- Move jsonwebtoken to keystone crate ([#820](https://github.com/openstack-experimental/keystone/pull/820))
- *(tests)* Reorganize integration_api tests ([#815](https://github.com/openstack-experimental/keystone/pull/815))
- mapping engine phase 3 - migrate SPIFFE ([#811](https://github.com/openstack-experimental/keystone/pull/811))
- Rename identity_mapping to idmapping ([#788](https://github.com/openstack-experimental/keystone/pull/788))
- Further align workspace features ([#772](https://github.com/openstack-experimental/keystone/pull/772))
- Make resolve_implied_roles optional ([#764](https://github.com/openstack-experimental/keystone/pull/764))
- Redesign SecurityContext with two-phase validation ([#717](https://github.com/openstack-experimental/keystone/pull/717))
- Small optimization of the derives ([#638](https://github.com/openstack-experimental/keystone/pull/638))
- Split the core-types crate ([#640](https://github.com/openstack-experimental/keystone/pull/640))
- Introduce features in api-types crate ([#624](https://github.com/openstack-experimental/keystone/pull/624))
- Slim down api-types crate ([#622](https://github.com/openstack-experimental/keystone/pull/622))
