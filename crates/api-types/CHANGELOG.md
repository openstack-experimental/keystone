# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/openstack-experimental/keystone/compare/openstack-keystone-api-types-v0.1.0...openstack-keystone-api-types-v0.1.1) - 2026-07-24

### Added

- Generalize marker pagination for v3/v4 lists ([#1086](https://github.com/openstack-experimental/keystone/pull/1086))
- *(identity)* Add trust create/delete and REST CRUD ([#1079](https://github.com/openstack-experimental/keystone/pull/1079))
- *(catalog)* Expose /v3/regions REST API ([#1078](https://github.com/openstack-experimental/keystone/pull/1078))
- *(identity)* Add PATCH to few resources ([#1076](https://github.com/openstack-experimental/keystone/pull/1076))
- *(ldap)* Add LDAP identity driver ([#1047](https://github.com/openstack-experimental/keystone/pull/1047))
- *(test)* Add tempest identity compatibility ([#998](https://github.com/openstack-experimental/keystone/pull/998))
- *(adr0028)* Add local-quorum-bypass emergency rotation ([#1032](https://github.com/openstack-experimental/keystone/pull/1032))
- Add catalog CRUD API and bootstrap support ([#1029](https://github.com/openstack-experimental/keystone/pull/1029))
- *(adr0026)* Extend keystone-manage oauth2 CLI ([#1020](https://github.com/openstack-experimental/keystone/pull/1020))
- *(adr0026)* Phase 6a ([#1017](https://github.com/openstack-experimental/keystone/pull/1017))
- *(adr0026)* Add client_credentials token endpoint ([#1014](https://github.com/openstack-experimental/keystone/pull/1014))
- *(adr0026)* Phase 2 client registration & OIDC discovery ([#1013](https://github.com/openstack-experimental/keystone/pull/1013))
- *(adr0026)* Phase 1 crypto engine & JWKS endpoint ([#1011](https://github.com/openstack-experimental/keystone/pull/1011))
- *(identity)* Add per-user auth rate limiting ([#996](https://github.com/openstack-experimental/keystone/pull/996))
- *(adr0025)* Complete imlpementation ([#969](https://github.com/openstack-experimental/keystone/pull/969))
- *(identity)* Implement user password change endpoint ([#970](https://github.com/openstack-experimental/keystone/pull/970))
- *(api)* Add global IP rate limiting framework (ADR-0022 phase 1) ([#846](https://github.com/openstack-experimental/keystone/pull/846))
- *(adr0025)* Phase 1 (1.1+1.2) ([#952](https://github.com/openstack-experimental/keystone/pull/952))
- *(security)* Wrap secrets with secrecy crate ([#369](https://github.com/openstack-experimental/keystone/pull/369)) ([#912](https://github.com/openstack-experimental/keystone/pull/912))
- *(scim)* ADR 0024 - Phase 5 ([#951](https://github.com/openstack-experimental/keystone/pull/951))
- *(scim)* ADR 0024 - Phase 1+2 ([#925](https://github.com/openstack-experimental/keystone/pull/925))
- *(credential)* Implement Phase 3 of ADR 0019 ([#909](https://github.com/openstack-experimental/keystone/pull/909))
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

### Fixed

- Address multiple tempest failures ([#1083](https://github.com/openstack-experimental/keystone/pull/1083))
- *(api)* Default enabled/domain_id on create ([#1073](https://github.com/openstack-experimental/keystone/pull/1073))
- *(security)* Address security review findings ([#1049](https://github.com/openstack-experimental/keystone/pull/1049))
- *(federation)* Allow long external unique_id values ([#1033](https://github.com/openstack-experimental/keystone/pull/1033))
- Unify ApiClient scope validation, fix nextest filter ([#947](https://github.com/openstack-experimental/keystone/pull/947))
- Finalize ADR 0021 work ([#906](https://github.com/openstack-experimental/keystone/pull/906))

### Other

- *(test)* Improve testing of the oauth2 OP ([#1024](https://github.com/openstack-experimental/keystone/pull/1024))
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
