# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-core-types-v0.1.1) - 2026-07-24

### Added

- Generalize marker pagination for v3/v4 lists ([#1086](https://github.com/openstack-experimental/keystone/pull/1086))
- *(identity)* Add trust create/delete and REST CRUD ([#1079](https://github.com/openstack-experimental/keystone/pull/1079))
- *(catalog)* Expose /v3/regions REST API ([#1078](https://github.com/openstack-experimental/keystone/pull/1078))
- *(identity)* Add PATCH to few resources ([#1076](https://github.com/openstack-experimental/keystone/pull/1076))
- *(ldap)* Add LDAP identity driver ([#1047](https://github.com/openstack-experimental/keystone/pull/1047))
- *(test)* Add tempest identity compatibility ([#998](https://github.com/openstack-experimental/keystone/pull/998))
- *(adr0028)* Add local-quorum-bypass emergency rotation ([#1032](https://github.com/openstack-experimental/keystone/pull/1032))
- Add catalog CRUD API and bootstrap support ([#1029](https://github.com/openstack-experimental/keystone/pull/1029))
- *(adr0026)* Add RFC 8628 Device Authorization Grant ([#1023](https://github.com/openstack-experimental/keystone/pull/1023))
- *(adr0026)* Phase 6a ([#1017](https://github.com/openstack-experimental/keystone/pull/1017))
- *(adr0026)* Add Phase 5 offline token verification ([#1016](https://github.com/openstack-experimental/keystone/pull/1016))
- *(adr0026)* Add authorization code flow with PKCE ([#1015](https://github.com/openstack-experimental/keystone/pull/1015))
- *(adr0026)* Add client_credentials token endpoint ([#1014](https://github.com/openstack-experimental/keystone/pull/1014))
- *(adr0026)* Phase 2 client registration & OIDC discovery ([#1013](https://github.com/openstack-experimental/keystone/pull/1013))
- *(adr0026)* Phase 1 crypto engine & JWKS endpoint ([#1011](https://github.com/openstack-experimental/keystone/pull/1011))
- *(adr0026)* Phase 0 token abstraction and JWS driver ([#1010](https://github.com/openstack-experimental/keystone/pull/1010))
- *(identity)* Add per-user auth rate limiting ([#996](https://github.com/openstack-experimental/keystone/pull/996))
- *(adr0025)* Complete imlpementation ([#969](https://github.com/openstack-experimental/keystone/pull/969))
- *(api)* Add global IP rate limiting framework (ADR-0022 phase 1) ([#846](https://github.com/openstack-experimental/keystone/pull/846))
- *(adr0025)* Phase 1 (1.1+1.2) ([#952](https://github.com/openstack-experimental/keystone/pull/952))
- *(security)* Wrap secrets with secrecy crate ([#369](https://github.com/openstack-experimental/keystone/pull/369)) ([#912](https://github.com/openstack-experimental/keystone/pull/912))
- *(scim)* ADR 0024 - Phase 4 (protocol surface completion) ([#929](https://github.com/openstack-experimental/keystone/pull/929))
- *(scim)* ADR 0024 - Phase 3 ([#928](https://github.com/openstack-experimental/keystone/pull/928))
- *(scim)* ADR 0024 - Phase 1+2 ([#925](https://github.com/openstack-experimental/keystone/pull/925))
- *(credential)* Implement Phase 3 of ADR 0019 ([#909](https://github.com/openstack-experimental/keystone/pull/909))
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

- *(api)* Default enabled/domain_id on create ([#1073](https://github.com/openstack-experimental/keystone/pull/1073))
- *(security)* Address security review findings ([#1049](https://github.com/openstack-experimental/keystone/pull/1049))
- *(federation)* Allow long external unique_id values ([#1033](https://github.com/openstack-experimental/keystone/pull/1033))
- Unify ApiClient scope validation, fix nextest filter ([#947](https://github.com/openstack-experimental/keystone/pull/947))
- Finalize ADR 0021 work ([#906](https://github.com/openstack-experimental/keystone/pull/906))
- Resolve raft replication state races ([#884](https://github.com/openstack-experimental/keystone/pull/884))
- *(k8s_auth)* Flatten k8s.aud claim from JWT TokenReview ([#834](https://github.com/openstack-experimental/keystone/pull/834))
- Align "extra" property handling ([#787](https://github.com/openstack-experimental/keystone/pull/787))

### Other

- Revise documentation layout ([#1069](https://github.com/openstack-experimental/keystone/pull/1069))
- *(security)* Close mutation-testing gaps in auth/policy ([#1056](https://github.com/openstack-experimental/keystone/pull/1056))
- Move jsonwebtoken to keystone crate ([#820](https://github.com/openstack-experimental/keystone/pull/820))
- mapping engine phase 3 - migrate SPIFFE ([#811](https://github.com/openstack-experimental/keystone/pull/811))
- Rename identity_mapping to idmapping ([#788](https://github.com/openstack-experimental/keystone/pull/788))
- Make resolve_implied_roles optional ([#764](https://github.com/openstack-experimental/keystone/pull/764))
- Redesign SecurityContext with two-phase validation ([#717](https://github.com/openstack-experimental/keystone/pull/717))
- Unify state initialization in test ([#642](https://github.com/openstack-experimental/keystone/pull/642))
- Small optimization of the derives ([#638](https://github.com/openstack-experimental/keystone/pull/638))
- Split the core-types crate ([#640](https://github.com/openstack-experimental/keystone/pull/640))
