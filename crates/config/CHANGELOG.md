# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-config-v0.1.0) - 2026-07-24

### Added

- *(config)* Revoke Vault token on shutdown ([#1088](https://github.com/openstack-experimental/keystone/pull/1088))
- Generalize marker pagination for v3/v4 lists ([#1086](https://github.com/openstack-experimental/keystone/pull/1086))
- *(config)* Add Vault-backed configuration ([#1051](https://github.com/openstack-experimental/keystone/pull/1051))
- *(logging)* Add native journald log writer ([#1081](https://github.com/openstack-experimental/keystone/pull/1081))
- *(identity)* Add PATCH to few resources ([#1076](https://github.com/openstack-experimental/keystone/pull/1076))
- *(ldap)* Add LDAP identity driver ([#1047](https://github.com/openstack-experimental/keystone/pull/1047))
- *(adr0028)* Add local-quorum-bypass emergency rotation ([#1032](https://github.com/openstack-experimental/keystone/pull/1032))
- Add catalog CRUD API and bootstrap support ([#1029](https://github.com/openstack-experimental/keystone/pull/1029))
- *(adr0026)* Add RFC 8628 Device Authorization Grant ([#1023](https://github.com/openstack-experimental/keystone/pull/1023))
- *(adr0026)* Add authorization code flow with PKCE ([#1015](https://github.com/openstack-experimental/keystone/pull/1015))
- *(adr0026)* Add client_credentials token endpoint ([#1014](https://github.com/openstack-experimental/keystone/pull/1014))
- *(adr0026)* Phase 2 client registration & OIDC discovery ([#1013](https://github.com/openstack-experimental/keystone/pull/1013))
- *(adr0026)* Phase 0 token abstraction and JWS driver ([#1010](https://github.com/openstack-experimental/keystone/pull/1010))
- *(api)* capture client IP via proxy headers & SPIFFE (#358 follow-up) ([#908](https://github.com/openstack-experimental/keystone/pull/908))
- *(identity)* Add per-user auth rate limiting ([#996](https://github.com/openstack-experimental/keystone/pull/996))
- *(adr0025)* Complete imlpementation ([#969](https://github.com/openstack-experimental/keystone/pull/969))
- *(api)* Add global IP rate limiting framework (ADR-0022 phase 1) ([#846](https://github.com/openstack-experimental/keystone/pull/846))
- *(scim)* Harden RFC 7644 compliance, add docs ([#968](https://github.com/openstack-experimental/keystone/pull/968))
- *(adr0025)* Phase 1 (1.1+1.2) ([#952](https://github.com/openstack-experimental/keystone/pull/952))
- *(security)* Wrap secrets with secrecy crate ([#369](https://github.com/openstack-experimental/keystone/pull/369)) ([#912](https://github.com/openstack-experimental/keystone/pull/912))
- *(scim)* ADR 0024 - Phase 5 ([#951](https://github.com/openstack-experimental/keystone/pull/951))
- *(scim)* ADR 0024 - Phase 1+2 ([#925](https://github.com/openstack-experimental/keystone/pull/925))
- *(fernet)* Unify credential/token key repositories ([#915](https://github.com/openstack-experimental/keystone/pull/915))
- Start ADR 0025 immplementation ([#911](https://github.com/openstack-experimental/keystone/pull/911))
- *(credential)* Implement Phase 3 of ADR 0019 ([#909](https://github.com/openstack-experimental/keystone/pull/909))
- Prepare PKCS#11/TPM KEK support in storage ([#907](https://github.com/openstack-experimental/keystone/pull/907))
- *(credential)* Implement ADR 0019 phases 1-2 ([#897](https://github.com/openstack-experimental/keystone/pull/897))
- Implement stateless SCIM ingress auth (ADR 0021) ([#891](https://github.com/openstack-experimental/keystone/pull/891))
- *(auth)* Password hashing parity with Python Keystone ([#859](https://github.com/openstack-experimental/keystone/pull/859))
- *(audit)* Implement CADF audit framework Phase 2 ([#872](https://github.com/openstack-experimental/keystone/pull/872))
- *(storage)* SPIFFE checks, RBAC, rate limiting, auto-join ([#861](https://github.com/openstack-experimental/keystone/pull/861))
- *(storage)* Harden preflight and erase dev KEK ([#860](https://github.com/openstack-experimental/keystone/pull/860))
- Add bootstrap cli command ([#809](https://github.com/openstack-experimental/keystone/pull/809))
- *(mapping)* ADR-0020 (mapping engine) phase 1 ([#794](https://github.com/openstack-experimental/keystone/pull/794))
- Add inter-provider event notification system ([#784](https://github.com/openstack-experimental/keystone/pull/784))
- Add SO_PEERCRED peer credential validation ([#775](https://github.com/openstack-experimental/keystone/pull/775))
- Validate password for compliance conformity ([#774](https://github.com/openstack-experimental/keystone/pull/774))
- Enforce minimum range boundaries for security
- Add role-imply rest api ([#750](https://github.com/openstack-experimental/keystone/pull/750))
- Add user update functionality ([#747](https://github.com/openstack-experimental/keystone/pull/747))
- Make drivers more dynamic ([#737](https://github.com/openstack-experimental/keystone/pull/737))
- Add keystone container with opa and policies ([#738](https://github.com/openstack-experimental/keystone/pull/738))
- Add Admin interface over the UDS ([#735](https://github.com/openstack-experimental/keystone/pull/735))
- Add spiffe provider ([#733](https://github.com/openstack-experimental/keystone/pull/733))
- Introduce SecurityContext ([#710](https://github.com/openstack-experimental/keystone/pull/710))
- Add skeleton for the spiffe mTLS integration ([#695](https://github.com/openstack-experimental/keystone/pull/695))
- Implement ConfigManager for config watching ([#691](https://github.com/openstack-experimental/keystone/pull/691))
- Improve the code ([#686](https://github.com/openstack-experimental/keystone/pull/686))
- Add k8s-auth raft driver ([#676](https://github.com/openstack-experimental/keystone/pull/676))
- Add raft support under skaffold ([#667](https://github.com/openstack-experimental/keystone/pull/667))
- Introduce raft backend for webauthn ([#658](https://github.com/openstack-experimental/keystone/pull/658))
- Introduce the keystone-manage cli managing raft ([#656](https://github.com/openstack-experimental/keystone/pull/656))

### Fixed

- *(security)* Address security review findings ([#1049](https://github.com/openstack-experimental/keystone/pull/1049))
- *(passkey)* Prevent user enumeration ([#905](https://github.com/openstack-experimental/keystone/pull/905))

### Other

- Revise documentation layout ([#1069](https://github.com/openstack-experimental/keystone/pull/1069))
- Moves health and metrics endpoints to dedicated listener on separate port ([#910](https://github.com/openstack-experimental/keystone/pull/910))
- Move jsonwebtoken to keystone crate ([#820](https://github.com/openstack-experimental/keystone/pull/820))
- mapping engine phase 3 - migrate SPIFFE ([#811](https://github.com/openstack-experimental/keystone/pull/811))
- Rename identity_mapping to idmapping ([#788](https://github.com/openstack-experimental/keystone/pull/788))
- Replace Regex with str::find for db connection ([#760](https://github.com/openstack-experimental/keystone/pull/760))
- Redesign SecurityContext with two-phase validation ([#717](https://github.com/openstack-experimental/keystone/pull/717))
- Split out remaining sql drivers ([#633](https://github.com/openstack-experimental/keystone/pull/633))
- Split config into standalone crate ([#628](https://github.com/openstack-experimental/keystone/pull/628))
