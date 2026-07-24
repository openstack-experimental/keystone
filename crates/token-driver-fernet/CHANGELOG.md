# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-token-driver-fernet-v0.1.1) - 2026-07-24

### Added

- *(adr0026)* Phase 0 token abstraction and JWS driver ([#1010](https://github.com/openstack-experimental/keystone/pull/1010))
- *(fernet)* Unify credential/token key repositories ([#915](https://github.com/openstack-experimental/keystone/pull/915))
- Add user update functionality ([#747](https://github.com/openstack-experimental/keystone/pull/747))
- Make drivers more dynamic ([#737](https://github.com/openstack-experimental/keystone/pull/737))

### Fixed

- Widen Fernet key index from i8 to u32 ([#1080](https://github.com/openstack-experimental/keystone/pull/1080))
- Support macOS dev builds and fs watcher shutdown ([#1009](https://github.com/openstack-experimental/keystone/pull/1009))
- Fix msgpack decode and auth-method encoding bugs ([#895](https://github.com/openstack-experimental/keystone/pull/895))
