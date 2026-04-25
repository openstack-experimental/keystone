# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2](https://github.com/openstack-experimental/keystone/compare/openstack-keystone-v0.1.1...openstack-keystone-v0.1.2) - 2026-04-25

### Added

- Add k8s-auth raft driver ([#676](https://github.com/openstack-experimental/keystone/pull/676))
- Add basic healthcheck endpoint ([#671](https://github.com/openstack-experimental/keystone/pull/671))
- Add raft support under skaffold ([#667](https://github.com/openstack-experimental/keystone/pull/667))
- Introduce raft backend for webauthn ([#658](https://github.com/openstack-experimental/keystone/pull/658))
- Make raft storage available through state ([#657](https://github.com/openstack-experimental/keystone/pull/657))
- Introduce the keystone-manage cli managing raft ([#656](https://github.com/openstack-experimental/keystone/pull/656))

### Other

- Small optimization of the derives ([#638](https://github.com/openstack-experimental/keystone/pull/638))
- Split the core-types crate ([#640](https://github.com/openstack-experimental/keystone/pull/640))
- Split out remaining sql drivers ([#633](https://github.com/openstack-experimental/keystone/pull/633))
- Split more drivers to separate crates ([#632](https://github.com/openstack-experimental/keystone/pull/632))
- Split config into standalone crate ([#628](https://github.com/openstack-experimental/keystone/pull/628))
- Make assignment sql driver a standalone crate ([#626](https://github.com/openstack-experimental/keystone/pull/626))
- Move assignment parameters resolution to driver ([#625](https://github.com/openstack-experimental/keystone/pull/625))
- Introduce features in api-types crate ([#624](https://github.com/openstack-experimental/keystone/pull/624))
- Slim down api-types crate ([#622](https://github.com/openstack-experimental/keystone/pull/622))
- Split out webauthn into crate ([#621](https://github.com/openstack-experimental/keystone/pull/621))
- Split out token-fernet driver ([#620](https://github.com/openstack-experimental/keystone/pull/620))
- Prepare slit out of the FernetTokenProvider ([#619](https://github.com/openstack-experimental/keystone/pull/619))
- Move benchmark into the proper crate ([#614](https://github.com/openstack-experimental/keystone/pull/614))
