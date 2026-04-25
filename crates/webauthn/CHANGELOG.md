# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-webauthn-v0.1.0) - 2026-04-25

### Added

- Add k8s-auth raft driver ([#676](https://github.com/openstack-experimental/keystone/pull/676))
- Add metadata for raft data ([#670](https://github.com/openstack-experimental/keystone/pull/670))
- Add raft support under skaffold ([#667](https://github.com/openstack-experimental/keystone/pull/667))
- Introduce raft backend for webauthn ([#658](https://github.com/openstack-experimental/keystone/pull/658))

### Other

- Split the core-types crate ([#640](https://github.com/openstack-experimental/keystone/pull/640))
- Move assignment parameters resolution to driver ([#625](https://github.com/openstack-experimental/keystone/pull/625))
- Introduce features in api-types crate ([#624](https://github.com/openstack-experimental/keystone/pull/624))
- Split out webauthn into crate ([#621](https://github.com/openstack-experimental/keystone/pull/621))
