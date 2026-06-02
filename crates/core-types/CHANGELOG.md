# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-core-types-v0.1.1) - 2026-06-02

### Added

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

### Other

- Redesign SecurityContext with two-phase validation ([#717](https://github.com/openstack-experimental/keystone/pull/717))
- Unify state initialization in test ([#642](https://github.com/openstack-experimental/keystone/pull/642))
- Small optimization of the derives ([#638](https://github.com/openstack-experimental/keystone/pull/638))
- Split the core-types crate ([#640](https://github.com/openstack-experimental/keystone/pull/640))
