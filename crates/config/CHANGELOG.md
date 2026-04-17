# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-config-v0.1.0) - 2026-04-17

### Added

- Add raft support under skaffold ([#667](https://github.com/openstack-experimental/keystone/pull/667))
- Introduce raft backend for webauthn ([#658](https://github.com/openstack-experimental/keystone/pull/658))
- Introduce the keystone-manage cli managing raft ([#656](https://github.com/openstack-experimental/keystone/pull/656))

### Other

- Split out remaining sql drivers ([#633](https://github.com/openstack-experimental/keystone/pull/633))
- Split config into standalone crate ([#628](https://github.com/openstack-experimental/keystone/pull/628))
