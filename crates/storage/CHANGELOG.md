# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/openstack-experimental/keystone/compare/openstack-keystone-distributed-storage-v0.1.0...openstack-keystone-distributed-storage-v0.1.1) - 2026-04-25

### Added

- Add k8s-auth raft driver ([#676](https://github.com/openstack-experimental/keystone/pull/676))
- Add SetIndex/RemoveIndex storage commands ([#675](https://github.com/openstack-experimental/keystone/pull/675))
- Add basic healthcheck endpoint ([#671](https://github.com/openstack-experimental/keystone/pull/671))
- Add metadata for raft data ([#670](https://github.com/openstack-experimental/keystone/pull/670))
- Add transaction support for Raft storage ([#669](https://github.com/openstack-experimental/keystone/pull/669))
- Add initial benchmarks for the storage ([#668](https://github.com/openstack-experimental/keystone/pull/668))
- Add raft support under skaffold ([#667](https://github.com/openstack-experimental/keystone/pull/667))
- Introduce raft backend for webauthn ([#658](https://github.com/openstack-experimental/keystone/pull/658))
- Prepare raft storage promotion ([#659](https://github.com/openstack-experimental/keystone/pull/659))
- Make raft storage available through state ([#657](https://github.com/openstack-experimental/keystone/pull/657))
- Introduce the keystone-manage cli managing raft ([#656](https://github.com/openstack-experimental/keystone/pull/656))

### Other

- *(deps)* Bump openraft to alpha17 ([#641](https://github.com/openstack-experimental/keystone/pull/641))
