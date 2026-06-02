# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-config-v0.1.0) - 2026-06-02

### Added

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

### Other

- Redesign SecurityContext with two-phase validation ([#717](https://github.com/openstack-experimental/keystone/pull/717))
- Split out remaining sql drivers ([#633](https://github.com/openstack-experimental/keystone/pull/633))
- Split config into standalone crate ([#628](https://github.com/openstack-experimental/keystone/pull/628))
