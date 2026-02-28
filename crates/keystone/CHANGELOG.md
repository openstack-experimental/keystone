# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.2](https://github.com/openstack-experimental/keystone/compare/openstack_keystone-v0.1.1...openstack_keystone-v0.1.2) - 2026-02-28

### Added

- Implement k8s auth api test ([#579](https://github.com/openstack-experimental/keystone/pull/579))
- Add k8s_auth api ([#580](https://github.com/openstack-experimental/keystone/pull/580))
- Implement k8s auth provider api ([#578](https://github.com/openstack-experimental/keystone/pull/578))
- Implement k8s auth provider ([#567](https://github.com/openstack-experimental/keystone/pull/567))
- Spit role from assignment provider ([#565](https://github.com/openstack-experimental/keystone/pull/565))
- Add raft backed distributed storage ([#556](https://github.com/openstack-experimental/keystone/pull/556))
- Create revoke event after revoke grant ([#555](https://github.com/openstack-experimental/keystone/pull/555))
- Implement trust token validation ([#484](https://github.com/openstack-experimental/keystone/pull/484))

### Fixed

- Prevent endless extending token ([#564](https://github.com/openstack-experimental/keystone/pull/564))

### Other

- Remove one level of errors ([#575](https://github.com/openstack-experimental/keystone/pull/575))
- Introduce k3s test ([#571](https://github.com/openstack-experimental/keystone/pull/571))
- Switch functional tests to keystone_api_types ([#574](https://github.com/openstack-experimental/keystone/pull/574))
- Split api types into a separate crate ([#572](https://github.com/openstack-experimental/keystone/pull/572))
- *(deps)* Upgrade rand to 0.10 and uuid to 0.21 ([#563](https://github.com/openstack-experimental/keystone/pull/563))
- Convert project to the crate workspace ([#554](https://github.com/openstack-experimental/keystone/pull/554))
