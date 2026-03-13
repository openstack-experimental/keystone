# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-v0.1.1) - 2026-03-13

### Added

- Further streamline policy enforcing ([#612](https://github.com/openstack-experimental/keystone/pull/612))
- Drop PolicyFactory mutability ([#611](https://github.com/openstack-experimental/keystone/pull/611))
- Integration test for verifying grant revocation ([#573](https://github.com/openstack-experimental/keystone/pull/573))
- Add delete_role provider api ([#605](https://github.com/openstack-experimental/keystone/pull/605))
- Add delete_domain provider api ([#604](https://github.com/openstack-experimental/keystone/pull/604))
- Add create_domain provider ([#603](https://github.com/openstack-experimental/keystone/pull/603))
- Implement k8s auth api test ([#579](https://github.com/openstack-experimental/keystone/pull/579))
- Add k8s_auth api ([#580](https://github.com/openstack-experimental/keystone/pull/580))
- Implement k8s auth provider api ([#578](https://github.com/openstack-experimental/keystone/pull/578))
- Implement k8s auth provider ([#567](https://github.com/openstack-experimental/keystone/pull/567))
- Spit role from assignment provider ([#565](https://github.com/openstack-experimental/keystone/pull/565))
- Add raft backed distributed storage ([#556](https://github.com/openstack-experimental/keystone/pull/556))
- Create revoke event after revoke grant ([#555](https://github.com/openstack-experimental/keystone/pull/555))
- Implement trust token validation ([#484](https://github.com/openstack-experimental/keystone/pull/484))
- Improve documentation ([#243](https://github.com/openstack-experimental/keystone/pull/243))
- Init loadtest

### Fixed

- *(roles)* Differentiate token roles ([#601](https://github.com/openstack-experimental/keystone/pull/601))
- Prevent endless extending token ([#564](https://github.com/openstack-experimental/keystone/pull/564))
- Another broken link to doc ([#337](https://github.com/openstack-experimental/keystone/pull/337))
- Build the ADRs in doc ([#321](https://github.com/openstack-experimental/keystone/pull/321))

### Other

- Make token_restriction a driver ([#610](https://github.com/openstack-experimental/keystone/pull/610))
- Rename crates to be dash-separated ([#609](https://github.com/openstack-experimental/keystone/pull/609))
- Improve revocation integration test ([#606](https://github.com/openstack-experimental/keystone/pull/606))
- Use role provider from drivers ([#594](https://github.com/openstack-experimental/keystone/pull/594))
- Introduce "guard" for api test suite ([#587](https://github.com/openstack-experimental/keystone/pull/587))
- Remove one level of errors ([#575](https://github.com/openstack-experimental/keystone/pull/575))
- Introduce k3s test ([#571](https://github.com/openstack-experimental/keystone/pull/571))
- Switch functional tests to keystone_api_types ([#574](https://github.com/openstack-experimental/keystone/pull/574))
- Split api types into a separate crate ([#572](https://github.com/openstack-experimental/keystone/pull/572))
- *(deps)* Upgrade rand to 0.10 and uuid to 0.21 ([#563](https://github.com/openstack-experimental/keystone/pull/563))
- Convert project to the crate workspace ([#554](https://github.com/openstack-experimental/keystone/pull/554))
- Adapt docs and workflows for the new org ([#318](https://github.com/openstack-experimental/keystone/pull/318))
- *(docs)* Update load test description in the readme ([#299](https://github.com/openstack-experimental/keystone/pull/299))
- Update README.md ([#116](https://github.com/openstack-experimental/keystone/pull/116))
- Add first workflows
- Cover user list/show
