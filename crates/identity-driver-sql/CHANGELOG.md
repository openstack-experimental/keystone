# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-identity-driver-sql-v0.1.0) - 2026-07-02

### Added

- *(auth)* Password hashing parity with Python Keystone ([#859](https://github.com/openstack-experimental/keystone/pull/859))
- *(mapping)* ADR-0020 (mapping engine) phase 1 ([#794](https://github.com/openstack-experimental/keystone/pull/794))
- Add inter-provider event notification system ([#784](https://github.com/openstack-experimental/keystone/pull/784))
- Add timing attack protection and failed auth tracking ([#758](https://github.com/openstack-experimental/keystone/pull/758))
- Add role-imply rest api ([#750](https://github.com/openstack-experimental/keystone/pull/750))
- Add user update functionality ([#747](https://github.com/openstack-experimental/keystone/pull/747))
- Make drivers more dynamic ([#737](https://github.com/openstack-experimental/keystone/pull/737))

### Fixed

- Validate password complexity before storing password ([#845](https://github.com/openstack-experimental/keystone/pull/845))
- Align "extra" property handling ([#787](https://github.com/openstack-experimental/keystone/pull/787))

### Other

- Move jsonwebtoken to keystone crate ([#820](https://github.com/openstack-experimental/keystone/pull/820))
- Consolidate password update flows ([#778](https://github.com/openstack-experimental/keystone/pull/778))
- Further align workspace features ([#772](https://github.com/openstack-experimental/keystone/pull/772))
