# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0](https://github.com/openstack-experimental/keystone/releases/tag/openstack-keystone-telemetry-v0.1.0) - 2026-11-01

### Added

- Make TLS and storage crypto provider selectable ([#1543](https://github.com/openstack-experimental/keystone/pull/1543))
- Enable OpenTelemetry metrics and traces support ([#1456](https://github.com/openstack-experimental/keystone/pull/1456))

### Fixed

- *(telemetry)* Use native roots for OTLP gRPC TLS ([#1604](https://github.com/openstack-experimental/keystone/pull/1604))
