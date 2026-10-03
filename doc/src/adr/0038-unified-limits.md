# 38. Unified Limits

**Date:** 2026-10-03

## Status

Accepted.

## Reference

Closes the "Limits" gap of the Python API compatibility list (#938, #1091).

## Context

Python Keystone exposes the "Unified Limits" API: operator defined
`registered_limits` (service wide default for a resource), per project or
domain `limits` that override the default, and a read-only enforcement model
discovery. Consumers (oslo.limit, Nova, Glance, ...) rely on it.

## Decision

A new `limit` provider (`crates/core/src/limit`) with a pluggable backend and
an SQL driver (`crates/limit-driver-sql`) is added. The SQL driver reuses the
Python tables (`registered_limit`, `limit`) and therefore creates them through
entity synchronisation (`keystone-manage db sync`), never through versioned
migrations.

### API (v3, Python compatible)

| Endpoint | Operations |
| --- | --- |
| `/v3/registered_limits` | list (filters `service_id`, `region_id`, `resource_name`), batch create |
| `/v3/registered_limits/{id}` | show, update, delete |
| `/v3/limits` | list (filters additionally `project_id`, `domain_id`), batch create |
| `/v3/limits/{id}` | show, update, delete |
| `/v3/limits/model` | enforcement model discovery |

### Behaviour

- Limit values are integers in `[-1, 2147483647]`.
- Referenced service, region, project and domain must exist (HTTP 400).
  A `project_id` referencing a domain-project is stored as `domain_id`.
- Registered limits are unique by `(service_id, resource_name, region_id)`,
  limits are unique per registered limit and project or domain (HTTP 409).
- A limit refers to the registered limit with identical service, resource
  name and region. Absence of one is an error (HTTP 400).
- A registered limit referenced by limits can neither be updated nor deleted.
- Batch creation is atomic.
- Update applies explicitly provided values, including `0` and an empty
  description (Python silently ignores falsy values).
- Enforcement model (`[limit] enforcement_model`): `flat` (default) or
  `strict_two_level` (project limit may not exceed the limit of the parent
  domain, domain limit may not be below any of its projects' limits).
- Visibility of limits in the list is bound to the token scope: system scope or
  `admin` see everything, a domain scope sees limits of the domain and its
  projects, a project scope sees limits of the project only. Every list item is
  re-checked with the `show` policy.

### Policies

`identity/registered_limit/{create,list,show,update,delete}`,
`identity/limit/{create,list,show,update,delete,model}`. Mutations require the
`admin` role (or system admin), reads are allowed for any authenticated user
with the scope restrictions described above.
