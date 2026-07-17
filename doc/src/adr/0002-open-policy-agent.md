# 2. Open Policy Agent

Date: 2025-11-03

## Status

Accepted

## Context

Use of oslo.policy is not easily possible from Rust. In addition to that during
the OpenStack Summit 2025 it
[was shown](https://www.youtube.com/watch?v=_B4Zsd8RG88&list=PLKqaoAnDyfgr91wN_12nwY321504Ctw1s&index=33)
how Open Policy Agent can be used to further improve the policy control in
OpenStack. As such the Keystone implement the policy enforcement using the OPA
with the following rules:

1. `List` operation MUST receive the all query parameters of the operation in
   the target.

2. For `Show` operation the policy MUST receive the current record as the
   `existing` (fetch the record and pass it into the policy engine); `target` is
   `null`.

3. `Update` operation MUST receive current and new state of the resource (first
   the current resource is fetched and passed as `existing` together with the
   new state as `target` to the policy engine).

4. `Create` operation works similarly as current oslo.policy with the desired
   state passed to the policy engine as `target`.

5. `Delete` operation MUST pass the current resource state of the resource into
   the policy engine as `existing`; `target` is `null`.

## Decision

The only policy enforcement engine supported in the Keystone is Open Policy
Engine.

## Consequences

- Policy evaluation requires external service (OPA) to be running.

- When covering existing functionality of the python Keystone policies SHOULD be
  converted as is and do not introduce a changed flow.

## Standardized Policy Input Structure

The `PolicyEnforcer` interface is standardized with the following signature:

```rust
async fn enforce(
    &self,
    policy_name: &'static str,
    credentials: &ValidatedSecurityContext,
    target: Value,
    existing: Option<Value>,
) -> Result<PolicyEvaluationResult, PolicyError>;
```

The OPA input document structure is:

```json
{
  "credentials": { "user_id": "...", "roles": [...], "domain_id": "...", ... },
  "target": {
    "<resource>": <object or null>
  },
  "existing": {
    "<resource>": <object or null>
  }
}
```

The `<resource>` key matches the REST resource type: `user`, `group`, `role`,
`project`, `instance`, `idp`, `mapping`, `restriction`, `assignment`, etc. This
prevents field name collisions between policies and ensures each resource's data
is properly isolated.

### Field Semantics Per Operation

The `<resource>` key matches the REST resource type:

- `user`, `group`, `role`, `project`, `instance`, `idp`, `mapping`,
  `restriction`, `assignment`, etc.
- This isolates data and prevents field name collisions between different
  resource schemas.

Policies read fields as `input.target.user.domain_id`,
`input.existing.restriction.user_id`, `input.target.instance.name`, etc.

Examples:

- Create user: `{"target": {"user": request_payload}}`
- Update restriction:
  `{"target": {"restriction": patch}, "existing": {"restriction": stored}}`
- Show group: `{"target": null, "existing": {"group": stored_object}}`
- List instances: `{"target": {"instance": query_params}}`

### Implementation Details

The handler-side contract for `enforce()`:

- **Create**: Pass `serde_json::to_value(request_object)?` as target, `None` as
  existing
- **Update**: Pass `serde_json::to_value(patch)?` as target,
  `Option::from(stored_object).map(serde_json::to_value)` as existing
- **Show**: Pass `Value::Null` as target,
  `Option::from(stored_object).map(serde_json::to_value)` as existing
- **Delete**: Pass `Value::Null` as target,
  `Option::from(stored_object).map(serde_json::to_value)` as existing
- **List**: Pass `serde_json::to_value(query_params)?` as target, `None` as
  existing

### Policy Evaluation Guidelines

Ownership predicates that need to work across create/show/delete/update should
resolve the `domain_id` from either target or existing:

```rego
# Resolve domain_id from target or existing depending on operation
resource_domain_id := input.target.domain_id if {
    input.target.domain_id
}
resource_domain_id := input.existing.domain_id if {
    input.existing.domain_id
}

own_resource if {
    resource_domain_id != null
    resource_domain_id == input.credentials.domain_id
}
```

Validation rules (checking user-provided data for referential integrity, e.g.,
that domain/project/role IDs exist) should read from `input.target` for both
create and update operations, as `target` carries the user's request in both
cases.

### Notes

- The `input.existing` field is `Value::Null` when passed as `None` from the
  handler, not an absent key. Policies can check `input.existing == null`.

- The `input.target` field is `Value::Null` for `Show` and `Delete`, since there
  is no new/desired state in those operations — the current record is passed as
  `existing` instead, never as `target`.

- Policy tests (`*_test.rego`) should use the same input structure as handlers:
  - Create tests: `"target": { "binding": { ... } }`
  - Update tests:
    `"target": { "binding": { ... } }, "existing": { "binding": { ... } }`
  - Show/Delete tests: `"target": null, "existing": { "binding": { ... } }`
