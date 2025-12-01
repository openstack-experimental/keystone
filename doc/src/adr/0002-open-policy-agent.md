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

2. For `Show` operation the policy MUST receive the current record as the target
   (fetch the record and pass it into the policy engine).

3. `Update` operation MUST receive current and new state of the resource (first
   the current resource is fetched and passed together with the new state
   [current, target] to the policy engine).

4. `Create` operation works similarly as current oslo.policy with the desired
   state passed to the policy engine.

5. `Delete` operation MUST pass the current resource state of the resource into
   the policy engine.

## Decision

The only policy enforcement engine supported in the Keystone is Open Policy
Engine.

## Consequences

- Policy evaluation requires external service (OPA) to be running.

- When covering existing functionality of the python Keystone policies SHOULD be
  converted as is and do not introduce a changed flow.
