# API policy enforcement

API policy is implemented using the
[Open Policy Agent (OPA)](https://openpolicyagent.org). It is a very powerful
tool and allows implementing policies much more complex than what the
`oslo.policy` would ever allow. The `policy` folder contain default policies.
They can be overloaded by the deployment.

OPA can be integrated into Keystone in 2 ways:

- HTTP. This is a default and recommended way of integrating applications with
  the OPA. Usually the OPA process is started as a side car container to keep
  network latencies as low as possible. Policies themselves are bundled into the
  container which OPA process is capable of downloading and even periodically
  refreshing. It can be started as
  `opa run -s --log-level debug tools/opa-config.yaml`. Alternatively the OPA
  process can itself run in the container in which case the configuration file
  should be mounted as a volume and referred from the entrypoint.

- WASM. Policies can be built into a WASM binary module. This method does not
  support feeding additional data and dynamic policy reload as of now.
  Unfortunately there is also a memory access violation error in the `wasmtime`
  crate happening for the big policy files. The investigation is in progress, so
  it is preferred not to rely on this method anyway. While running OPA as a WASM
  eliminates any networking communication, it heavily reduces feature set. In
  particular hot policy reload, decision logging, external calls done by the
  policies themselves are not possible by design. Using this way of policy
  enforcement requires `wasm` feature enabled.

All the policies currently are using the same policy names and definitions as
the original Keystone to keep the deviation as less as possible. For the newly
added APIs this is not anymore the case.

With the Open Policy Agent it is not only possible to define a decision (allowed
or forbidden), but also to produce additional information describing i.e. reason
of the request refusal. This is currently being used by the policies by defining
an array of "violation" objects explaining missing permissions.

Sample policy for updating the federated IDP mapping:

```rego
package identity.mapping_update

# update mapping.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	own_mapping
	"manager" in input.credentials.roles
}

own_mapping if {
	input.target.domain_id != null
	input.target.domain_id == input.credentials.domain_id
}

violation contains {"field": "domain_id", "msg": "updating mapping for other domain requires `admin` role."} if {
	identity.foreign_mapping
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "updating global mapping requires `admin` role."} if {
	identity.global_mapping
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "updating mapping requires `manager` role."} if {
	identity.own_mapping
	not "member" in input.credentials.roles
}
```

As can be guessed such policy would permit the API request when `admin` role is
present in the current credentials roles or the mapping in scope is owned by the
domain the user is currently scoped to with the `manager` role.`

## List operation

All query parameters are passed into the policy engine to be provide capability
of making decision based on the parameters passed. For example an admin user may
specify `domain_id` parameter when the current authentication scope is not
matching the given `domain_id` or a user with the `manager` role being able to
list shared federated identity providers.

Policy is being evaluated before the real data is being fetched from the
backend.

## Show operation

Policy evaluation for GET operations on the resource are executed with the
requested entity in the scope. This allows policy to deny the operation if the
user requested resource it is should not have access to. This means that 404
error may be raised before the validation of whether the user is allowed to
perform such operations.

## Create operation

Resource creation operation would pass the whole object to be created in the
context to the policy enforcement engine.

## Update operation

For the update operation the context contain the current state of the resource
and the new one. This allows defining policies preventing resource update upon
certain conditions (i.e. when tag "locked" is added).

## Delete operation

Resource deletion also passes the current resource state in the context to allow
comprehensive logic.
