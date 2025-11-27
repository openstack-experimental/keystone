# 8. Workload Federation

Date: 2025-11-03

## Status

Accepted

## Context

It is often desired to access the OpenStack cloud from workloads (i.e. GitHub
workflow, Zuul job, etc). Usually such services provide a JWT issued by the
platform which the service provider can trust. This is very similar (and
technically relates) to the OIDC standard.

In the JWT flow the "user" is exchanging a JWT token issued by the trusted
IdP for a Keystone token. This authentication response includes a token and a
service catalog to provide a known OpenStack usage scenario.

## Decision

OIDC mappings MUST specify a `type` which is `oidc` or `jwt` to specify the
flow they define. A `jwt` type mapping can be only used in the JWT flow.

The new authentication API includes the IdP ID. The authentication request does
not support the Json request body and uses a generic `authorization: bearer
<jwt>` header and `openstack-mapping-name: <mapping_name>` to request the
information. Depending on the mapping configuration the desired authorization
scope is returned. The flow does not support explicitly requesting the scope
beyond what is described by the mapping.


## Consequences

- A new API to exchange JWT token for the Keystone token is added.

- JWT auth must provide the mapping name.

- The mapping SHOULD point to some for of the technical user.
