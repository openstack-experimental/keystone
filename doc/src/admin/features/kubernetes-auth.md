# Kubernetes TokenReview Administration

Operators and domain administrators register Kubernetes clusters as
authentication instances. Workloads then exchange their service-account JWTs
through the user-facing authentication endpoint documented in the
[Kubernetes authentication guide](../../user/features/kubernetes-auth.md).

## Register an authentication instance

Create instances under `/v4/k8s_auth/instances`. Each instance records:

| Field | Purpose |
| --- | --- |
| `domain_id` | Domain that owns the authentication instance. |
| `host` | Base URL of the Kubernetes API server. |
| `ca_cert` | Optional PEM CA certificate for the Kubernetes API. |
| `disable_local_ca_jwt` | Disable fallback to the in-cluster CA certificate. |
| `enabled` | Allow or deny authentication through the instance. |
| `name` | Optional operator-facing name. |

For example:

```json
{
  "instance": {
    "domain_id": "domain-infra",
    "host": "https://kubernetes.default.svc",
    "ca_cert": null,
    "disable_local_ca_jwt": false,
    "enabled": true,
    "name": "production-cluster"
  }
}
```

Use the instance API to manage registrations:

| Action | Endpoint |
| --- | --- |
| Create or list | `POST` or `GET /v4/k8s_auth/instances` |
| Show, update, or delete | `GET`, `PATCH`, or `DELETE /v4/k8s_auth/instances/{instance_id}` |

The current request and response schemas are available in the
[OpenAPI reference](../../swagger-ui.html).

## Kubernetes API permissions

Keystone sends the workload's JWT both in the TokenReview request and as the
bearer credential for that Kubernetes API call. Bind workloads that use this
flow to a role that permits creation of
`tokenreviews.authentication.k8s.io`, normally `system:auth-delegator`.

When `ca_cert` is omitted and `disable_local_ca_jwt` is `false`, Keystone reads
the Kubernetes service-account CA certificate from its local pod filesystem.
Set `ca_cert` explicitly for a remote cluster or when the local CA does not
represent the registered API server.

## Configure identity mapping

Every enabled instance needs an enabled mapping ruleset whose source type is
`k8s` and whose `cluster_id` identifies that instance. Domain managers can
match these claims:

- `k8s.serviceaccount.name`
- `k8s.serviceaccount.namespace`
- `k8s.aud`

Rules define the resulting virtual user, scope, roles, and groups. Keep cluster
registration and authorization rules separate: operators maintain connectivity
and CA trust, while authorized domain managers maintain mappings through
`/v4/mappings/rulesets`.

See [Identity Mapping Administration](identity-mapping.md) for cluster-wide
configuration and [Identity Mapping Rules and API](../../user/features/identity-mapping.md)
for rule syntax and Kubernetes examples.

## Operational checklist

1. Verify the Kubernetes API URL and CA chain from every Keystone node.
2. Restrict instance management with OPA policy.
3. Confirm the workload can create TokenReview requests before enabling it.
4. Create and review the domain's Kubernetes mapping ruleset.
5. Test with a short-lived projected service-account token.
6. Disable the instance before changing its API host or trust configuration.
