# 15. Kubernetes Authentication Mechanism for Keystone

Date: 2026-02-17

## Status

Accepted

## Context

Currently, Keystone supports various authentication mechanisms (Password, Token,
TOTP, External, etc.). As OpenStack increasingly runs alongside or underneath
Kubernetes workloads, there is a need for "machine authentication" where a
Kubernetes Pod can exchange its **Service Account Token (JWT)** for a Keystone
token without managing long-lived secrets like passwords or API keys.

This implementation follows the logic used by OpenBao:

1. **Trust Establishment:** Keystone is configured to trust a Kubernetes API
   server's JWT issuer.
2. **Role Mapping:** A Kubernetes Service Account (and namespace) is mapped to a
   specific Keystone Project/Role.
3. **Validation:** Keystone validates the incoming JWT against the Kubernetes
   TokenReview API.

## Decision

We will implement a new `kubernetes` auth method in Keystone. This requires
persistent storage to manage multiple Kubernetes clusters (backends) and the
mapping of Kubernetes identities to OpenStack identities.

### 1. Data Model Changes

Two new tables will be introduced to the Keystone schema.

#### Table: `kubernetes_auth`

This table stores the configuration for connecting to and validating tokens from
external Kubernetes clusters.

| Column               | Type        | Description                                                           |
| -------------------- | ----------- | --------------------------------------------------------------------- |
| `id`                 | String(64)  | Primary Key (UUID).                                                   |
| `domain_id`          | String(64)  | Domain ID (UUID).                                                     |
| `enabled`            | Boolean     | Enabled flag.                                                         |
| `name`               | String(255) | Unique name for this K8s backend configuration.                       |
| `host`               | String(255) | The URL of the Kubernetes API server (e.g., `https://10.0.0.1:6443`). |
| `token_reviewer_jwt` | Text        | A long-lived JWT used by Keystone to access the K8s TokenReview API.  |
| `ca_cert`            | Text        | PEM encoded CA cert for the K8s API (optional for self-signed).       |

#### Table: `kubernetes_auth_role`

This table maps Kubernetes-specific attributes (Namespace/ServiceAccount) to
Keystone-specific token restriction (User/Project/Roles).

| Column                             | Type        | Description                                           |
| ---------------------------------- | ----------- | ----------------------------------------------------- |
| `id`                               | String(64)  | Primary Key (UUID).                                   |
| `kubernetes_id`                    | String(64)  | Foreign Key to `kubernetes_auth.id`.                  |
| `enabled`                          | Boolean     | Enabled flag.                                         |
| `token_restriction_id`             | String(64)  | Foreign Key to `token_restriction.id`.                |
| `bound_service_account_names`      | Text        | List of allowed SAs (comma-separated or JSON).        |
| `bound_service_account_namespaces` | Text        | List of allowed Namespaces (comma-separated or JSON). |
| `bound_audience`                   | String(128) | Optional Audience claim to verify in the JWT.         |

Token Restrictions represent here a finite mapping of the `user_id` (which
should point to the service account user and MUST be set), the target project
(based on the `project_id`) and the corresponding roles granted on this scope.
As such it is not required to grant the user roles on the project directly and
instead only specify them in the token restriction mapping.

---

### 2. Required API

#### Administrative API (CRUD for Configuration)

Admin-only endpoints to manage the trust relationship.

- **POST** `/v4/k8s_auth/`: Register a new Kubernetes cluster.
- **GET/PATCH/DELETE** `/v4/k8s_auth/{cluster_id}`: Manage cluster config.
- **POST** `/v4/k8s_auth/{cluster_id}/roles/role`: Create a mapping between a
  K8s SA/Namespace and a Keystone Project.
- **GET/PATCH/DELETE** `/v4/k8s_auth/{cluster_id}/roles/{role_name}`: Manage
  role mappings.
- **POST** `/v4/k8s_auth/{cluster_id}/auth`: Exchange K8s SA token for Keystone
  token.

#### Authentication API (The "Login" Flow)

The new authentication endpoint is exposed under
`/v4/k8s_auth/{cluster_id}/auth` and expects a json payload with a **POST**
method.

**Request Payload:**

```json
{
  "k8s_role": "web-servers-role",
  "jwt": "<jwt_from_k8s_service_account_token_volume_projection>"
}
```

---

### 3. Authentication Workflow

1. **Lookup:** Keystone receives the request, identifies the `role`. It fetches
   the associated `kubernetes_auth` config.
2. **Verification:** Keystone calls the Kubernetes API (`host`) at the
   `/apis/authentication.k8s.io/v1/tokenreviews` endpoint using the
   `token_reviewer_jwt` or the user specified `jwt` when `token_reviewer_jwt` is
   unset. In the later case it is required that the service account has the
   `system:auth-delegator` ClusterRole. It can be granted with

```
kubectl create clusterrolebinding client-auth-delegator \
  --clusterrole=system:auth-delegator \
  --group=group1 \
  --serviceaccount=default:svcaccount1 ...
```

3. **Validation:**

- K8s returns the status of the JWT.
- Keystone verifies that the `kubernetes.io/serviceaccount/service-account.name`
  and `namespace` claims match the `bound_service_account_names` and
  `namespaces` in the `kubernetes_auth_role` table.

4. **Token Issuance:** If valid, Keystone issues a scoped token for the
   `token_restriction_id` defined in the role mapping.

## Consequences

- **Pros:**
  - Enables seamless "Secretless" authentication for workloads running on
    Kubernetes.
  - Matches industry standards set by OpenBao/Vault.
  - Supports multi-tenancy by allowing multiple Kubernetes clusters to connect
    to one Keystone.

- **Cons:**
  - Keystone must have network line-of-sight to the Kubernetes API server.
  - Adds complexity to the identity backend.
