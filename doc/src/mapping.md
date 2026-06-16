# Identity Mapping Engine

The Identity Mapping Engine is a unified framework used by Keystone to resolve
external identities (from various authentication sources) into internal Keystone
principals and security contexts. Instead of hardcoding authentication logic for
each provider, the mapping engine uses a set of configurable rules to determine
how an external identity should be mapped.

## Concept

The mapping engine decouples the **authentication** phase (verifying who the
user is) from the **authorization** phase (determining what the user is in
Keystone).

When an authentication request is received, the identity provider extracts
"claims" (attributes about the identity) and passes them along with the source
of the identity to the Mapping Engine. The engine evaluates these against a set
of **Rulesets**. The first matching rule defines:

- The **Principal** (user or group) to be mapped to.
- The **Scope** and **Role** associations for the resulting token.

This allows administrators to dynamically change how external identities are
mapped to internal users without changing code or reconfiguring the
authentication providers.

## Rule Structure

A `MappingRuleSet` contains an ordered list of `MappingRule`s. The engine
iterates through these rules in sequence and applies the first rule that
satisfies its match criteria. Each rule consists of:

- **Match Criteria**: A nested boolean expression tree evaluating claims.
- **Identity Binding**: Defines the target Keystone user (`user_name`,
  `user_id`, `user_domain_id`) using optional template interpolation.
- **Authorizations**: Roles granted at the System, Domain, or Project level.
- **Group Assignments**: Groups the identity should be mapped to, with
  configurable resolution strategy.

### Match Criteria

Match criteria define the boolean logic for evaluating conditions:

- **`AllOf`**: All conditions must match.
- **`AnyOf`**: At least one condition must match.
- **`AllOfStrict`**: All conditions must match, with an optional
  `require_all_keys` flag. When enabled, the engine verifies that all claim keys
  referenced in the criteria are present in the claims map. This prevents
  claim-suppression attacks where an attacker omits claims to bypass
  higher-priority rules.

### Match Conditions

A match condition can be either:

- **`Condition`**: A leaf-level claim assertion (see Claim Conditions below).
- **`Nested`**: A sub-group of `MatchCriteria`, allowing complex boolean
  nesting.

### Claim Conditions

A claim condition evaluates a specific claim key against a target value. Each
condition must specify `claim` (the key to look up in the claims map):

- **`Equals`**: The claim value must equal the specified `value`. JSON
  primitives (numbers, booleans) are normalized to strings for comparison.
- **`AnyOf`**: The claim value must match at least one value in the `values`
  array.
- **`MatchesRegex`**: The claim value must match the given `regex` pattern.
  Regex patterns are cached with a 1024-entry LRU limit.

### Identity Binding & Template Interpolation

The identity binding defines the resulting Keystone principal:

- **`user_name`** (required): String identifying the user. Supports template
  interpolation.
- **`user_id`** (optional): Explicit user identifier. Supports template
  interpolation.
- **`user_domain_id`** (optional): Domain context for the user. Supports
  template interpolation, subject to `DomainResolutionMode` constraints.
- **`is_system`** (default false): When true, grants system-level privileges.
  Rulesets containing system bindings are treated as immutable system mappings
  after creation.

**Template Interpolation**

Identity fields support two template tokens:

- **`${claims.<key>}`**: Replaces with the first value from the claims map for
  the given key. Unresolved keys leave the token intact.
- **`${enclosing_domain_id}`**: Replaces with the ruleset's enclosing domain ID.

Templates are limited to 256 characters after resolution and cannot reference
reserved keys (e.g., `enclosing_domain_id` is blocked in `${claims.*}` syntax to
prevent context shadowing).

### Authorizations

Roles are assigned at one of three scope levels:

- **`System`**: Grants roles at the system scope (requires `is_system: true`).
  Requires `system_id` (typically `"all"`) and `roles`.
- **`Domain`**: Grants roles on a specific domain. Requires `domain_id` and
  `roles`.
- **`Project`**: Grants roles on a specific project. Requires `project_id`,
  `project_domain_id`, and `roles`.

Role references support both `id` and `name` lookups.

### Group Assignments

Group assignments map the external identity to localized Keystone groups:

- **`group_id`** (required): Immutable group identifier.
- **`group_name`** (required): Group name, supports template interpolation.
- **`group_domain_id`** (optional): Domain containing the group.
- **`strategy`** (default `CreateOrGet`):
  - **`CreateOrGet`**: Creates the group if it does not exist, or retrieves the
    existing one.
  - **`Get`**: Only retrieves an existing group; fails if the group is missing.

## Domain Resolution Modes

Each ruleset specifies how the domain context for the resolved principal is
determined:

- **`Fixed`** (default): Domain is fixed to the `domain_id` on the ruleset.
  `user_domain_id` templates cannot reference `${claims.*}` tokens.
- **`ClaimsOnly`**: Domain is resolved exclusively from claims. At least one
  rule in the ruleset must use a `${claims.*}` template in `user_domain_id`.
- **`ClaimsOrMapping`**: Domain is resolved from `user_domain_id` template
  first, falling back to the ruleset `domain_id`. Both claim templates and
  static values are permitted.

## Authentication Providers

### SPIFFE

SPIFFE (Secure Production Identity Framework for Everyone) provides a way to
identify workloads across heterogeneous environments using SVIDs (SPIFFE
Verifiable Identity Documents), typically x509 certificates.

#### Concept

SPIFFE authentication extracts the SVID from the mTLS x509 certificate and
flattens it into a claims map for the mapping engine. The source type is
`spiffe`, identified by the `trust_domain` field.

#### Claims Contract

The following claims are produced for SPIFFE identities:

- **`spiffe.id`**: Full SPIFFE ID URI (e.g.,
  `spiffe://example.org/spiffe/test-workload`).
- **`spiffe.trust_domain`**: Trust domain from the SPIFFE ID (e.g.,
  `example.org`).

#### Mapping Rule Examples

**Example 1: Map specific SPIFFE ID to a System Admin**

Grants system-level privileges to a specific administrative workload.

```json
{
  "name": "system-admin-workload",
  "match": {
    "all_of": [
      {
        "type": "condition",
        "equals": {
          "claim": "spiffe.id",
          "value": "spiffe://example.org/spiffe/admin-tool"
        }
      }
    ]
  },
  "identity": {
    "user_name": "admin-workload",
    "is_system": true
  },
  "authorizations": [
    {
      "type": "system",
      "system_id": "all",
      "roles": [{ "id": "admin", "name": "admin" }]
    }
  ],
  "groups": []
}
```

**Example 2: Map Trust Domain to a Project Role**

Broadly maps any workload from a specific trust domain into a project with a
specific role.

```json
{
  "name": "trust-domain-mapping",
  "match": {
    "all_of": [
      {
        "type": "condition",
        "equals": {
          "claim": "spiffe.trust_domain",
          "value": "example.org"
        }
      }
    ]
  },
  "identity": {
    "user_name": "external-workload-user"
  },
  "authorizations": [
    {
      "type": "project",
      "project_domain_id": "default",
      "project_id": "project-123",
      "roles": [{ "id": "member", "name": "member" }]
    }
  ],
  "groups": [
    {
      "group_id": "external-group",
      "group_name": "External Workloads",
      "strategy": { "type": "create_or_get" }
    }
  ]
}
```

**Example 3: Regex-based workload pattern matching**

Maps workloads matching a path pattern using regex.

```json
{
  "name": "dev-workloads-regex",
  "match": {
    "all_of": [
      {
        "type": "condition",
        "matches_regex": {
          "claim": "spiffe.id",
          "regex": "^spiffe://example.org/dev/.+$"
        }
      }
    ]
  },
  "identity": {
    "user_name": "dev-workload-user"
  },
  "authorizations": [
    {
      "type": "project",
      "project_domain_id": "default",
      "project_id": "dev-project",
      "roles": [{ "id": "member", "name": "member" }]
    }
  ],
  "groups": []
}
```

**Example 4: AllOfStrict with trust domain and specific path**

Prevents claim-suppression by requiring both claims to be present.

```json
{
  "name": "strict-namespace-mapping",
  "match": {
    "all_of_strict": {
      "conditions": [
        {
          "type": "condition",
          "equals": {
            "claim": "spiffe.trust_domain",
            "value": "example.org"
          }
        },
        {
          "type": "condition",
          "equals": {
            "claim": "spiffe.id",
            "value": "spiffe://example.org/production/api"
          }
        }
      ],
      "require_all_keys": true
    }
  },
  "identity": {
    "user_name": "production-api"
  },
  "authorizations": [
    {
      "type": "project",
      "project_domain_id": "default",
      "project_id": "prod-project",
      "roles": [{ "id": "member", "name": "member" }]
    }
  ],
  "groups": []
}
```

#### Usage Instructions

1. **Configure SPIFFE Trust**: Ensure the Keystone service is configured to
   trust the SPIFFE trust domain.
2. **Create Mapping Rules**: Create a mapping ruleset that targets `spiffe` source
   type with the appropriate `trust_domain`. The rules should match against
   `spiffe.id` or `spiffe.trust_domain` claims.
3. **Admin Shortcut**: To bypass the mapping engine for administrative tasks,
   configure `admin_svid` in the admin interface configuration. Requests
   presenting this SVID over the admin interface are granted system-admin
   privileges.

### Federation

Federation-based identity sources (e.g., OAuth 2.0, OIDC, SAML) authenticate via
an IdP and extract claims from the resulting security token.

#### Concept

The ingress adapter performs the cryptographic validation of the federation
token (signature verification, CRL checks, remote `TokenReview` calls) and
flattens the claims into a map. The mapping engine then resolves the identity
using the same rule-based matching as other providers. The source type is
`federation`, identified by the `idp_id` field.

#### Claims Contract

Claims are provider-dependent and vary by federation protocol. Common claims
include:

- `sub`: Subject identifier (unique to the IdP).
- `preferred_username`: Human-readable username.
- `groups`: Group memberships from the IdP.
- `email`: Email address.

#### Mapping Rule Examples

**Example 1: Map Federation User by Subject**

Resolve a specific federation user by their `sub` claim.

```json
{
  "name": "federation-subject-mapping",
  "match": {
    "all_of": [
      {
        "type": "condition",
        "equals": {
          "claim": "sub",
          "value": "federation-user-123"
        }
      }
    ]
  },
  "identity": {
    "user_name": "${claims.preferred_username}",
    "user_domain_id": "${enclosing_domain_id}"
  },
  "authorizations": [
    {
      "type": "project",
      "project_domain_id": "default",
      "project_id": "project-123",
      "roles": [{ "id": "member", "name": "member" }]
    }
  ],
  "groups": [
    {
      "group_id": "federation-users",
      "group_name": "Federation Users",
      "strategy": { "type": "create_or_get" }
    }
  ]
}
```

**Example 2: Map Federation Group Membership**

Resolve identities based on the `groups` claim.

```json
{
  "name": "federation-group-mapping",
  "match": {
    "all_of": [
      {
        "type": "condition",
        "any_of": {
          "claim": "groups",
          "values": ["engineering", "operations"]
        }
      }
    ]
  },
  "identity": {
    "user_name": "${claims.preferred_username}"
  },
  "authorizations": [
    {
      "type": "project",
      "project_domain_id": "default",
      "project_id": "shared-project",
      "roles": [{ "id": "member", "name": "member" }]
    }
  ],
  "groups": []
}
```

### Kubernetes

Kubernetes authentication validates service accounts via the Kubernetes API
server's `TokenReview` endpoint.

#### Concept

The ingress adapter verifies the Kubernetes bearer token by calling the
cluster's `TokenReview` endpoint, extracts user/group claims from the response,
and passes them to the mapping engine. The source type is `k8s`, identified by
the `cluster_id` field.

#### Claims Contract

Common claims from Kubernetes TokenReview:

- `k8s.username`: Service account or user identity.
- `k8s.groups`: Kubernetes group memberships.
- `k8s.extra`: Extra attributes from the token.

#### Mapping Rule Examples

**Example 1: Map Kubernetes Service Account by Cluster**

Map any service account from a specific cluster into a project.

```json
{
  "name": "k8s-cluster-mapping",
  "match": {
    "all_of": [
      {
        "type": "condition",
        "matches_regex": {
          "claim": "k8s.username",
          "regex": "^system:serviceaccount:\\w+/\\w+$"
        }
      }
    ]
  },
  "identity": {
    "user_name": "${claims.k8s.username}"
  },
  "authorizations": [
    {
      "type": "project",
      "project_domain_id": "default",
      "project_id": "k8s-project",
      "roles": [{ "id": "member", "name": "member" }]
    }
  ],
  "groups": [
    {
      "group_id": "k8s-sa-group",
      "group_name": "K8s Service Accounts",
      "strategy": { "type": "create_or_get" }
    }
  ]
}
```

**Example 2: Namespace-scoped Service Account with Nested Criteria**

Use nested boolean logic to match a specific namespace.

```json
{
  "name": "k8s-namespace-scoped",
  "match": {
    "all_of": [
      {
        "type": "nested",
        "any_of": [
          {
            "type": "condition",
            "equals": {
              "claim": "k8s.groups",
              "value": "system:serviceaccounts:production"
            }
          },
          {
            "type": "condition",
            "equals": {
              "claim": "k8s.groups",
              "value": "system:serviceaccounts:staging"
            }
          }
        ]
      },
      {
        "type": "condition",
        "matches_regex": {
          "claim": "k8s.username",
          "regex": "^system:serviceaccount:.*:api-server$"
        }
      }
    ]
  },
  "identity": {
    "user_name": "${claims.k8s.username}",
    "is_system": true
  },
  "authorizations": [
    {
      "type": "system",
      "system_id": "all",
      "roles": [{ "id": "admin", "name": "admin" }]
    }
  ],
  "groups": []
}
```

## Mapping API

The mapping engine is managed via the Keystone API (v4).

### RuleSet Management

| Action     | Endpoint                          | Description                                                                                                                                                                  |
| ---------- | --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Create** | `POST /v4/mapping`                | Create a new ruleset. Requires `source`, `domain_resolution_mode`, `enabled`, and `rules`.                                                                                   |
| **List**   | `GET /v4/mapping`                 | List rulesets. Filterable by `domain_id`, `enabled`, `limit`, and `marker`.                                                                                                  |
| **Show**   | `GET /v4/mapping/{mapping_id}`    | Get detailed rule definitions for a ruleset.                                                                                                                                 |
| **Update** | `PATCH /v4/mapping/{mapping_id}`  | Toggle `enabled` state, update `allowed_domains`, or replace the entire `rules` array. Immutable fields (`domain_id`, `source`, `domain_resolution_mode`) cannot be changed. |
| **Delete** | `DELETE /v4/mapping/{mapping_id}` | Remove a ruleset.                                                                                                                                                            |

### Imperative Rule Mutation

To avoid replacing the entire rules array, the API supports atomic mutations:

- **`Insert`**: Add a rule at a specific position (`before` or `after` a named
  anchor rule).
- **`Update`**: Replace an existing rule by its `name`.
- **`Delete`**: Remove a rule by its `name`.

### Create Request Example

```json
{
  "mapping": {
    "mapping_id": "unique-ruleset-id",
    "domain_id": "default-domain",
    "source": {
      "type": "spiffe",
      "trust_domain": "example.org"
    },
    "domain_resolution_mode": {
      "type": "fixed"
    },
    "enabled": true,
    "rules": [
      {
        "name": "admin-workload",
        "match": {
          "all_of": [
            {
              "type": "condition",
              "equals": {
                "claim": "spiffe.id",
                "value": "spiffe://example.org/spiffe/admin-tool"
              }
            }
          ]
        },
        "identity": {
          "user_name": "admin-workload",
          "is_system": true
        },
        "authorizations": [
          {
            "type": "system",
            "system_id": "all",
            "roles": [{ "id": "admin", "name": "admin" }]
          }
        ],
        "groups": []
      }
    ]
  }
}
```

## Security Considerations

- **Immutable System Mappings**: Rulesets containing `is_system: true` are
  locked after creation to prevent privilege escalation via rule mutations.
- **AllOfStrict Claim Suppression Prevention**: The `require_all_keys` flag in
  `AllOfStrict` prevents attackers from bypassing high-priority rules by
  suppressing specific claims in lower-trust assertions.
- **Template Safety**: Templates cannot reference `enclosing_domain_id` as a
  claim to prevent shadowing the ruleset's domain context. Interpolated values
  are capped at 256 characters.
- **Regex Cache Limits**: Compiled regex patterns are cached with a 1024-entry
  cap and 100-entry LRU eviction to prevent adversarial cache partitioning.
  Regex evaluation is limited to claim values under 4 KiB.
