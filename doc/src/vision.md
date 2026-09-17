# OpenStack Authentication and Authorization: A Vision

**Status:** Draft for community discussion

**Date:** 2026-09-10

This document proposes a target model for authentication and authorization
across OpenStack. It is derived from the architecture decisions already taken in
the Rust Keystone implementation (the ADRs under `adr/`) and from the SPIRE
integration plan (`doc/plans/spire-integration.md`), and it extends them into
one coherent picture that other OpenStack projects can react to. It is
deliberately written for a wide audience: operators, service maintainers, SDK
authors, and the Technical Committee. It is not an ADR and it does not commit
any project to anything; its purpose is to give the community a concrete
proposal to argue about.

The model is described independently of any implementation. The Rust Keystone is
the reference implementation and the place where the building blocks already
exist, but nothing in the proposal requires it; Python Keystone,
`keystonemiddleware`, `oslo.policy` and every service can adopt the pieces that
concern them.

Each part states its own requirements and limits where it is described, and the
last section lists the questions the community, not this document, has to
answer.

## 1. The vision in one page

OpenStack authentication and authorization today is built around one artifact:
the scoped bearer token. A token proves who the caller is _and_ carries the
project, domain or system the caller may act on _and_ the roles the caller holds
there, frozen at issuance. Every service validates that token against Keystone
(or a cache of Keystone) and applies a local policy file that reads the roles
and the scope out of it.

The proposal separates the three things the token conflates:

| Concern           | Today                                                  | Proposed                                                                                                                                                                                                                                                                                   |
| ----------------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Who** (authn)   | Fernet/JWS token, password, app-cred, trust            | Short-lived signed JWT for the public API (OIDC/OAuth2, passkeys, device flow, workload federation); SPIFFE mTLS identity for everything inside the control plane and for tenant workloads                                                                                                 |
| **Where** (scope) | Baked into the token at issuance                       | Stated per request (a structured `OpenStack-Target` header, or derived from the addressed resource), generalizing the v3 tokenless auth headers to every call. The scope _types_ do not change: project, domain and system scope all survive, they stop being properties of the credential |
| **What** (authz)  | Roles frozen into the token; `oslo.policy` per service | Decided per request by a policy engine that receives the authentication facts, the target scope and the operation, and asks Keystone whether the caller holds the required role or permission on that target                                                                               |

The central move is the third row. Today a service asks "does the role list
inside this token contain `admin`, and does the scope inside this token match
the resource?". Under this proposal it asks Keystone "does this principal hold
the role or permission this operation requires, on this target?". The token
stops being the carrier of the answer and becomes only the proof of who is
asking.

Four further changes follow from this split:

- **The control plane authenticates with mTLS and nothing else.** Every
  OpenStack service holds a SPIFFE identity issued by SPIRE. Service-to-service
  calls, the Keystone back-channel, and the Nova-to-Keystone attestation path
  all authenticate at the TLS layer. Service users, service passwords and
  `X-Service-Token` disappear.
- **Trusts are replaced by service grants and on-behalf-of exchange**
  ([ADR 0036](adr/0036-service-delegation.md)). The acting service is always
  recorded, no secret is ever delegated, and the delegation boundary is a fact
  of the authentication chain rather than of the token's scope.
- **Tenant workloads get platform identity without credentials.** A VM or a
  Kubernetes node boots, attests to SPIRE with a Keystone-signed proof of its
  placement, receives a project-bound SVID, and calls the OpenStack APIs with
  it. No password, application credential or EC2 key is ever written into a
  guest.
- **Humans authenticate with phishing-resistant methods.** WebAuthn passkeys and
  OIDC federation are first-class; the CLI authenticates with WebAuthn directly,
  and the device authorization grant covers headless machines and CI.

The payoff is a model in which a policy rule, an individual operation, or a set
of operations can be bound to a human, a service or a workload identity on any
target without inventing a new role for it, the way AWS STS session policies or
Azure role assignments work. That is what finally makes "system scope", "global
reader", "domain manager" and "service role" expressible without every service
re-implementing the semantics.

## 2. Where OpenStack is today and what hurts

### 2.1 Tokens carry scope

A Keystone token is `(user, scope, roles, expiry)` sealed together.
Consequences:

- A client that touches three projects holds three tokens, or re-authenticates
  on every switch. SDKs, Terraform providers and dashboards all carry code to
  manage this.
- Every service's policy reads `project_id` and `roles` out of the token. The
  policy therefore answers "does this token's scope match the resource" rather
  than "may this principal do this to that resource". The two questions diverge
  exactly in the cases the community has struggled with for a decade:
  cross-project operations, cloud-wide read, and services acting on behalf of
  users.
- Scope is attacker-influenceable through rescope. Two 2026 advisories
  (OSSA-2026-005, OSSA-2026-015; see the
  [security model](contributor/security-model.md)) are instances of a decision
  keyed on token scope instead of on the immutable authentication chain.

### 2.2 Every request is a Keystone round trip

`keystonemiddleware` validates the token on each request, with a cache in front.
Keystone is on the data path of every OpenStack API call and its availability
bounds the availability of the whole cloud. The Rust implementation already
addresses the validation half of this with offline JWT verification
([ADR 0026](adr/0026-oauth2-oidc-provider.md) §6), but as long as roles are
frozen into the token, offline validation also freezes authorization for the
token lifetime.

This proposal does **not** remove Keystone from the data path. It moves the
round trip from token validation to an authorization decision, and it changes
what a cache entry is keyed on: today one entry per token, afterwards one entry
per `(subject, target)` pair. A caller that touches many projects therefore
trades many tokens for many cache entries. What is gained is that the cached
thing is a live decision with an operator-chosen TTL rather than a frozen role
list with the token's lifetime; what is not gained is independence from
Keystone. §8 states the resulting availability posture, and it is a hard
requirement on any deployment adopting the model.

### 2.3 System scope and the Secure RBAC goal

The community goal "Consistent and Secure Default RBAC" introduced three
personas (`reader`, `member`, `admin`), later `manager` and `service`, on three
scopes (`project`, `domain`, `system`). The design placed the scope in the token
and asked every service to decide what a system-scoped token means for each of
its project-owned resources. Services could not answer that uniformly: a
system-scoped token has no project, so creating a server "as the system" had no
owner, listing servers "as the system" needed new query semantics, and existing
operator tooling broke. The goal was re-scoped; system scope is today avoided by
most services and `admin` on a project remains the practical cloud
administrator.

The root cause is not the persona model, and it is not system scope itself. It
is that the scope was a property of the credential, so the credential had to be
re-issued for each target, and a system-scoped credential arrived at a service
with no project in it at all. This proposal keeps system scope — it is the right
way to name cloud-level resources and cloud-wide authority — and removes it from
the credential. An operator holding a system-level grant names a project target
on the calls that need one and the system target on the calls that do not,
without re-authenticating between them.

### 2.4 Global reader and "admin is global"

Two of the oldest open problems in OpenStack authorization are the same problem
seen from both ends:

- **Global reader:** an auditor, a billing collector, or a monitoring system
  needs read access to every project. Today that requires either `admin`, a role
  on every project, or a system-scoped token that most services cannot
  interpret.
- **Admin is global:** `admin` on _any_ project historically meant `admin`
  everywhere, because policies checked `role:admin` and the token scope was not
  compared to the resource. Fixing this per service took years and is still
  incomplete.

Both need the same primitive: a decision that takes the principal, the operation
and the _resource's_ target, and a single authority that knows how a grant on
the system or on a domain projects onto a project. That authority is Keystone;
today it is not consulted at decision time.

### 2.5 Roles are the only unit of grant

The only thing Keystone can grant is a role on a target. To let one workload
call one operation (rotate a secret, signal a Heat wait condition, read one
metric endpoint), an operator must create a role, wire the role into every
service's policy file, and assign it. Nobody does that; instead the workload
gets `member` or `admin`. Application-credential access rules were meant to
address this and have never been enforced at request time.

Every hyperscaler solved this with permissions as the unit of grant and roles as
named permission sets: AWS IAM actions and policies, GCP IAM permissions and
roles, Azure actions and role definitions. OpenStack already has a cloud-wide
operation vocabulary (the `oslo.policy` rule names such as
`os_compute_api:servers:create`); it has never been usable as a grant.

### 2.6 Secrets everywhere

- Every service has a service user with a password in a config file and the
  `admin` (or `service`) role.
- Heat, Magnum, Mistral and others store trusts; Magnum ships a trustee password
  into every cluster VM.
- Tenant automation gets application credentials or EC2 keys baked into images,
  Kubernetes secrets and CI variables, valid for months.
- Users authenticate with passwords in `clouds.yaml`.

Each of these is a long-lived bearer secret whose theft is indistinguishable
from legitimate use.

### 2.7 How the rest of the industry does it

| Platform   | Credential                                      | Where the scope lives                                          | Unit of grant                         | Workload identity                        |
| ---------- | ----------------------------------------------- | -------------------------------------------------------------- | ------------------------------------- | ---------------------------------------- |
| AWS        | SigV4-signed requests with STS short-lived keys | In the request (resource ARN); evaluated per call              | Action on resource (IAM policy)       | Instance profile, IRSA, roles anywhere   |
| GCP        | OAuth2 access token                             | In the request (resource name); hierarchy inheritance          | Permission; roles are permission sets | Service account attached to the workload |
| Azure      | Entra ID JWT, audience-bound                    | In the role _assignment_, not in the token; evaluated per call | Action; role definitions              | Managed identity                         |
| Kubernetes | Projected service-account token, audience-bound | In the request (namespace/resource); `SubjectAccessReview`     | Verb on resource (RBAC rule)          | Service account, SPIFFE via SPIRE        |
| OpenStack  | Fernet token (JWT in keystone-rs, still scoped) | In the token                                                   | Role on project/domain/system         | Application credential in the guest      |

OpenStack is the outlier on every column. The proposal below moves each column
to the industry pattern while keeping the v3 API and Python services working
during the transition.

## 3. Principles

1. **Authentication proves identity, nothing else.** A credential says who the
   caller is and how strongly that was established (`amr`). It does not say what
   the caller may do.
2. **Authorization is decided per request, against the target.** The target is
   the addressed resource's owner, or the scope the caller names for create/list
   operations. It is never taken from the credential.
3. **Security decisions key on the authentication chain, never on scope.** This
   is the overarching rule of the security model (of which invariant I1,
   "delegation facts come from the chain", is the delegation-specific case),
   generalized: delegation boundaries, restrictions and the acting party are
   chain facts; the target is a per-call input.
4. **Keystone is the authority for grants; services are the authority for
   resources.** A service knows which project a server belongs to; Keystone
   knows whether the caller holds `compute:servers:delete` there, including
   through domain or system inheritance. Neither should have to know the other's
   rules.
5. **Credential-less wherever possible.** Identity is bound to the runtime
   (SPIFFE SVID, attested VM, passkey), not to a secret in a file.
6. **Short-lived, sender-constrained, audience-bound.** Whatever bearer
   artifacts remain live for minutes, are bound to the presenting workload where
   the transport allows it, and name the services that may accept them.
7. **Every acting party is recorded.** Delegated calls carry `act`; audit never
   loses who did what on whose behalf.
8. **Compatibility is a design input, not an afterthought.** v3 tokens, Python
   services and existing SDKs keep working through every phase.
9. **Grants are roles and permissions; a relation store is an implementation
   choice.** The model works on the SQL assignment driver alone. Roles,
   inheritance and permission sets answer every problem in §7; an OpenFGA-backed
   driver (ADR 0033) is valuable for deployments that already run a relation
   store and for resource-level grants (§6.5), and it is a per-domain backend
   decision (ADR 0034), never a prerequisite for adopting anything here.
   That choice is not free of consequence, though, and the consequence is
   permanent rather than a rollout gap: it fixes the ceiling on what freshness
   the authorization path could ever offer. Where Keystone is the sole writer of
   every decision input, an early-drop signal is at least reachable — §6.3
   refuses the elaborate form of it and leaves a coarse one open. On an
   externally owned store Keystone cannot observe every write, so no such signal
   is sound at any cost and revocation is bounded by the cache lifetime by
   construction (§6.3). An operator choosing OpenFGA for its resource-level
   flexibility is choosing that too. So is an operator choosing an LDAP identity
   backend, for the same reason on a different input.

## 4. Target architecture

```mermaid
flowchart LR
    subgraph callers["Callers"]
        human["Human<br/>passkey, OIDC, device flow"]
        ext["External automation<br/>GitHub, GitLab, Zuul, k8s operator"]
        vm["Tenant workload<br/>VM or cluster node with SVID"]
    end

    subgraph ks["Keystone: writes, token issuance"]
        op["OAuth2 / OIDC provider<br/>issues scope-less JWT"]
        map["Mapping engine<br/>SVID / OIDC / JWT to principal"]
    end

    subgraph dt["Decision tier: scaled independently"]
        authz["Authorization API /v4/authz/check<br/>grants, roles, permissions, inheritance"]
    end

    subgraph cp["Control plane: SPIFFE mTLS"]
        svc["OpenStack service<br/>nova-api, neutron, ..."]
        pdp["Policy engine<br/>OPA, or oslo.policy bridge"]
        peer["Other service<br/>placement, glance, ..."]
    end

    spire["SPIRE"]

    human -->|"login"| op
    ext -->|"workload federation JWT"| map
    vm -->|"JWT-SVID"| map
    map --> op
    callers ==>|"Bearer JWT + OpenStack-Target"| svc
    svc -->|"authn facts, target, operation"| pdp
    pdp -->|"check(sub, op, target)<br/>cached, short-lived"| authz
    ks -.->|"assignment data: Raft learner,<br/>read replica or relation store"| authz
    svc -->|"mTLS peer identity,<br/>user JWT forwarded or exchanged"| peer
    spire -.->|"SVIDs"| cp
    spire -.->|"SVIDs"| vm
```

### 4.1 Identity tracks

| Caller                                  | Authentication                                                                         | What the service sees                                                      |
| --------------------------------------- | -------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Human at a browser                      | OIDC authorization code + PKCE at Keystone; passkey or federated IdP behind it         | Bearer JWT, `sub` = user, `amr` = `["webauthn"]` etc.                      |
| Human at a CLI                          | Device authorization grant (browser login with passkey/MFA on a headless machine)      | Same JWT                                                                   |
| External CI / operator                  | Workload federation: platform JWT exchanged through the mapping engine (ADR 0008/0020) | Bearer JWT, `sub` = mapped principal                                       |
| Tenant VM / cluster node                | SPIRE-issued project/instance SVID, presented as JWT-SVID `private_key_jwt`            | Bearer JWT, `sub` = ephemeral principal bound to `spiffe.project_id`       |
| Control-plane service acting as itself  | X.509 SVID at the TLS layer of the internal interface                                  | No token at all; peer identity from the TLS session, mapped to a principal |
| Control-plane service acting for a user | The user's JWT forwarded, or an on-behalf-of token with `act` (ADR 0036 §6)            | User JWT plus service SVID at the transport                                |
| Deferred automation (Heat, Magnum)      | Service grant redeemed with the service SVID (ADR 0036 §5)                             | JWT with `sub` = grantor, `act` = service                                  |

### 4.2 Control plane: mTLS, no dedicated authentication

Every control-plane process holds a SPIFFE identity from a local SPIRE agent
(SPIRE plan Phase 1). Keystone's internal interface, and the internal endpoints
of every other service, terminate SPIFFE mTLS and identify the peer from the
SVID URI. A request from `spiffe://td/service/nova-api` to Neutron is
authenticated by the handshake; Neutron's policy input carries the peer as
`service_credentials` and the forwarded user context (if any) as `credentials`.

This removes:

- service **passwords** in configuration files, and the `admin` role assignments
  services hold today;
- `X-Service-Token` and `service_token_roles_required`, which exist only because
  the transport carried no service identity;
- the plaintext back-channel from `keystonemiddleware` to Keystone (SPIRE plan
  Phase 4.1, the middleware SPIFFE mTLS transport change).

It does not remove the service as a subject of authorization. Every service
still corresponds to a principal in Keystone — mapped from its SPIFFE ID through
the mapping engine rather than carrying a password — and still holds a grant,
namely the `service` permission set on the system target (§7.4). "No dedicated
authentication in the control plane" means the transport authenticates the
service; it does not mean the service is unauthorized, and it does not mean the
service inherits the user's authority. mTLS identifies the _service_, never the
user it serves: a user-initiated call still carries the user's JWT, and a policy
that needs the user must read `credentials`, not `service_credentials`. Read the
other way, this would reintroduce the service-user-with-`admin` pattern under a
new name.

Per-host identities (`.../nova-compute/host/{hostname}`) let Keystone bind an
attestation request to the compute host that actually runs the instance (ADR
0032), which a flat service identity cannot do.

```mermaid
flowchart LR
    subgraph host_a["Controller"]
        na["nova-api<br/>spiffe://td/service/nova-api"]
        ne["neutron-server<br/>spiffe://td/service/neutron"]
        ks["keystone internal<br/>spiffe://td/service/keystone"]
    end
    subgraph host_b["Compute host c-3"]
        nc["nova-compute<br/>spiffe://td/service/nova-compute/host/c-3"]
        ag["spire-agent"]
    end
    ss["spire-server"]
    na <-->|"mTLS: user JWT forwarded,<br/>peer = nova-api"| ne
    na <-->|"mTLS"| ks
    nc -->|"mTLS: POST /v4/vendordata"| ks
    ag -->|"node attestation"| ss
    ss -.->|"SVIDs"| na
    ss -.->|"SVIDs"| ne
    ss -.->|"SVIDs"| ks
    ss -.->|"SVIDs"| ag
```

### 4.3 Public API: a JWT that says who, and a request that says where

Keystone is an OAuth2/OIDC provider (ADR 0026). The access token it issues for
OpenStack APIs carries:

- `iss`, `sub`, `aud`, `exp` of about fifteen minutes, `jti`, `amr`. The
  audience is narrowed to the service types the client asked for
  (`openstack-apis:{domain_id}:compute`, …) **by default**; the domain-wide
  `openstack-apis:{domain_id}` audience is an explicit opt-out for clients that
  cannot enumerate their callees. This default is what makes the forwarding rule
  of §4.8 meaningful — a rule that says "forward only tokens whose `aud`
  includes the callee" is vacuous if every token is audience-wide;
- `act` when a service acts on behalf of the subject;
- `delegation_context` when the chain is delegated (service grant, application
  credential, on-behalf-of);
- `restrictions` when the holder asked for a narrower token than its full
  authority (a self-imposed ceiling, see §5.4);
- **no** project, domain or system scope, and **no** roles.

The caller names the target on each request. The proposal generalizes the idea
behind the v3 X.509 tokenless authorization headers, which already let a client
say "I am this certificate, acting on this project", into one structured header
sent on every call:

```http
GET /v2.1/servers HTTP/1.1
Authorization: Bearer <JWT>
OpenStack-Target: project="8e3f..."
```

Section 5 specifies the contract. Section 5.3 shows how `keystonemiddleware` can
turn it into the `X-Project-Id` / `X-Roles` context today's services expect, and
why that compatibility mode is a per-service opt-in rather than a free ride: a
client-supplied target is not a Keystone-attested one, and a service that treats
it as attested is exactly the bug class §5.4 and the
[security model](contributor/security-model.md) exist to prevent.

### 4.4 Authorization: the policy engine asks Keystone

Each service evaluates policy per request with an input of three parts:

```json
{
  "credentials": {
    "sub": "...",
    "amr": ["webauthn"],
    "act": null,
    "delegation_context": null,
    "restrictions": null
  },
  "service_credentials": { "spiffe_id": "spiffe://td/service/nova-api" },
  "target": {
    "scope": { "project_id": "8e3f..." },
    "server": { "id": "...", "project_id": "8e3f..." }
  },
  "operation": "compute:servers:delete"
}
```

The policy decides using local rules (ownership, resource state, `amr`
requirements, delegation tripwires) and one remote fact it cannot know itself:
whether `sub` holds the operation, or a role that implies it, on `target.scope`.
It asks Keystone:

```http
POST /v4/authz/check
{
  "subject": { "sub": "...", "act": null, "delegation_context": null, "restrictions": null },
  "target": { "project_id": "8e3f..." },
  "operations": ["compute:servers:delete"]
}
```

```json
{
  "results": {
    "compute:servers:delete": {
      "allowed": true,
      "via": ["role:admin@domain:inherited"],
      "ttl": 60,
      "minted": 1789432011
    }
  },
  "roles": ["admin"]
}
```

Keystone resolves direct, group, inherited and system-level grants, intersects
with the delegation boundary and with any self-imposed restriction, and returns
a decision plus the classic role list for policies that still key on roles.

The cache lifetime is per result, not per response. One call can return an
allow and a deny, and a deployment may not want the two held on the same terms:
a stale deny is an inconvenience, a stale allow is a security failure. `minted`
is a monotonic stamp for compare-and-set against a shared cache, not a freshness
signal. §6.3 sets out the freshness options, what the assignment driver does and
does not change about them, and why the elaborate answer is refused.

**The cache is part of the architecture, not an optimization.** A decision cache
keyed on `(subject, target)` sits in front of every call to `/v4/authz/check`:
the live call happens on a miss or on expiry. Running with the cache disabled is
a supported posture rather than an oversight, and §6.3 says when it is the right
one; what it costs is latency on the hot path and a hard dependency on tier
availability. §6.3 specifies the cache contract, and the part of it that is not
uniform: what freshness each decision input can actually be held to differs, and
is visible in the API response.

This is the Kubernetes `SubjectAccessReview` pattern, and the shape
`oslo.policy` already supports through its `http` check type, which gives Python
services a zero-code migration path (§9).

```mermaid
sequenceDiagram
    participant C as Client
    participant M as keystonemiddleware
    participant S as nova-api
    participant P as Policy engine
    participant K as Keystone authz API

    C->>M: DELETE /servers/{id}<br/>Authorization: Bearer JWT<br/>OpenStack-Target: project=P
    M->>M: verify JWT offline (JWKS cache)<br/>parse OpenStack-Target
    M->>S: request + authn facts + requested scope
    S->>S: load server, owner = P'
    S->>P: input {credentials, target{scope:P, server{project:P'}}, operation}
    P->>P: requested scope must equal resource owner (P == P') else deny
    P->>K: POST /v4/authz/check (sub, P, compute:servers:delete)<br/>(cached per sub+target)
    K-->>P: allowed via role:admin@domain:inherited, ttl
    P-->>S: allow
    S-->>C: 204
```

Where a decision is _evaluated_ and where the grant _facts_ come from are two
independent choices, and this proposal fixes only the second. The policy engine
may run as a sidecar beside each service or as an in-process `oslo.policy`
library; a per-service OPA sidecar calling the check API over SVID mTLS is a
shape an earlier proof of concept already exercised, and the `http.send` stanza
left commented in `policy/identity/user/list.rego` is where it did so. What the
proposal does rule out is on the other axis: replicating the grant graph itself
to every evaluation point (§6.3).

#### The check API is served by a dedicated decision tier

`/v4/authz/check` carries authorization traffic — at least one decision per API
call across the whole cloud — while grant writes and token issuance carry a load
orders of magnitude smaller. Those two have no reason to share a process, a
release cadence or a scaling unit. The check API is therefore a component in its
own right: a horizontally scalable decision tier that reads assignment data (as
an embedded Raft learner, a read replica, or a client of the relation store,
depending on the driver) and serves decisions, deployed and sized independently
of the Keystone nodes that accept writes.

This is the structural lesson worth taking from Zanzibar. Google did not add a
check API to its identity service; it built a separately scaled system, because
deciding every request is a different engineering problem from authenticating
callers. Extracting the decision tier into its own binary is the same move, and
it is what makes a live check survivable without asking every service to hold a
copy of the grant graph.

It is also the containment boundary for everything §6.3 makes driver-dependent.
Batch expansion, the per-item short-circuit, per-result lifetimes and the
freshness limits an externally owned store imposes all live in this one
component, so `oslo.policy` and the services see a single uniform contract
whatever the assignment driver underneath is. Without that boundary the
per-driver differences leak into every enforcement point in the cloud.

One decision tier does not mean one cluster. The serving layer is federated — a
region-local or domain-local decision tier, each independently scalable and
independently failable — while grants keep a single authoritative write path, so
there is still exactly one place a grant is defined and revoked. That is the
Raft-learner idea of §8 drawn as a deployment pattern rather than a multi-region
footnote, and it is the main lever for keeping one authority from meaning one
failure domain, which is why §8 makes it the definition of a supported
high-availability topology rather than one option among several. It is not
uniform across drivers: a learner or read replica follows the SQL driver
anywhere, while a region-local tier serving a domain whose assignments live in a
remote relation store still pays a WAN round trip on every miss, because there
is no learner concept to borrow (§6.3). And the bound
during a partition has to be stated plainly: a cut-off region keeps serving
decisions from its local state and stops receiving revocations.

Federating the read path also adds a staleness term §6.3 does not account for.
The cache lifetime bounds how long an enforcement point holds a decision;
replication lag bounds how far behind the write path the tier that minted it
was. The freshness an operator can promise is the sum of the two, and during a
partition the second term is unbounded — which is the price of serving at all
rather than a defect to be fixed.

Three properties are requirements on this tier rather than inherited
assumptions:

- It is a second trust boundary over assignment data. The rule that security
  decisions key on the authentication chain and never on scope, the delegation
  invariants (I2/I4), and the requirement that secrets be stripped from policy
  input all hold inside the decision tier, and are tested there.
- It serves from state it holds locally for as long as the write path is
  unreachable, including cold-booting a replacement replica while the write path
  is down — the statically stable posture §8 states as a requirement and names a
  test for. A tier that is decoupled from the write path on the diagram but
  calls it to warm its state is not decoupled from it.
- Keystone's own authorization stays in-process (§6.3). The decision tier is how
  other services ask; it is not in the path of Keystone authorizing a call to
  itself, and it must not become a startup dependency of the Keystone write
  path.

### 4.5 Delegation without secrets

[ADR 0036](adr/0036-service-delegation.md) replaces trusts with two mechanisms
on the OAuth2 token endpoint:

- **Service grants** for deferred authority (Heat stacks, Magnum clusters,
  Mistral workflows): a user-visible, revocable record naming a registered
  service client as grantee; redeemed with the service's SVID; token `sub` is
  the grantor and `act` is the service.
- **On-behalf-of exchange** (RFC 8693) for continuing a user-initiated operation
  past token expiry (Glance import, long migrations): the service exchanges the
  user's token for one that carries `act`, bound to the root token's `jti` so
  revoking the user's token ends the chain.

No impersonation flag, no redelegation, no use counter, no trustee user, no
password in a cluster. Both mechanisms already place every delegation fact in
`delegation_context`, so they survive scope-less tokens unchanged (ADR 0036 §7).

```mermaid
sequenceDiagram
    participant U as User
    participant H as heat-api
    participant K as Keystone
    participant E as heat-engine
    participant N as nova-api

    U->>H: create stack (Bearer JWT)
    H->>K: POST /v4/service-grants (grantee = heat client, project P, roles)
    K-->>H: grant_id
    Note over E: hours later, autoscaling fires
    E->>K: POST /v4/oauth2/{d}/token grant_type=service-grant<br/>mTLS with heat-engine SVID
    K->>K: roles = grant ∩ grantor live roles on P
    K-->>E: JWT sub=user, act=heat-engine, delegation_context{grant_id, P}
    E->>N: POST /servers  Bearer JWT  OpenStack-Target: project=P
    N->>K: authz check (sub, P, compute:servers:create) with delegation bound
    K-->>N: allowed
```

### 4.6 Tenant workload identity

The SPIRE plan gives every VM a platform identity without a secret in the guest:

1. Nova asks Keystone (over mTLS, with its per-host SVID) for a short-lived
   attestation JWT for `(project, instance)`; Keystone verifies placement with
   Nova before signing (ADR 0032).
2. The JWT is delivered through vendor data; the guest's SPIRE agent presents it
   to the SPIRE server, which mints `spiffe://td/project/{p}/instance/{i}`.
3. The workload calls Keystone's token endpoint with the JWT-SVID
   (`private_key_jwt`) or the OpenStack APIs directly with a JWT-SVID mapped by
   a rule on `spiffe.project_id`, and receives whatever the mapping rule grants:
   a role, or, with §6, a specific set of operations on its own project.

The same path serves Magnum cluster nodes, Trove database guests and any tenant
automation that runs on the cloud; Octavia amphorae are a candidate once their
certificate bootstrap is reconsidered (out of scope in ADR 0036). Application
credentials and EC2 keys remain for automation that runs _outside_ the cloud and
cannot attest, and they shrink to a legacy niche.

```mermaid
sequenceDiagram
    participant NC as nova-compute (host SVID)
    participant K as Keystone
    participant VM as Guest (cloud-init + spire-agent)
    participant SS as SPIRE server
    participant API as OpenStack API

    NC->>K: POST /v4/vendordata {project, instance} (mTLS)
    K->>K: verify placement with Nova, sign with attestation key
    K-->>NC: attestation JWT (5 min)
    NC->>VM: vendor_data.json
    VM->>SS: attest with JWT
    SS->>K: GET /v4/spiffe/{domain}/jwks
    SS-->>VM: SVID spiffe://td/project/P/instance/I
    VM->>API: Bearer JWT-SVID, OpenStack-Target: project=P
    API->>K: authz check (principal mapped from spiffe.project_id, P, op)
```

### 4.7 Human authentication

- **Passkeys** (ADR 0005) are the default strong method. Keystone acts as the
  WebAuthn relying party; the OIDC provider records `amr: ["webauthn"]`, so a
  policy can require phishing-resistant authentication for sensitive operations
  (key rotation, role assignment, grant creation).
- **External IdPs** federate through the mapping engine (ADR 0020), including
  expiring group membership (ADR 0013) and SCIM provisioning (ADR 0024).
- **CLI login** already reaches passkeys: the Rust CLI authenticates with
  WebAuthn directly, and the device authorization grant covers headless machines
  and CI by delegating to a passkey-capable browser login. This is where
  phishing-resistant authentication earns its keep, because OpenStack users
  authenticate at the CLI and in CI far more than at Horizon. With that path in
  place the `clouds.yaml` password is already optional and is documented as
  deprecated.
- **Step-up** is expressed as `amr` requirements in policy rather than as
  separate credentials.

### 4.8 Cross-service calls on behalf of a user

When Nova calls Neutron for a user it either forwards the user's JWT or performs
an on-behalf-of exchange (§4.5). Forwarding is simpler and works with today's
code, but a forwarded token is accepted by whatever its audience allows, so a
compromised service can act as the user everywhere the token is accepted. The
rule is therefore:

> **Forward only a token whose `aud` includes the callee; otherwise exchange.**

With service-type audiences as the default (§4.3), forwarding is naturally
confined to the services the client already intended to call, and the exchange
path covers the rest. Both paths carry the caller's SVID as
`service_credentials`, which is the control-plane identity that replaces
`X-Service-Token`.

## 5. Scope-less tokens and per-request target scope

### 5.1 Request contract

A request to an OpenStack service names its target in one of three ways, in this
order of precedence:

1. **Resource-derived.** For any operation on an existing resource
   (`GET/PUT/PATCH/DELETE .../servers/{id}`), the target is the owner of that
   resource as recorded by the service. This is authoritative. A client-supplied
   scope that disagrees with it is a policy violation and the request fails
   closed (404 or 403 per the service's existing disclosure rules).
2. **Header.** For operations that have no existing resource (create, list,
   actions on collections), the client sends a structured header (RFC 8941
   dictionary syntax) naming the target:

   ```http
   OpenStack-Target: project="8e3f..."
   ```

   Exactly one of `project`, `domain` or `system-scope` must be present, with a
   string value:

   | Member         | Value      | Target                                                                |
   | -------------- | ---------- | --------------------------------------------------------------------- |
   | `project`      | project id | that project                                                          |
   | `domain`       | domain id  | that domain                                                           |
   | `system-scope` | `all`      | the system: cloud-level resources, and cloud-wide reach over projects |

   `system-scope="all"` is deliberately the **same** system scope the v3 API
   already has, spelled the way `keystonemiddleware` already exposes it
   (`OpenStack-System-Scope: all`). This proposal introduces no new scope type:
   a service that understands system scope today understands this header, and a
   service that does not is in exactly the position it is in today. What changes
   is only that the scope arrives per request instead of frozen into the
   credential, so an operator no longer re-authenticates to move between system
   scope and a project.

   Name-based addressing mirrors the tokenless `X-Project-Name` /
   `X-Project-Domain-Name` pair as dictionary members the middleware resolves to
   ids:

   ```http
   OpenStack-Target: project-name="demo", domain-name="Default"
   ```

   The header may also carry the addressed resource, in the same
   `<service-type>:<resource>:<id>` form the operation vocabulary uses (§6.1):

   ```http
   OpenStack-Target: project="8e3f...", resource="compute:server:550e..."
   ```

   For an existing resource the `resource` member never overrides rule 1: it
   lets the middleware and the policy engine pre-check and audit the request
   before the service loads the resource, and it is the hook for resource-level
   grants (§6.5). A `resource` member that disagrees with the URL, or a
   `project` that disagrees with the loaded resource's owner, fails closed.

3. **Default.** If neither is present, `keystonemiddleware` rejects the request
   unless the operator has enabled fallback to the subject's default project (an
   existing Keystone user attribute) for the migration period. Reject is the
   default; fallback is a documented, per-service opt-in, and it is time-boxed
   by a deprecation cycle so that it expires with the migration rather than
   becoming a permanent mode.

Unauthenticated endpoints are outside this contract: version discovery, JWKS,
`.well-known` documents and health checks carry neither a subject nor a target
and are never subject to rule 3's rejection. A service's list of unauthenticated
routes is the same list it maintains today.

Using a structured field rather than a family of `X-*` headers keeps the grammar
extensible (a later `region` or `resource-version` member is additive), gives
every SDK a standard parser, and avoids the `X-Project-Id` family that
`keystonemiddleware` overwrites on the WSGI environment.

**The resource-derived target always wins (invariant).** Rule 1 is not a
preference, it is the invariant that makes the whole design safe. If a service
trusted `OpenStack-Target` for `DELETE /servers/{id}`, a caller with rights on
project A could name A while deleting a server owned by B. Every service that
participates must therefore compare the requested target to the loaded
resource's owner and fail closed on a mismatch, with the same scope-drift
tripwire discipline the [security model](contributor/security-model.md) applies
to delegation (I2/I3). A service that has not implemented this comparison is not
ready to accept per-request targets, which is why §5.3 makes the compatibility
mode an opt-in.

### 5.2 What `keystonemiddleware` does

1. Verifies the JWT offline (signature, `iss`, `aud`, `exp`, `nbf`), or
   validates a legacy Fernet token through the mTLS back-channel.
2. Parses `OpenStack-Target`; resolves names to ids; validates that the named
   project or domain exists and is enabled (cached). The result is the
   **requested** target, and the middleware labels it as such: it is a client
   assertion, not a Keystone-attested fact.
3. Populates the WSGI environment with the authentication facts and the
   requested target: `X-User-Id`, `X-Requested-Target`, `X-Actor-*` for `act`,
   the delegation context and the restrictions.
4. Leaves the decision to the service's policy, which resolves the target of
   §5.1 (resource owner first) and asks `/v4/authz/check` for the concrete
   operation on the resolved target. This is the model: the policy asks Keystone
   whether the actor holds the required role or permission on the target,
   instead of reading a role list out of the credential.

The middleware never fills `X-Project-Id` / `X-Roles` from the requested target
on its own initiative, because a role list computed for a client-asserted scope,
placed in the variable legacy policy treats as attested, is precisely the
confusion this proposal exists to remove. It fills them only in the
compatibility mode of §5.3, which a service must opt into.

### 5.3 Compatibility

- A v3 scoped token keeps working: the middleware treats its embedded scope as
  the requested scope and rejects a conflicting `OpenStack-Target` header. A
  scoped token's scope _is_ Keystone-attested, so nothing below applies to it.
- A client that never sends the header and holds a JWT gets the default
  behaviour of §5.1 item 3, which an operator can set to "subject's default
  project" to keep unmodified tooling working.
- Keystone continues to issue scoped tokens on request; `audience` narrowing
  (ADR 0036 §7.1) and the `restrictions` claim (§5.4) let a client voluntarily
  pre-bind a token where a deployment wants that.
- **Compatibility mode is a per-service opt-in.** A service can ask the
  middleware to keep populating `X-Project-Id`, `X-Domain-Id`, `X-Roles` and
  `OpenStack-System-Scope` from the requested target plus a role-list lookup, so
  that unmodified `oslo.policy` rules keep evaluating. Enabling it is a
  declaration by that service that it enforces the §5.1 invariant: every
  operation on an existing resource compares the requested target to the
  resource's own owner and fails closed on a mismatch. Until that declaration
  the middleware refuses the mode, and the service sees only the §5.2
  environment.

  The declaration is the whole point of the opt-in. The environment variables
  are byte-identical to today's, but their provenance is not: under a scoped
  token `X-Project-Id` was attested by Keystone, and under a per-request target
  it is chosen by the caller. A rule that reads `project_id` without comparing
  it to the resource — or code that stamps ownership, charges quota, or
  shortcuts on `is_admin` from it — becomes caller-influenceable. (That is the
  defect class of OSSA-2026-015: a decision keyed on caller-influenceable scope
  instead of on an attested fact.) Adopting per-request targets is therefore a
  real, reviewable change in each service, and §9 budgets for it.

  The mode exists so a service can accept per-request targets before it moves
  its policy to the check API, so it is time-boxed on the same footing as the
  §5.1 item 3 fallback: it is a per-service configuration flag that Keystone can
  report as a capability, and Phase 6 switches it off service by service.

- SDKs add one header and drop per-project re-authentication.

### 5.4 Threat model changes

A scope-less token represents the subject's full authority, as an AWS access key
or an Azure token does. The mitigations are the ones those platforms use, and
most already exist in the ADRs. The first three are **gates on shipping
scope-less tokens at all**, not later refinements. (Without them a scope-less
bearer token is a cloud-wide master key, weaker than the scoped Fernet token it
replaces.) §9 splits the migration at exactly this line (Phase 2a / Phase 2b).

- **Sender constraint (gate).** JWTs issued to SVID holders are bound to the
  SPIFFE identity through `act`/`sub` and presented over mTLS; JWTs issued to
  public clients use DPoP (ADR 0026 v1.5) so a stolen token is unusable without
  the client's key. ADR 0036 rules out RFC 8705 because SPIRE rotates
  certificates, which is correct for a thumbprint binding — the workable
  substitute is to bind to the **SPIFFE ID** rather than to the certificate,
  verified at the internal interface where the SVID is the TLS peer, and that
  binding needs specifying before Phase 2b.
- **Audience narrowing (gate).** Per service type by default (§4.3), so a token
  captured at one service cannot be replayed at another (ADR 0036 §7.1).
- **Self-imposed restrictions (gate).** A client may request a token whose
  `restrictions` claim limits it to named targets and operations (the AWS STS
  session-policy shape). Restrictions only ever narrow, are chain facts, and are
  intersected by `/v4/authz/check`. Token restrictions already exist in the Rust
  implementation (`TokenRestriction`, used by the Kubernetes authentication
  method); this generalizes them. They are also the feature
  application-credential access rules promised and never enforced: a CI job or a
  script can hold a token that can do exactly one thing. Scope-less must be the
  default, never the only option; without restrictions the proposal trades one
  problem (too many tokens) for another (every token is a master key).
- **Short lifetime** (fifteen minutes) with refresh-token rotation and family
  breach detection (ADR 0026 §9).
- **Fail-closed scope agreement.** The resource-derived target always wins over
  the header; a mismatch is an error, never a silent widening (§5.1).
- **Audit.** Every decision logs subject, `act`, requested scope, resolved
  target, operation and outcome (ADR 0023), which is what makes anomaly
  detection on a stolen token possible at all.

## 6. Authorization model

### 6.1 Roles stay; permissions are added

Keystone keeps roles, role assignments, implied roles and inheritance. It adds
**permissions**: operation identifiers drawn from the cloud-wide policy
vocabulary that every service already publishes through `oslo.policy`
(`os_compute_api:servers:create`, `get_image`, `create_port`). A role becomes,
in addition to its name, a named set of permissions; the SRBAC personas are
shipped as such sets:

| Persona   | Meaning as a permission set                                                                                           |
| --------- | --------------------------------------------------------------------------------------------------------------------- |
| `reader`  | every `*:list`, `*:show`, `*:get` operation of every service                                                          |
| `member`  | `reader` plus lifecycle operations on tenant-owned resources                                                          |
| `manager` | `member` plus administration of the target short of `admin`: project manager on a project, domain manager on a domain |
| `admin`   | everything on the target                                                                                              |
| `service` | the operations a control-plane service needs when acting as itself                                                    |

A grant is `(principal, role | permission set | permission, target)`. Targets
are `system`, `domain:<id>`, `project:<id>` and, later, individual resources.
Inheritance is what it is today: a grant on a domain or on the system can be
marked inherited and projects onto every project below it.

Which operations belong to `member` rather than `manager` in each service stays
a per-project decision, and it is the same decision the SRBAC goal already
requires; this proposal changes how the answer is stored, not what it is.

#### The operation vocabulary is a prerequisite

Per-operation grants need stable, cloud-wide operation identifiers. The
`oslo.policy` rule names are close but inconsistent across projects
(`os_compute_api:servers:create` versus `create_port` versus `add_image`), so
the deliverable is a registry with a normalized form
(`<service-type>:<resource>:<verb>`) and a per-project alias table. This is the
largest cross-project ask in this document; authoring it is documentation and a
generator rather than code.

Operating it needs more than that. Because `/v4/authz/check` expands roles and
permission sets into operations at decision time (§6.3), Keystone holds a live
catalog that spans every deployed service, including out-of-tree ones, and that
changes on every service upgrade. Three rules make that tractable:

- **The catalog is deployment state with a version.** Services register their
  operations (or an operator imports the generated registry). A vocabulary
  change is a change to a decision input like any other, so a caller evaluates
  against a stale vocabulary for no longer than its decision cache lifetime
  (§6.3).
- **Unknown operations fail closed.** A check for an operation the catalog does
  not know is denied, never allowed. A service that ships a new operation before
  the registry knows it is therefore broken loudly for that operation only,
  rather than quietly permissive.
- **Persona sets are expressed as patterns, not enumerations.** `reader` is
  "every `*:list`, `*:show`, `*:get`" evaluated against the catalog, not a
  frozen list of operation names, so a new read operation is covered on the day
  it is registered. This is what keeps a service upgrade from silently demoting
  existing readers, and it is why the verb half of the normalized form has to be
  a closed set.

### 6.2 The authorization input contract

The community-facing deliverable is a schema, not a tool. Any policy engine (OPA
is the reference; `oslo.policy` with an `http` check is the bridge) must
receive:

- `credentials`: the authentication facts from the JWT or SVID, exactly as
  projected by `Credentials` in the Rust implementation, without roles;
- `service_credentials`: the mTLS peer, when a service is calling;
- `target.scope`: the resolved target of §5.1;
- `target.<resource>` and `existing.<resource>` per ADR 0002;
- `operation`: the permission identifier;
- `context`: extra resource facts the calling service attaches for a single
  decision — Neutron's `rbac_policy` sharing rows, an image's member list, a
  secret's ACL, a network's address-scope — passed straight through to the
  engine in its native shape (OPA `input`, OpenFGA contextual tuples plus a
  `context` object, Cedar `context`). This is how a service moves a complex,
  service-specific condition into the check call instead of keeping a local
  enforcement path for it. `context` feeds the decision only; it never feeds
  the delegation boundary, the `restrictions` filter or the role set, all of
  which stay bound to the authentication chain (I1/I2) and are not
  caller-supplied.

The contract is the community-level standard; the engine is not. Mandating OPA
in every service would stall adoption, so OPA is the reference engine and
`oslo.policy` with a `keystone` check type is the bridge — a Python service can
adopt the model by changing its policy defaults rather than its code.

Rules that today read `input.credentials.roles` keep working in the
compatibility mode of §5.3, where the middleware pre-fetches the role list for
the requested target; that mode carries the §5.1 obligation with it. Rules that
need finer control, and every rule in a service that has moved off the
compatibility mode, call the check API for the specific operation on the
resolved target.

### 6.3 The Keystone authorization API

`POST /v4/authz/check` (batchable) answers, for a subject and a target, which of
the listed operations are allowed and through which grant. It applies:

1. direct, group-derived and inherited grants on the target;
2. system-level grants marked as applying to every project (this is how a global
   reader is expressed);
3. the delegation boundary from `delegation_context` (I2/I4 of the security
   model): a delegated subject can only be allowed on its delegated project and
   only for the delegated roles or permissions;
4. `restrictions` from the token;
5. implied-role expansion and role-to-permission expansion.

It is served by the dedicated decision tier of §4.4 — horizontally scalable and
independent of the write path — and every caller puts a cache in front of it.
The OpenFGA assignment driver (ADR 0033) and per-domain drivers (ADR 0034) mean
a deployment can back this API with a Zanzibar-style relation store for tenants
that already run one, with relation sync (ADR 0035) keeping group membership
consistent, at the cost of a weaker freshness guarantee that the rest of this
section states rather than buries.

#### This is the new hot path; design it like one

`/v4/authz/check` replaces token validation on the data path, so its
non-functional requirements are not negotiable: batchable, answered from state
local to the decision tier without a per-request SQL round trip, cacheable on
terms the response states explicitly, admission-controlled per calling SVID and
accounted in decisions rather than requests, and exposed on the internal
interface only. Its latency budget is the one today's
`keystonemiddleware` cache miss has. The
per-request cache (ADR 0030) is a building block on the Keystone side. The
existing assignment-layer caches are not: ADR 0034 §8 caches the
domain-to-driver binding rather than resolved assignments, and ADR 0033 §9
declines to cache OpenFGA results in the driver at all. A decision cache is new
work in the decision tier, not an existing mechanism to reuse.

Two shapes are explicitly _not_ the answer. A pushed "entitlement snapshot" per
subject would recreate the frozen-roles problem this proposal exists to remove.
Replicating the grant graph to every evaluation point — a data bundle each
service's policy engine pulls and evaluates locally — fails for two independent
reasons. There is no partition boundary to bound a bundle to: Nova, Neutron,
Cinder and Glance each serve arbitrary projects in arbitrary domains from any
node, so there is no per-node scope the way a Kubernetes cluster is at least
self-contained. And the blast radius is categorically worse than the
single-organization case that precedent comes from, because an OpenStack grant
graph spans mutually distrusting tenants: "every compute node holds every
tenant's grants" is a disclosure decision, not a caching decision. Both are
constraints on where grant _facts_ come from and say nothing about where policy
is _evaluated_ — a per-service OPA sidecar asking this API live is unaffected
(§4.4).

#### Keeping a decision cache fresh: the options

A cache in front of a decision has to decide when to stop trusting what it
holds, and every answer trades revocation latency against check traffic. The
choice is operator-visible, so it belongs in the API rather than in each
service's configuration file, and the options are worth setting out in full
before one is adopted.

**Option A: do not cache at all.** Every policy evaluation calls the decision
tier. Revocation is instant in both directions and there is no freshness
contract to specify. The obvious objection is the multiplication: one inbound
API call evaluates policy once for the collection and again per item (see the
re-check requirement below), so a thousand-item list is a thousand decisions.
But the batch request of §4.3 collapses those into one call, and the
request-scoped memo below removes the repeats, which leaves roughly one tier
call per inbound request — the same round-trip count deployments already pay
for token validation today, against a cheaper call. No-cache is therefore a
legitimate configuration rather than an absurd one, and it is the right one for
a deployment whose compliance posture forbids ever acting on a stale allow. What
it costs is latency on the hot path and a hard dependency on tier availability,
which is what §8's fail posture is for. No phase may assume it away.

**Option B: one short uniform cache lifetime.** Sixty seconds is a sensible
default. It is one dial, needs no schema change, and behaves identically on
every driver — SQL, Raft, an LDAP-backed identity domain and an external
relation store alike. It bounds staleness in _both_ directions: a revoked grant
stops working within the lifetime, and a new grant starts working within it. The
comparison that matters is not against a perfect mechanism but against the
status quo, where a token is accepted for its full multi-hour lifetime and
`keystonemiddleware`'s validation cache adds a window on top of that. A
sixty-second bound on every authorization fact in the cloud is a strict
improvement on what deployments run now.

**Option C: per-result lifetimes.** Keep the `ttl` in each result of §4.3 and
let the tier choose it. Two reasons survive independently of any invalidation
mechanism: a decision that depends on a credential or a delegation with a known
expiry can be clamped to it, and a deployment may want denies held longer than
allows, because a stale deny is an inconvenience while a stale allow is a
security failure. Note that the asymmetry runs that way — allows short, denies
longer — precisely because there is no early-drop signal; a mechanism that could
clear a revoked allow early would invert it. Costs nothing beyond a field the
response already carries.

It is worth recording that this inverts the closest precedent. The Kubernetes
webhook authorizer caches allows far longer than denies — minutes against tens
of seconds — because its case is a single-tenant control plane where a stale
deny breaks a controller. Ours is a multi-tenant cloud where a stale allow is a
cross-tenant security failure. The inversion is deliberate, and reading it as
deliberate matters when the Kubernetes defaults are cited as a baseline.

**Option D: a cloud-wide generation number, polled.** One row holding one
integer, bumped by any write that can change any decision. Enforcement points
read it cheaply, on a timer or alongside a check they were making anyway, and
flush their whole decision cache when it moves.

Coarseness is not a shortcut here, it is the load-bearing property. The
tempting refinement — a counter per subject, so only the affected caches drop —
does not avoid the failure mode it looks like it avoids, because bumping it
still requires computing which subjects a write affects: adding one user to a
large group means bumping every member's counter, and adding a domain-level
inherited grant means bumping every subject beneath it. That is exactly the
"which cached entries does this write affect" fan-out whose repeated
incompleteness drove Python Keystone to coarse full-region cache flushes, merely
relocated from cache-key deletion to counter bumping and no more tractable
there. A single cloud-wide integer is the one form in which no writer has to
compute anything.

It also delivers what no per-subject scheme can, namely near-instant
propagation of new grants as well as revocations, and it lets the lifetime of
Option B be much longer between changes. The costs are real and bounded: every
assignment write empties every cache in the cloud, so the re-check herd needs
the jitter and per-`(subject, target)` coalescing that §9 already requires of
the check type, and in a cloud with continuous assignment
churn the cache never warms. It cannot see writes Keystone does not mediate
either, so it bounds nothing by itself and has to sit underneath a lifetime
rather than replace one. The schema cost is one row, which makes it worth
investigating on the merits.

**Option E: push invalidation.** Covered in §8: Keystone has no mechanism for
pushing anything to services today, so this is new infrastructure rather than a
configuration change, and it is out of scope for the phases below. Coarse push
is Option D with a transport instead of a poll. _Targeted_ push — telling a
cache which entries to drop — requires computing which subjects a write affects,
which is the fan-out Option D exists to avoid.

**Option F: source-versioned freshness tokens.** The elaborate option. It is
rejected below, and explicitly rather than silently, because the response
format reserves a field for it.

#### Why source-versioned freshness tokens are rejected

The design is worth stating before rejecting it, because it is sound and the
reasons it loses are not the obvious ones.

The tier seals into an opaque token the identity and current value of every
grant source a decision consulted: the subject's grant row, each group it
resolved through, each hierarchy ancestor it inherited from, plus a cloud-wide
epoch for the structural facts (role implications, the role-to-permission map,
hierarchy moves, deletions). Revalidating an expired entry becomes decode, read
those counters by key, compare — and because an allow's consulted set is the
granting path itself, that set is a handful of sources however large the cloud
is, so the comparison replaces the traversal that _discovers_ the path. That is
the entire appeal, and it depends on the token being sealed rather than hashed:
a bare digest can only answer "identical or not" after the tier has already
recomputed the state, which is the expensive half of the work.

It would also carry two requirements that are easy to get wrong. The token has
to be sealed with authenticated encryption rather than signed over readable
content, or every enforcement point in the cloud learns the group names a
subject resolved through and the target's domain ancestry, disclosed between
tenants that do not trust each other. And it has to bind
`(subject, operation, target, allowed)`, or revalidation becomes a
decision-laundering path: a caller presenting a token minted for someone else's
allow, beside a cache entry of its own invention, would be told "unchanged"
about a decision the tier never made.

Four things sink it.

**No single driver owns all the inputs.** A decision is a function of five
things and they live in four crates: grants in `assignment-driver-*`, group
membership in `identity-driver-*`, the project and domain hierarchy in
`resource-driver-sql`, role implications in `role-driver-sql`. A composite token
spans all four, so there is no transaction in which its counters can be read
consistently. Worse, `crates/identity-driver-ldap` is permanently read-only:
group membership lives in the directory and changes there with no Keystone write
to attach a counter bump to. ADR 0034 makes the driver a per-domain choice, so
one cloud runs an LDAP domain beside a SQL one. The structural objection this
section makes below against minting a token over an externally owned assignment
store — a minter that cannot observe every write cannot mint — therefore applies
to the native path too, for any domain whose identity backend is external.

**The counter bump is a correctness invariant in four write paths.** It has to
commit in the same transaction as the write it describes. A bump that lands late
or not at all leaves a revoked grant revalidating as fresh — a stale _allow_,
the one failure class an authorization system cannot have, arriving silently.
Holding that invariant means every write path added to four crates in future
remembers it, with nothing in the type system to enforce it.

**It buys compute, not latency, and only in a narrow band.** Revalidation is
still a round trip; only the cache lifetime removes one. A new grant still waits
out the lifetime, because a source that was never consulted has no counter in
the token — so the mechanism accelerates revocation and not propagation, and
propagation is the direction users file bugs about. The counters short-circuit
only when nothing moved: where assignments are near-static a longer lifetime
gets nearly the same effect for no code at all, and where they are not, the
counters have moved and the traversal happens anyway. What is left is the band
where writes are frequent enough that operators refuse a long lifetime and rare
enough that counters usually have not moved.

**The counter table becomes the hottest row set in the deployment**, written by
every grant write and read by every revalidation, with single rows — the epoch,
the operation registry — that every hierarchy move and every role-implication
edit serializes on. That is write contention bought with read compute, and
whether a batch of point reads actually beats a traversal served from the tier's
own warm state is a measurement nobody has taken.

One piece of the design is worth keeping because it costs nothing: a monotonic
mint stamp on each result, so a slow response cannot clobber a newer entry in a
shared `oslo.cache`. A set of counters is only partially ordered and could not
serve that purpose anyway; a stamp needs no counters and no new tables.

#### What the assignment driver still changes

Rejecting Option F removes most of the per-driver difference, but not all of it,
and what remains is a property of each _input_ rather than of the assignment
driver as a whole:

| Decision input | Written through | Every write observable by Keystone? |
| --- | --- | --- |
| Direct and group grants | `assignment-driver-sql`, `-raft` | yes |
| Direct and group grants | `assignment-driver-openfga` | no — deployment-owned provisioning writes tuples straight to the store (ADR 0035, Context) |
| Group membership | `identity-driver-sql` | yes |
| Group membership | `identity-driver-ldap` | no — the driver is read-only and the directory is written elsewhere |
| Project and domain hierarchy | `resource-driver-sql` | yes |
| Role implications, role-to-permission map | `role-driver-sql`, operation registry (§6.1) | yes |

Only an all-SQL deployment can observe every input, and since the driver is a
per-domain choice, "all-SQL" is a property of a domain rather than of a cloud.
Any scheme that needs to observe every write is therefore a per-domain
capability at best, which is the second reason Option B is the baseline and
Option D an investigation rather than a plan.

On an externally owned store the limit is structural rather than a matter of
lag, and it is worth being precise about why, because both of the rejections
above lean on it. Relation sync is asynchronous by design (ADR 0035, "Why not
inside the write transaction"), so anything minted at SQL commit would advertise
a freshness the relation store has not reached — leaving a cache
confidently stale rather than detectably stale, the worse of the two. The store
is also eventually consistent by default, so even a read issued after an
observed write is not guaranteed current. What that leaves:

| Property | All inputs Keystone-observable | Any input externally written |
| --- | --- | --- |
| Freshness bound | the cache lifetime | the cache lifetime |
| Early drop | reachable in principle, per domain (Option D) | not reachable |
| Revocation latency bound | the lifetime | the lifetime, plus relation-sync lag for the memberships Keystone syncs |
| Local evaluation of grants | technically possible, refused (§10, question 8) | structurally impossible: a decision is a graph traversal, not a fact to copy |
| Operator's freshness dial | the lifetime | the lifetime |

The columns very nearly converge, and that is the payoff of not building Option
F: one operator-visible freshness model across every driver, instead of a SQL
feature sitting beside an external-store limitation. Two things are still worth
investigating and must not be assumed by any phase. The external store's own
consistency controls may expose a token that can be passed through, which would
be the honest way to give the right-hand column an early drop. Its changelog
(`ReadChanges`) offers after-the-fact detection bounded by a poll interval,
which is Option D by another route and weaker than invalidation.

#### The cache contract

So the contract is deliberately small, and the same on every driver:

- A decision cache keyed on `(subject, target)` sits in front of
  `/v4/authz/check`; the live call happens on a miss or on expiry. Running with
  the cache disabled is supported (Option A) and is the correct posture for a
  deployment that cannot act on a stale allow.
- Each result carries its own lifetime, chosen by the tier and clamped by the
  operator (Options B and C). Sixty seconds is the default; a decision derived
  from a credential or delegation that expires sooner is clamped to it.
- Each result carries a monotonic mint stamp, for compare-and-set against a
  shared cache. It is not a freshness signal and must not be treated as one.
- The response format reserves an opaque `version` member. It is unspecified,
  absent today, and a caller must treat an absent version as "lifetime is the
  only bound". Reserving it keeps Option D or an external store's own token
  addable without an API change; nothing in any phase below depends on it.
- A cloud-wide generation number (Option D) is an investigation, not a
  commitment, and would shorten revocation latency for Keystone-mediated writes
  only.

What actually removes the bulk of the traffic is not the cross-request cache at
all, but the request-scoped memo below — and that one has no freshness problem
to solve, because it lives and dies with a single request.

#### Request-scoped deduplication, a separate mechanism from the cache

One inbound API call can evaluate policy many times: the collection-level
decision plus one per item, per the re-check requirement below. Those
evaluations frequently ask the same `(subject, target, operation)` question. A
shared cross-request cache does not deduplicate them reliably — entries can be
evicted or expire mid-request, and on a cold cache every one of them is a miss —
so an in-memory memo scoped to the request and discarded with it is a
requirement alongside the shared cache, not a substitute for it. It is also what
gives a request one consistent view: a request that asks the same question twice
should not get two different answers because an assignment changed in between.

This is the caller-side counterpart of ADR 0030, which solves the same problem
inside Keystone. Nothing in `oslo.policy` provides it today, so it is part of
the check-type work in §9.

#### Capacity is isolated per caller class, not merely rate-limited

Rate limiting caps what one caller can do to itself. It does nothing about the
problem this API creates at scale: a large unrelated integration's traffic
degrading queueing and latency for the core services sharing the same decision
tier. Nova's checks are not optional — a check that does not complete is a user
request that fails — while a third-party reporting integration's checks are
sheddable. Those two must not compete for the same queue on equal terms.

So the decision tier declares **traffic classes** with per-class concurrency
limits and admission control, shedding the lower class first, with separate
deployments as an option on top rather than as the mechanism. The isolation key
costs nothing to obtain: the tier already authenticates every caller by SVID on
the internal interface, so the SPIFFE trust domain or SVID path prefix is
available without inventing an identity concept for it.

Two things about the cost model matter more than the limit values:

- **Accounting is in decisions, not requests.** The API is deliberately
  batchable, so one request can carry a thousand `(target, operations)` pairs,
  and a per-request limit is bypassed by batching. ADR 0022's rate limiting is
  request-count limiting keyed on IP or username with no notion of per-request
  cost and no concurrency control, so this is new work rather than an existing
  mechanism to configure.
- **The number to size is decisions per second**, not cache entries. The
  per-item re-check below amplifies one user action into a page's worth of
  decisions, so a deployment guide that documents only cache sizing (§8) has
  documented the smaller half of the capacity question.

Both depend on being able to see the traffic, which makes per-trust-domain
attribution a prerequisite and not a later nicety: decisions per second, cache
hit ratio, denial rate and shed count broken down by caller class belong in the
metrics (ADR 0031) that ship with the tier. Quotas that cannot be measured
cannot be set.

#### Collection reads and the per-item re-check

The security model requires list endpoints to re-enforce the per-item read
policy against each record's own identifiers (I8), and forbids replacing that
with a permissive collection filter (I8a). A cross-project list under
`system-scope="all"` therefore cannot be one decision: it is a collection-level
decision plus one per-item decision per record. Three things keep that from
being a per-record round trip:

- **Batch checks.** The API takes a list of `(target, operations)` pairs in one
  call, so a page of results is one request, not one per row.
- **Grant-shaped short-circuit.** When the collection-level decision was allowed
  through a system or domain grant that covers every project in the page, the
  per-item check is answered from that same grant rather than re-derived. This
  is a short-circuit in the _evaluation_, not a relaxation of I8: each item is
  still decided against its own owner, and an item owned outside the grant's
  reach still has to be decided on its own and dropped if denied.
- **Page-scoped caching.** Decisions are cached per `(subject, target)`, so a
  page whose rows share few owners costs few distinct decisions.

The consequence is that cross-project listing is more expensive under this model
than a system-scoped token that services interpreted themselves, and deployments
must size the check API for it.

#### Bootstrapping and Keystone's own authorization

Keystone is itself a service with authorized APIs, so the circularity has to be
stated rather than discovered. Keystone evaluates its own policies against its
own assignment data in-process — it does not call `/v4/authz/check` over the
network to authorize a call to itself — and `/v4/authz/check` is itself
authorized by the caller's SVID at the internal interface, not by a recursive
check. The first grant in a new deployment comes from the existing bootstrap
path (`keystone-manage`, operating on the store directly), exactly as today. In
addition, Keystone exposes a local admin interface over a Unix domain socket: it
carries the full API, is reachable only from the host, and authenticates the
caller by SVID, so a high-security perimeter can drive administrative calls
without a bearer token and with the same policy checks the network API applies.

### 6.4 Binding operations to workload identities

With permissions as a unit of grant, a mapping rule (ADR 0020) can bind an
identity to exactly what it needs:

```json
{
  "name": "cluster-autoscaler",
  "matches": {
    "all": [
      {
        "claim": "spiffe.id",
        "match": "prefix",
        "value": "spiffe://td/project/"
      }
    ]
  },
  "binding": {
    "identity_mode": "ephemeral",
    "project_id": "${claims.spiffe.project_id}",
    "permissions": [
      "compute:servers:create",
      "compute:servers:delete",
      "compute:servers:list"
    ]
  }
}
```

No role is created, no policy file is edited in Nova, and the grant is visible
and revocable in Keystone. This is the AWS STS pattern, with one difference
worth naming: the permission set assumed at authentication time is an upper
_bound_ on what the call may do, not the decision itself. The decision also
needs the target, which this proposal binds per request (§5.1), and the grants
the subject holds on that target, which stay in Keystone. There is deliberately
no mint-time document that answers the question by itself — which is why the
check API exists, and why attaching a small precomputed policy to the credential
is not an alternative to it. Human users get the same through service grants
with a permission list (ADR 0036 §4) or through self-imposed `restrictions`.

### 6.5 Resource-level targets

Once services pass `target.<resource>` with a stable id, a grant can name a
resource (`server:<id>`) rather than a project. This is how sharing a single
image, a single network or a single secret with another principal becomes a
Keystone grant instead of a per-service sharing API. It is a later phase and
depends on services registering their resource types, but the check API shape
does not change.

This is where a relation store earns its keep: resource-level grants are the
shape OpenFGA (ADR 0033) models well, and a deployment that runs one can back
this phase with it. Per principle 9 that stays a backend choice — the same
grants are expressible on the SQL assignment driver, and no phase of this
proposal requires a relation store to be deployed.

Sharing rules that a service computes today from its own tables — Neutron's
`rbac_policy` entries being the largest example — do not have to become Keystone
grants to move under the check API. A service can keep owning that data and pass
it per call as `context` (§6.2): the engine evaluates the sharing condition, the
service keeps no enforcement branch. Turning those rows into first-class
resource-level grants is then an optional later step, taken if and when the
service wants them managed and audited centrally.

### 6.6 Quota and unified limits

Quota is the one place outside policy where services read the token's scope as
an authoritative project id: it decides which project a new resource is charged
to, and which project's limit is enforced. Moving the scope into the request
does not change what quota means, but it changes where the project id may come
from. The rule follows §5.1: quota is charged to the **resolved** target, which
for a create is the requested target after the service has accepted it, and
never to a value read out of the credential. Two consequences deserve stating in
the unified-limits work rather than being left to each service:

- A create under `system-scope="all"` has no project to charge and must be
  rejected; a cloud administrator creating a resource for a tenant names that
  tenant's project as the target (§7.1), and quota is charged there, to the
  tenant — which is also what makes the operation auditable.
- A delegated call is charged to the delegated project, the same project the
  delegation boundary pins the decision to (I2), so a service grant cannot be
  used to charge one tenant's resources to another's quota.

## 7. What this solves

### 7.1 System scope and the SRBAC personas

The personas survive, system scope survives, and the scope moves out of the
credential. An operator who holds `admin` on `system` sends
`OpenStack-Target: project="P"` when creating a server for a tenant, and Nova
asks Keystone whether that subject may `compute:servers:create` on P. Keystone
says yes because the system grant is inherited. The created server has an owner
(P), quota is charged to P (§6.6), and listing works with `project="P"`.

This is the part of the SRBAC design that did not work, and it is worth being
precise about why. The blocker was never "what is a system administrator"; it
was that a system-scoped _token_ arrived at Nova with no project in it, so
"create a server as the system" had no owner. Per-request targets remove that
situation entirely: the same principal, holding the same system grant, names a
project on the calls that need one. Nova does not need new semantics for
system-scoped creates, because there are none — a create always names a project.
Every service gets consistent persona semantics from one authority instead of
implementing them in its own policy file.

### 7.2 Global reader

A `reader` grant on `system`, inherited, allows every `*:list`/`*:show`
operation on every project. An auditor lists servers with
`OpenStack-Target: system-scope="all"`; Nova checks `compute:servers:list` on
the system target, receives allow, and runs its all-projects query — the same
all-projects query it already runs for a system-scoped token today. No token per
project, no `admin`, no new role in any service, and no new scope type: a
service that supports system scope today supports this, and one that does not is
no worse off than it is now. The per-item obligations of I8 apply as in §6.3.

### 7.3 Admin is global

`admin` on project A now yields `allowed: false` for any target other than A,
because the check is always against the resource's own target. A cloud
administrator is an explicit `admin` grant on `system`. There is no
`is_admin_project`, no `admin` special-casing in policy files, and the
distinction between project administrator and cloud administrator is a Keystone
fact rather than a per-service convention.

### 7.4 Service users with `admin`

A control-plane service acting as itself is identified by its SVID, is mapped to
a principal, and holds the `service` permission set on `system`; nothing else,
and in particular no password and no `admin`. When it acts for a user it
forwards the user's JWT or performs an on-behalf-of exchange, and the policy
sees both the user (`credentials`) and the service (`service_credentials`), so
"only `nova-api` may call `create_port` with `device_owner=compute:*`" is a
plain rule.

### 7.5 Trusts

Replaced as described in §4.5. The remaining trust-shaped use cases in Heat,
Magnum, Mistral, Glance, Nova and Cinder each have a documented migration in ADR
0036 §10.

### 7.6 Cross-project operations

Live migration, image sharing, network RBAC, volume transfer and quota
management all involve a caller acting across targets. With per-request targets,
a single token and a single check per touched target express them without
rescope. Services that today keep a `service_token` fallback to bypass scope can
drop it.

### 7.7 Domain manager

`manager` on `domain:D` is a grant like any other; Keystone resolves it for
`OpenStack-Target: domain="D"` and, when inherited, for every project in D. The
domain-manager persona that has taken several cycles to plumb through Keystone
policies is a permission set plus inheritance, and other services get it for
free.

## 8. Revocation, offline validation and the back-channel

Offline JWT validation removes Keystone from the data path but freezes
authorization for the token lifetime (ADR 0026 §11, SPIRE plan "Mode C"). The
SPIRE plan names three `keystonemiddleware` postures: **Mode A** legacy
(plaintext back-channel), **Mode B** SPIFFE mTLS with a per-request back-channel
call (keeps instant revocation), and **Mode C** JWT offline validation (no
back-channel, trades instant revocation for zero round trips). The proposal
changes the trade-off in a useful way:

- **Authentication** is validated offline: signature and expiry.
- **Authorization** is checked against live Keystone data on every cache miss.
  Disabling a user, removing a role, revoking a grant or narrowing a delegation
  takes effect at the next cache expiry, which an operator sets independently of
  the token lifetime — sixty seconds by default, and §6.3 argues against raising
  it far without an early-drop signal to compensate.
- An optional signed revocation feed (`/v4/oauth2/{domain}/revocations`, SPIRE
  plan "Mode C") bounds credential revocation without a per-request round trip.
  It does not bound grant revocation: no early-drop signal for cached decisions
  is committed to, because the mechanism that would provide one is refused on
  cost (§6.3, "Why source-versioned freshness tokens are rejected") and a coarse
  cloud-wide generation number remains an investigation there. The cache
  lifetime is the bound, plus whatever replication lag the serving tier carries
  ("Splitting the control plane from the data plane", below).

Two mechanisms are involved, and the proposal commits to only the first.

**Default, and all that Phase 2a/2b assume: pull, with a short-lived cache.**
The caller holds a decision cache and re-checks on miss or expiry. This needs no
new transport: `oslo.cache` over memcached is already the deployed pattern for
token-validation caching, and the `keystone` check type of §9 uses it. What is
new is capacity rather than software — entries scale with distinct
`(subject, target)` pairs rather than with tokens (§2.2), so an existing
token-cache deployment is not automatically sized for this.

**Future, and explicitly out of scope for these phases: push invalidation.**
Keystone has no mechanism today for pushing anything to services, so this is new
infrastructure rather than a configuration change. The plausible shape is a
per-host agent following the SPIRE-agent deployment model Phase 1 already
commits to, subscribing to invalidations and serving them to the enforcement
points on its host. No phase here should assume it exists. On an externally
owned assignment store it would additionally require the store to notify
Keystone first, which is not something Keystone can require of it (§6.3).

Keystone therefore remains a runtime dependency, as it is today, but with a
cache in front that degrades gracefully: on Keystone unavailability, cached
decisions remain valid until their TTL and new decisions fail closed. This is
the same posture `keystonemiddleware` has with its token cache, and the same one
Kubernetes API servers take with webhook authorizers.

That posture is an operational requirement of the same weight as the SPIRE
dependency, and it has to be written down where operators will read it rather
than inferred:

- Deployment guides state the fail-closed behaviour explicitly: when the check
  API is unreachable and no cached decision applies, the request is denied, and
  the cache TTL is the length of the resulting brown-out.
- Cache sizing is a documented number, not a default. The entry count scales
  with distinct `(subject, target)` pairs, not with tokens (§2.2), so a
  multi-project workload sizes differently than today's token cache.
- Multi-region deployments need a region-local read path for the check API —
  Raft learners or read replicas — because a cross-region round trip on every
  cache miss puts a WAN in the middle of every API call. §4.4 states this as a
  federated serving layer over a single write path, which is the general form of
  the same requirement.
- Capacity is stated in decisions per second alongside cache entries, and in
  per-caller-class terms, per §6.3.

#### One fail posture does not fit every caller

Fail-closed on a cache miss is the right default and the wrong universal rule.
It is correct for `compute:servers:delete`. It is needlessly harsh for a
read-only third-party integration that would rather act on a
stale-but-still-correct decision than return 5xx to its own users. Once Keystone
is the authorization authority for callers well outside OpenStack's own stakes,
a single cloud-wide switch is no longer expressive enough, so the posture is
declared per caller and per operation:

- **deny** — fail closed at TTL expiry, the default and the only posture for
  anything mutating;
- **grace** — serve the last known decision past its normal TTL for a bounded
  window, stale-while-revalidate style, re-checking in the background.

Four constraints make this a safety feature rather than a hole, and each is
load-bearing:

- **The posture is a property of the grant, never of the request.** It is set on
  the integration's registration or on the service grant (ADR 0036) and returned
  by the decision tier with the decision. A caller that could ask to be served
  stale could extend its own revocation window on demand, which is a revocation
  bypass wearing an availability costume.
- **Grace replays an earlier allow; it never manufactures one.** Serving a
  stale deny is free, serving a stale allow is the entire risk, and no posture
  turns a deny — cached, fresh or absent — into a permit.
- **Never for a delegated chain.** A decision whose authentication chain carries
  `act`, `delegation_context` or `restrictions` is never grace-served. A
  delegation's value is a narrow and promptly revocable boundary, and stale
  allows directly undercut I2/I4.
- **The stricter of the two declarations wins.** Operation class comes from the
  operation vocabulary (§6.1) and caller class from the registration; where they
  disagree the more conservative applies, so a caller's read-only posture can
  never leak onto a mutating operation.

A grace-served allow is also a distinct audit event (ADR 0023), not silently
equivalent to a fresh one. "Allowed on current data" and "allowed on data up to
N seconds old" are different facts, and an auditor reconstructing an incident
needs to tell them apart. The same posture is what a caller's circuit breaker
applies when the tier is unreachable (§9), which is why it has to be delivered
with decisions and cached ahead of time: at the moment the breaker opens, the
client can no longer ask what posture it has.

Crossed with §6.3, grace is available on either assignment driver but means
different things: on the SQL driver it extends a bound that a write can already
cut short, and on an externally owned store it stacks on a TTL that was already
the only bound there was.

#### Splitting the control plane from the data plane

The split of §4.4 — a write path that mutates grants, a decision tier that
evaluates them — is the industry's answer to this section's problem, and it is
worth being precise about what it does and does not buy. On its own it buys
nothing on availability: one decision tier is the same single point of failure
with a different process name. What it buys is independent scaling, an
independent release cadence and a containment boundary. Availability comes from
three further properties, and each has to be a requirement rather than a
deployment habit.

**Static stability.** Every decision-tier replica holds a durable local copy of
the inputs it serves and keeps serving from that copy while the write path is
unreachable — for the length of the outage, not for a cache lifetime. The
corollary is the one implementations lose: no startup dependency on the control
plane. A replacement replica must cold-boot and begin serving with the write
path down. A tier that can only warm its state by calling the component it
exists to survive is coupled to it, whatever the deployment diagram says.

**One failure domain per serving tier.** The federated serving layer of §4.4 is
the definition of a supported high-availability topology, not one option among
several: a tier per region, no cross-domain call on the read path, and a
partitioned region degrades alone.

**Two lags, both operator-visible.** §6.3 bounds how long an enforcement point
holds a decision. Replication lag bounds how far behind the write path the tier
that minted it was. What an operator can promise is the sum, and a deployment
that publishes only the cache lifetime is understating its revocation window.

What the split buys is larger than it looks, and it is the actual answer to
"Keystone must not be a single point of failure": after this proposal
Keystone is not on the data path at all. Authentication is validated offline,
authorization is served by replicated tiers, and a total control-plane outage
costs exactly this and nothing more:

- no new or changed grants, role definitions or implied-role edits;
- no operation-vocabulary changes (§6.1);
- no credential, delegation or service-grant issuance (§4.5, ADR 0036);
- no project, domain or user lifecycle operations.

Existing workloads keep authenticating and keep authorizing throughout. That
list is a deployment-guide statement rather than an implementation detail: it is
what an operator is buying, and it belongs alongside the fail-posture and
cache-sizing numbers above. Read against §2.2, where a Keystone outage is a
cloud outage because token validation runs through it, it is the largest
availability change in this proposal.

One further lever is already in the repository and unremarked. Per-domain
drivers (ADR 0034) make the write path shardable by domain, so a cloud-wide
control-plane failure domain is a deployment default rather than something this
architecture requires.

Every large platform that decides authorization centrally has converged on the
same two answers, and the convergence is more useful than any single precedent:

| Platform        | Where evaluation happens                                                 | Grant propagation                                | Freshness mechanism                                                               |
| --------------- | ------------------------------------------------------------------------ | ------------------------------------------------ | --------------------------------------------------------------------------------- |
| AWS IAM         | in-region, per-service data plane over asynchronously replicated policy  | eventually consistent, documented as such        | replication only; statically stable by design                                     |
| GCP (Zanzibar)  | replicated ACL servers per cluster over Spanner                          | snapshot-consistent per request                  | consistency tokens, plus a materialized closure index fed from a changelog        |
| Azure Entra     | the resource provider evaluates entitlements carried in the token        | role-assignment changes propagate in minutes     | short token lifetime, plus an event channel for a few critical account events     |
| Kubernetes      | in-process RBAC over a watch-fed cache, or a webhook authorizer          | watch-fed: seconds; webhook: the cache lifetime  | the watch, or authorizer cache lifetimes                                          |

Nobody keeps grant propagation synchronous, and everybody buys availability by
replicating the evaluator rather than the enforcement point. Azure is the one
exception on the second count, and it pays with precisely the frozen-scope
problem §2.1 exists to remove — and even there the push channel carries critical
account events, not role assignments. Kubernetes' in-process RBAC is the
grant-graph replication §6.3 refuses, and the reasons it works there do not
transfer: the graph is small, a cluster is a scope boundary, and there is one
enforcement point rather than one per service.

Four shapes could reduce the coupling further. Only the first is recommended
now.

- **Federated tiers, statically stable, with both lags published.** The three
  requirements above. No new component and no new protocol — a hardening of
  §4.4 rather than an addition to it.
- **A node-local decision agent.** A per-host agent on the SPIRE-agent
  deployment model Phase 1 already commits to, holding the decision cache for
  every enforcement point on its host. It collapses cache sizing from
  per-process to per-node, gives push invalidation exactly one subscriber per
  host if that is ever built, and lets a whole node ride out a tier outage on
  its grace window. It is not grant-graph replication: the agent holds only the
  `(subject, target, operation)` results its own host asked for, so the
  cross-tenant disclosure argument of §6.3 does not apply to it. Identified, not
  committed to — nothing in Phase 2 needs it, and it is new deployment surface
  that should follow measured decision rates rather than precede them (§10,
  question 10).
- **A materialized closure index inside the tier.** Group and hierarchy
  expansion precomputed and incrementally maintained: the Zanzibar answer to the
  same fan-out that Option F of §6.3 tried to put in a token. A scaling lever
  rather than an availability one, invisible to services, available where
  Keystone owns the inputs and unnecessary on a store that maintains its own.
  Worth reaching for if fan-out shows up in a profile, not before.
- **Entitlements carried in the token.** The best availability properties on
  this list by a wide margin — no runtime dependency on anything — and refused
  anyway, for the reason §2.1 gives. It is named here rather than omitted so
  that the refusal is visibly costed: this proposal trades the strongest
  availability story available for per-request authorization, knowingly.

Local evaluation in every enforcement point is not on that list. §6.3 refuses
it, and on an externally owned store it is unavailable at any price (§10,
question 8).

Static stability decays silently when it is not exercised, so it ships with a
test rather than a paragraph. The deployment guide names two game-day
exercises: stop the write path and verify that the cloud still authenticates and
still authorizes; partition one region's decision tier and verify that only that
region degrades, and to the posture it declared.

#### What a central authority costs

None of the above removes the trade this architecture makes, and the trade
should be named rather than implied to be free: a single authority for mutually
independent trust domains means its outage is everyone's outage at once, and a
bad grant write or policy rollout has cloud-wide and cross-tenant reach. The
mechanisms here shrink the blast radius (per-caller posture, per-class capacity)
and lengthen how long an outage is absorbed before it is felt (grace windows,
region-local serving, bulkheaded pools). They do not decouple anything.

This is the bet AWS made with IAM, and it is a defensible one — but the
precedent cuts both ways and is more useful read honestly. IAM's mitigation set
is the one above, regional isolation included, _plus_ accepting and documenting
eventual consistency in grant propagation. So the industry answer converges on
grace semantics as a normal property rather than a concession for low-stakes
callers. For OpenStack that is also an expectation change and not only an
architectural one: revocation today is nominally immediate, and this proposal
trades nominal immediacy for a bound an operator chooses and can read.

Two consequences follow for how the work is delivered rather than designed. The
decision tier and the policy bundle both need staged rollout and canarying,
because correctness blast radius is now as cloud-wide as availability blast
radius — and the policy bundle is already a named trust boundary with an open
supply-chain gap (`doc/src/contributor/security-review.md` §V4: a mutable
`:latest` tag, verification not wired into the load path). And the bet belongs
in front of operators at adoption time, as §10's open question on it records.

## 9. Migration and coexistence

Every phase is additive; Python Keystone, Fernet tokens and unmodified services
keep working throughout. Phase 2 is deliberately split: the per-request target
and the check API can land against today's scoped tokens and stand on their own,
while the scope-less token cannot ship until the constraints of §5.4 exist.
Nothing between 2a and 2b leaves a deployment holding unconstrained cloud-wide
bearer tokens.

```mermaid
flowchart LR
    p0["Phase 0<br/>shipped foundation"]
    p1["Phase 1<br/>control-plane identity"]
    p2a["Phase 2a<br/>per-request target"]
    p2b["Phase 2b<br/>scope-less JWT"]
    p3["Phase 3<br/>permissions"]
    p4["Phase 4<br/>delegation"]
    p5["Phase 5<br/>workload identity"]
    p6["Phase 6<br/>policy-engine path"]
    p7["Phase 7<br/>sunset"]
    p0 --> p1 --> p2a
    p2a -->|"gate: restrictions,<br/>audience, sender constraint"| p2b
    p2b --> p3 --> p4 --> p5 --> p6 --> p7
```

- **Phase 0 (shipped):** Rust Keystone beside Python Keystone; Fernet parity;
  OPA policies; `SecurityContext` invariants; mapping engine; OAuth2/OIDC
  provider.
- **Phase 1, control-plane identity:** SPIRE in devstack and deployment tooling;
  per-service and per-host SVIDs; `keystonemiddleware` SPIFFE transport (SPIRE
  plan Mode B).
- **Phase 2a, per-request target:** `OpenStack-Target` header;
  `/v4/authz/check`, served by the decision tier of §4.4 as a deployable
  component with its own scaling and availability story rather than as a
  property of the Keystone write nodes; the cache-aware `keystone` check type
  and its request-scoped dedup (§6.3, §9), shipping on per-result cache
  lifetimes alone with the `version` member reserved but unspecified (§6.3);
  middleware exposes the requested target as a client assertion; per-service
  adoption of the
  resource-owner-wins invariant (§5.1) and, where wanted, opt-in to the
  compatibility mode (§5.3); SDK header support. Tokens are still scoped, so
  this phase adds capability without weakening any credential, and each service
  migrates on its own schedule.
- **Phase 2b, scope-less JWT — gated:** may not start until the `restrictions`
  claim, service-type audience narrowing and sender-constrained presentation
  (DPoP for public clients, SPIFFE-ID binding for SVID holders) are all shipped.
  Then: scope-less access tokens, JWT offline filter (Mode C), and scoped tokens
  demoted to a compatibility option.
- **Phase 3, permissions:** operation vocabulary registry with versioning and
  fail-closed unknown operations (§6.1); role as permission set; mapping
  bindings with permissions; batch check API for collection reads (§6.3).
- **Phase 4, delegation:** service grants and on-behalf-of exchange (ADR 0036);
  Heat, Glance and Magnum pilots; trusts off by default.
- **Phase 5, tenant workload identity:** vendor data attestation; SPIRE node
  attestor; JWT-SVID client authentication; Magnum and Trove guests
  credential-less.
- **Phase 6, policy-engine path:** services that want central authorization move
  from `oslo.policy` `http` checks against `/v4/authz/check` to a full
  policy-engine input; the compatibility mode of §5.3 is switched off for those
  services one at a time; service passwords and service `admin` grants removed
  where no longer used; `X-Service-Token` retired once nothing depends on it.
- **Phase 7, sunset:** Fernet validate-only, then off; `/v3/OS-TRUST` removed;
  application credentials limited to off-cloud automation.

### 9.1 Two ways to consume the check API

Consuming `/v4/authz/check` is a spectrum of how much of the decision a service
hands over. The first mode is a valid place to stop, and it needs no change to
service code at all.

- **Mode 1, role resolution.** For every request the actor and the
  `OpenStack-Target` go to Keystone, which returns the effective roles and
  permissions on that scope; the caller then evaluates its existing
  `oslo.policy` rules locally, exactly as it does today with a scoped token. The
  only change from today is that the role set arrives per request instead of
  baked into the token — and that swap happens **inside `keystonemiddleware`
  and `oslo.policy`, not in the service.** The middleware already knows the
  request's scope, so it fills the target header; the `oslo.policy` `keystone`
  check resolves the role set. A service whose `policy.yaml` only tests
  scope-level facts (`role:member`, `project_id:%(...)s`, `system_scope:all`)
  ships unmodified: upgrade the two shared libraries and it is on Mode 1. This
  is the drop-in state when tokens go scope-less in Phase 2b.
- **Mode 2, full delegation.** The service sends the actor, the operation and
  the resource and receives allow or deny. It enforces nothing itself. This is
  the Phase 6 end state.

Both modes depend on the cache-aware, failure-aware check type above. The
mandatory per-request call to Keystone is only affordable because most such
calls are answered from cache, and "zero work for a typical service" only holds
if the cache, the dedup and the breaker live in the shared libraries rather than
in each service. The posture a breaker falls back to (§8) has to arrive with
decisions and be cached, since it cannot be fetched once the tier is
unreachable. Both also
inherit the per-driver freshness difference of §6.3 — a domain backed by an
external store gets TTL-bounded revocation in either mode — and Mode 2 inherits
it most visibly, because there the cached artifact is the decision itself rather
than a role set the service re-evaluates locally on every request.

**A deployment may stay on Mode 1 indefinitely.** It is not only a transition
rung. The price of stopping there is capability, not correctness: role
resolution answers only scope-level questions, so Mode 1 does not deliver
resource-level decisions — ownership, attributes, relations (§6.5, ADR 0033) —
permission-set personas beyond what the local rules already encode, or central
policy changes that take effect without redeploying a service. Everything each
service enforced before keeps working unchanged.

That is the point of the split. The mandatory work for the ecosystem is to
upgrade `keystonemiddleware` and `oslo.policy`; the mandatory work for a typical
service is zero. Per-service work starts only where a service opts into
something past Mode 1 — passing the resource owner as the target so its own
resource-scoped rules keep matching (§5.1), permissions, resource-level targets,
full delegation — each taken when that service wants the feature it unlocks, on
its own schedule or never.

Four rules hold across every phase, and they are what "additive" means in
practice:

- v3 scoped tokens and `OpenStack-Target` coexist. A scoped token's own scope is
  the requested scope, and a conflicting header is rejected (§5.3).
- Python Keystone keeps validating the tokens Rust Keystone issues (ADR 0026
  Phase 0) until it is retired.
- No Python-owned table changes; new state lives in Raft-backed drivers.
- Every phase has an off switch that restores the previous behaviour for one
  service without redeploying Keystone.

Held to those rules and to the gate on Phase 2b, the phasing delivers a system
strictly stronger than the status quo at every step: it removes long-lived
secrets from the control plane and from guests, makes every delegation visible
and revocable, gives every service the same persona semantics from one
authority, and makes the scope and role decisions behind the last decade of
authorization advisories impossible to key on the wrong input. The gate is the
load-bearing part — scope-less tokens without restrictions, audience narrowing
and sender constraint, or per-request targets without the resource-owner
invariant, would be a regression, which is why Phase 2 is split where it is.

Concrete dependencies on other projects:

| Project                        | Change                                                                                                                                                                                                                                            |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `python-keystonemiddleware`    | SPIFFE transport; JWT offline filter; `OpenStack-Target` parsing; `/v4/authz/check` client; `X-Requested-Target`/`X-Actor-*` env; per-service gate for the §5.3 compatibility mode                                                                |
| `keystoneauth1`                | Device-flow, `v4servicegrant`, `v4onbehalfof` plugins; per-request scope instead of per-session scope                                                                                                                                             |
| `oslo.policy`                  | A first-class **cache-aware, failure-aware** `keystone` check type wrapping `/v4/authz/check`: `oslo.cache`/memcached-backed decision cache, honouring the per-result lifetimes that let allows and denies be cached on different terms and treating an absent or unrecognised `version` member as lifetime-only (§6.3), request-scoped dedup (§6.3), a circuit breaker whose fallback is the posture delivered with the decision (deny or grace, §8) rather than retry-until-timeout, and jittered recovery with per-`(subject, target)` coalescing so a restored tier is not met by a synchronized re-check herd. Where a local fallback is offered at all it evaluates the service's existing `policy.yaml` against the last known role set (Mode 1), never a bespoke emergency ruleset. The existing `http` check works as a stopgap but provides none of these. Operation registry export |
| `openstacksdk`, CLI, Terraform | Send `OpenStack-Target`; stop re-authenticating per project                                                                                                                                                                                       |
| Nova, Neutron, Cinder, Glance  | **Enforce resource-owner-wins (§5.1) on every resource operation** before accepting per-request targets; pass resource owner as `target.scope`; charge quota to the resolved target (§6.6); drop `is_admin` shortcuts and service-token fallbacks |
| Heat, Magnum, Mistral, Glance  | Service grants / on-behalf-of instead of trusts (ADR 0036 §10)                                                                                                                                                                                    |
| Nova (compute)                 | `vendor_data_url` to Keystone; per-host SVID (SPIRE plan Phase 1-2)                                                                                                                                                                               |
| Deployment tooling             | SPIRE server and agents; OPA or the `oslo.policy` bridge; internal endpoints on SPIFFE mTLS                                                                                                                                                       |

## 10. What the community still decides

1. **Header grammar details.** `OpenStack-Target` as an RFC 8941 dictionary is
   proposed; open are the exact member names, whether `resource` is mandatory
   for single-resource operations once services support it, and how multi-target
   operations (server migration between projects, image sharing) name a second
   target.
2. **Where does the operation registry live?** In `oslo.policy` as generated
   documentation, in Keystone as a resource services register at startup, or in
   a separate governance-owned document?
3. **Cross-project listing for non-admins.** `system-scope="all"` reuses the
   existing system scope and therefore keys on a system-level grant, exactly as
   today. It leaves untouched the case of a user with roles on many projects who
   wants one listing across them; resolving that to "the set of projects the
   subject can read, with the service filtering" is friendlier to those users
   and considerably more expensive. Is it worth a separate target, or is it a
   client-side concern?
4. **DPoP versus mTLS-bound tokens for public clients.** DPoP is the OAuth
   standard; OpenStack clients have no established key-management story for it
   yet.
5. **Resource-level grants.** Whether and when to let Keystone hold grants on
   individual resources, replacing per-service sharing APIs.
6. **Retirement timeline for application credentials and EC2 keys** once
   off-cloud automation can use workload federation and on-cloud automation has
   SVIDs.
7. **Should driver-dependent freshness be an operator-facing capability
   matrix?** §6.3 states the difference as a table and principle 9 as a
   consequence, but whether each assignment driver declares a supported
   revocation-latency guarantee — a capability contract operators can hold the
   project to — or whether it stays an implementation note in ADR 0034 is a
   governance question as much as a technical one. Operators pick drivers on it.
   The same matrix is where a cloud-wide generation number, if the investigation
   in §6.3 goes anywhere, would have to declare which domains it can actually
   bound — an LDAP-backed or externally stored input is not one of them.
8. **Is anything owed to deployments that want local evaluation?** This proposal
   leaves live-check-plus-cache as the only shape, rejecting both pushed
   entitlement snapshots and grant-graph replication (§6.3). For a domain backed
   by an external store that is the only shape available in any case. For a
   SQL-only deployment willing to accept that every enforcement point holds
   every tenant's grants, local evaluation is technically reachable, and the
   question is whether that is documented as a supported option or named and
   refused. This proposal names and refuses it; a single-tenant deployment may
   reasonably disagree, and should say so here rather than build it quietly.
   What is _not_ open is whether the coupling exists: §8 states it as an
   accepted cost, and the question here is only whether an escape hatch is
   offered for the deployments that can afford one.
9. **How is the fail posture of §8 administered?** The posture model — deny by
   default, grace where a caller's stakes warrant it — settles the semantics but
   not the interface. Whether an operator sets it per registered integration,
   whether a domain administrator may set it for callers in their own domain,
   and what maximum grace window a cloud can impose over a domain's choice are
   governance questions with an API surface, and they should be answered before
   anything ships that can serve a stale allow.
10. **Is the node-local decision agent part of the target architecture or an
    optimization held in reserve?** §8 names it and declines to commit. It
    solves real problems — decision caches sized per process rather than per
    host, and no single place to deliver a push invalidation to — and it is the
    only form of local caching that does not spread grant facts to every
    service. It is also a new per-host component to deploy, secure and upgrade,
    on a cloud that is being asked to adopt a SPIRE agent in the same phase.
    Whether it belongs in the picture operators are shown, or appears only once
    measured decision rates justify it, is a question about appetite for
    deployment surface rather than about the design.

## 11. References

- [ADR 0002 — Open Policy Agent](adr/0002-open-policy-agent.md)
- [ADR 0005 — Passkey authentication](adr/0005-auth-passkey.md)
- [ADR 0008 — Workload federation](adr/0008-federation-workload.md)
- [ADR 0014 — Application credentials](adr/0014-application-credentials.md)
- [ADR 0017 — Security context](adr/0017-security-context.md)
- [ADR 0020 — Mapping engine](adr/0020-mapping-engine.md)
- [ADR 0021 — API-key ingress](adr/0021-api-key-scim.md)
- [ADR 0023 — Auditing](adr/0023-audit.md)
- [ADR 0025 — Dynamic authentication plugins](adr/0025-dynamic-auth-plugins.md)
- [ADR 0026 — OAuth2 / OIDC provider](adr/0026-oauth2-oidc-provider.md)
- [ADR 0030 — Per-request cache](adr/0030-per-request-cache.md)
- [ADR 0032 — Vendor data JWT attestation](adr/0032-vendor-data-jwt.md)
- [ADR 0033 — OpenFGA assignment driver](adr/0033-openfga-assignment-driver.md)
- [ADR 0034 — Per-domain assignment drivers](adr/0034-per-domain-assignment-drivers.md)
- [ADR 0035 — Relation sync provider](adr/0035-relation-sync-provider.md)
- [ADR 0036 — Service delegation](adr/0036-service-delegation.md)
- [Security model](contributor/security-model.md)
- SPIRE integration plan (`doc/plans/spire-integration.md`)
- OpenStack community goal: Consistent and Secure Default RBAC
- Keystone X.509 tokenless authorization (`[tokenless_auth]`)
- RFC 8693 (token exchange), RFC 9449 (DPoP), RFC 8705 (mTLS-bound tokens), RFC
  7523 (JWT client authentication), SPIFFE/SPIRE specifications
