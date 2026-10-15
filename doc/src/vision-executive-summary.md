# Executive summary: the authentication and authorization vision

**Status:** Draft for community discussion

**Date:** 2026-10-15

This page is for readers who decide rather than implement: Technical Committee
members, project leads and operators. It is one page by design. The
[vision](vision.md) holds the reasoning, the [roadmap](roadmap.md) holds the
order of work, and [IAM data plane and check API](iam-data-plane.md) holds the
design of the part that carries the most risk.

## The problem

Keystone predates the identity standards the rest of the industry is built on.
Its token model, API and scope-and-roles payload were designed in 2010–2012,
before OAuth 2.0 ([RFC 6749], October 2012), OpenID Connect (2014), JWT
([RFC 7519], 2015), SPIFFE (2017) and OAuth token exchange ([RFC 8693], 2020).
Those standards
were attached at the edges later and never adopted as the core. Federation goes
through Apache modules that map external assertions onto local users and groups.
OAuth 1.0a and OAuth 2.0 client credentials are extensions with a limited
coverage. JWS is just another token format carrying the same payload.
X-Auth-Token and /v3/auth/tokens are still OpenStack-only, so no gateway,
identity provider or service mesh can validate an OpenStack token or read its
roles without calling Keystone. Each problem below has to be fixed inside
Keystone instead of by adopting what other platforms already use.

An OpenStack token proves who the caller is, carries the project, domain or
system the caller may act on, and carries the roles held there, all frozen at
issuance. Every service validates it against Keystone and applies local policy
to what is inside ([§2](vision.md#today)). Following consequences hurt.

**1. Every request is a Keystone round trip.** A Keystone outage stops the cloud
the moment the validation cache expires ([§2.2](vision.md#keystone-round-trip)).

**2. Scope and roles in the token cannot express what operators need.** Policy
asks "does this token's scope match the resource", not "may this principal do
this to that resource". The two diverge in cross-project operations, cloud-wide
read and services acting for users, so system scope, global reader and "admin is
global" never worked cleanly and Secure RBAC stalled
([§2.1](vision.md#tokens-carry-scope), [§2.3](vision.md#system-scope-srbac),
[§2.4](vision.md#global-reader-admin-global)).

**3. Roles are the only unit of grant.** To let one workload call one operation,
an operator would create a role, wire it into every service's policy file and
assign it. Not all operators do this, and this is not triviel, so the workload
gets `member` or `admin`. Application credential access rules can only narrow a
credential that is already as privileged as its role, never grant
([§2.5](vision.md#roles-only-unit-of-grant)).

**4. Long-lived secrets are everywhere** ([§2.6](vision.md#secrets-everywhere)).
Each is a bearer secret whose theft looks exactly like legitimate use.

- Every service has a service user with a password in a config file and the
  `admin` or `service` role.
- Heat, Magnum and Mistral store trusts. Magnum ships a trustee password into
  every cluster VM. Heat ships a per-instance EC2 keypair into the metadata of
  every VM that runs its CloudFormation client.
- Tenant automation runs on application credentials or EC2 keys baked into
  images, Kubernetes secrets and CI variables, valid for months.
- Users authenticate with passwords in `clouds.yaml`.

**5. Trusts, application credentials and EC2 credentials are a recurring source
of vulnerabilities.** They are delegation mechanisms, and delegation is where
Keystone has repeatedly decided on the wrong input: the scope of the token
instead of the immutable record of how the caller authenticated
([security model](contributor/security-model.md)).

6. **Keystone doesn't scale well.** A massive swift/rgw cluster requires scaling
   Keystone to hundreds+ of instances only to validate request signatures.

- **[OSSA-2026-005] / [CVE-2026-33551].** A restricted application credential
  escaped its role restriction by minting an EC2 credential. Redeeming it at
  `/v3/ec2tokens` rebuilt the delegation chain but presented a bare project
  scope, so the credential inherited the owner's full project roles.
- **[OSSA-2026-015].** A delegated token was not bound to its delegation project
  on credential create, read, update and delete, so a delegate could reach
  credentials outside the project it was delegated.
- **Trusts have structural weaknesses besides bugs**
  ([ADR 0036](adr/0036-service-delegation.md)). The trustee is a user with a
  password that is copied to wherever the service runs. `expires_at` is
  optional, so a trust need not lapse. Any user can name any other user as
  trustee, and nothing caps the roles a service can receive. With
  `impersonation` downstream logs see only the trustor. One trustee holds every
  trust of its service, so activity cannot be attributed per trust. `OS-TRUST`
  is a home-grown protocol that no gateway, identity provider or audit tool
  understands, and it is expressed as token scope, which blocks scope-less
  tokens.
- **The pattern is the point.** Fixing each advisory closes one path. The vision
  removes the scope-keyed decision itself, and removes the delegated secret, so
  the next variant has less to key on.

OpenStack is the outlier on credential, scope location and workload identity
against AWS, GCP, Azure and Kubernetes ([§2.7](vision.md#industry-comparison)).

## The proposal

Modernize keystone and separate the three things the token conflates
([§1](vision.md#one-page)).

| Question             | Answer under the proposal                                                                                          |
| -------------------- | ------------------------------------------------------------------------------------------------------------------ |
| **Who** is calling   | A short-lived, scope-less JWT for the public API. SPIFFE mTLS inside the control plane.                            |
| **Where** may it act | The request says so, in an `OpenStack-Target` header or derived from the addressed resource.                       |
| **What** may it do   | The service's policy asks Keystone on every request, against a replica of live state, with no cross-request cache. |

Four further changes follow:

- **A secretless control plane.** Services authenticate by SPIFFE identity.
  Service users, service passwords and `X-Service-Token` go away
  ([§4.2](vision.md#control-plane-mtls)).
- **Trusts are replaced** by server-side service grants and [RFC 8693]
  on-behalf-of exchange. No secret is delegated, and every delegation is
  recorded ([§4.5](vision.md#delegation-without-secrets)).
- **Tenant workloads get identity without credentials.** A VM or cluster node
  attests and receives an SVID bound to its project
  ([§4.6](vision.md#tenant-workload-identity)).
- **Roles stay, permissions are added.** A rule, an operation or a set of them
  can be bound to any human, service or workload on any target, without
  inventing a role ([§6](vision.md#authorization-model)).

## What it costs

The costs fall on different parts of the community.

- **Operators deploy and maintain SPIRE.** The secretless control plane and
  tenant workload identity both need a SPIRE deployment: servers, an agent on
  every control-plane host and compute host, a trust domain, and the plumbing
  that registers each service. It is new infrastructure with its own upgrades,
  monitoring, backup and certificate-rotation practice, and it sits under every
  service-to-service call. Deployment tools and devstack have to ship it, and
  the roadmap makes this the first milestone
  ([§4.2](vision.md#control-plane-mtls), [A0](roadmap.md#a0-spire)).
- **Operators also take on a new availability model.** Authorization becomes a
  live check on every request, and an optional replicated data plane per failure
  domain keeps that from being a single point of failure. A total outage of the
  write path still stops all new logins, refreshes and exchanges, so the
  access-token lifetime becomes an availability setting
  ([§8.5](vision.md#outage-cost)).
- **Service maintainers change their policy and their API handling.** A service
  asks instead of reading roles out of the token, and it enforces that the
  requested target matches the resource's owner before it accepts per-request
  targets ([§5.1](vision.md#request-contract)). Each service may do this on its
  own schedule, or not at all.
- **Client and SDK authors take on new key management.** Public clients need
  sender-constrained tokens, and official OpenStack clients have no established
  story for holding a DPoP key yet ([§10](vision.md#open-questions)).
- **The community has to agree on shared contracts.** The header grammar and the
  operation vocabulary only work if projects adopt the same one, and who may
  write to the vocabulary is a decision about who holds a privilege
  ([§6.1](vision.md#roles-and-permissions)).

## How it is adopted

Every step is additive ([§9](vision.md#adoption)). Python Keystone, Fernet
tokens and unmodified services keep working. Every capability has a per-service
off switch. A deployment may stop at role resolution indefinitely and lose
nothing it had.

The [roadmap](roadmap.md) orders the work by dependency, not as one line of
phases, so teams can start in parallel: SPIRE and the secretless control plane,
the token format, the check API, and the policy engine.

## Decisions needed

Most questions belong to the community, not to this document
([§10](vision.md#open-questions)): the `OpenStack-Target` header grammar, where
the operation registry lives and who may write to it, DPoP versus mTLS-bound
tokens for public clients, and the retirement timeline for application
credentials and EC2 keys.

[CVE-2026-33551]: https://nvd.nist.gov/vuln/detail/CVE-2026-33551
[OSSA-2026-005]: https://security.openstack.org/ossa/OSSA-2026-005.html
[OSSA-2026-015]: https://security.openstack.org/ossa/OSSA-2026-015.html
[RFC 6749]: https://www.rfc-editor.org/info/rfc6749
[RFC 7519]: https://www.rfc-editor.org/info/rfc7519
[RFC 8693]: https://www.rfc-editor.org/info/rfc8693
