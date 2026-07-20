# 19. Credentials Provider Implementation

Date: 2026-06-09

## Status

Proposed

## Context

Keystone requires a secure mechanism to store and manage sensitive credentials
(e.g., EC2 access keys, TOTP secrets) for users. These credentials must be
encrypted at rest, support high-availability key distribution across clusters,
and provide a safe path for key rotation without risking data loss.

Keystone-NG is deployed **in parallel with the Python Keystone service** and
shares the same live database. This imposes hard constraints on this
implementation:

- Keystone-NG **never runs DDL** against tables owned by the Python Keystone
  service (schema evolution remains exclusively under Python Keystone's
  `alembic` control).
- All encryption and hashing behaviour must be **byte-for-byte compatible** with
  Python Keystone so that blobs written by either service can be decrypted by
  the other. Fernet compatibility is verified by cross-service tests.

---

## Decision

### 1. Architecture & Data Model

The Credentials Provider serves as a secure, encrypted vault for storing
sensitive authentication secrets used by various Keystone identity mechanisms.
It implements a "blind storage" pattern where the core API manages the metadata
and encryption, while the specific meaning of the secret is defined by the
`type` field.

#### Supported Credential Types

The provider treats the `type` field as an open string to allow extensibility.
Common types include:

- **`ec2`**: Stores AWS-compatible `access` and `secret` keys. Triggers
  deterministic ID generation via SHA-256 of the access key.
- **`totp`**: Stores Base32 encoded TOTP seeds for Multi-Factor Authentication
  (MFA).
- **Custom Types**: Any arbitrary string can be used to store secret blobs for
  third-party integrations.

#### Blob JSON Schemas Per Type

Each credential type carries a typed JSON blob. The following schemas define the
expected structure:

**EC2 Blob:**

```json
{
  "access": "AKIAIOSFODNN7EXAMPLE",
  "secret": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "trust_id": "optional, present if created via a trust-scoped token",
  "app_cred_id": "optional, present if created via an application credential",
  "access_token_id": "optional, present if created via an OAuth1 access token"
}
```

`trust_id`, `app_cred_id`, and `access_token_id` are mutually exclusive,
optional delegation-context fields. They are populated from the scope of the
token used to create the credential and must be passed through to the token
provider on `POST /v3/ec2tokens` (see §3, "Credential metadata in the token").
They are part of the same encrypted JSON blob as `access`/`secret` — the field
names above (not `access_id`) are the cross-service contract; a Rust and a
Python node must serialize identical keys or the two services will silently fail
to exchange delegation metadata.

**Server-managed, never client-settable** (OSSA-2026-005 / CVE-2026-33551): on
create, the server discards any `trust_id`/`app_cred_id`/`access_token_id`
supplied in the request's `blob` and re-derives them from the _actual_
authentication context of the creating request (trust or application credential;
absent for direct authentication). Without this, an EC2 credential created while
authenticated via a delegation would be indistinguishable from a
directly-authenticated one at `/v3/ec2tokens` validation time, silently
regaining the parent user's full, unrestricted project role set on every
subsequent use. On update, these fields are immutable and carried forward from
the stored blob when the caller's patch omits them (as any normal client would,
since the fields are never meant to be client-supplied); a patch that explicitly
supplies a _different_ value, or supplies one where none was stored, is
rejected.

**TOTP Blob:**

```json
{
  "seed": "JBSWY3DPEHPK3PXP",
  "digits": 6,
  "period": 30
}
```

Custom types may use arbitrary JSON structures; the provider does not validate
the blob contents beyond JSON-parseability.

#### Security Model

Because this provider stores critical secrets (including MFA seeds), it employs:

- **Encryption-at-Rest**: All secrets are stored as `encrypted_blob` using the
  Fernet (AES-128-CBC + HMAC-SHA256) scheme.
- **Key Isolation**: The encryption keys are stored in a separate
  filesystem-based repository, not in the database.
- **Integrity Verification**: The `key_hash` is stored alongside the blob to
  ensure the correct decryption key is used during rotation.

#### Persistence (Database Schema)

Credentials are persisted in the `credential` table, which is owned and
schema-managed exclusively by the Python Keystone service via alembic.
Keystone-NG treats this table as read/write but never issues DDL against it.

**Schema Definition:**

| Column           | Type          | Nullable | Description                                                                                                                                                                                                                                                                                                                                                                                                                                       |
| :--------------- | :------------ | :------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `id`             | `String(64)`  | No       | Primary Key. (For EC2: SHA-256 hex of the `access` key, per §1 ID Generation).                                                                                                                                                                                                                                                                                                                                                                    |
| `user_id`        | `String(64)`  | No       | Foreign key to the user who owns the credential.                                                                                                                                                                                                                                                                                                                                                                                                  |
| `project_id`     | `String(64)`  | Yes      | Project association (Mandatory for EC2 credentials).                                                                                                                                                                                                                                                                                                                                                                                              |
| `encrypted_blob` | `Text`        | No       | The Fernet-encrypted secret string.                                                                                                                                                                                                                                                                                                                                                                                                               |
| `type`           | `String(255)` | No       | Credential type (e.g., `'ec2'`, `'totp'`).                                                                                                                                                                                                                                                                                                                                                                                                        |
| `key_hash`       | `String(64)`  | No       | SHA-1 hex digest of the primary key used for encryption (see §4).                                                                                                                                                                                                                                                                                                                                                                                 |
| `extra`          | `Text`        | Yes      | Extensible JSON field. Python stores this via its `JsonBlob` `TypeDecorator`, which is backed by a plain `Text` column on every DB dialect Keystone supports — there is no native-JSON variant to detect. The Rust entity must model `extra` as `Option<String>` containing JSON text, parsed with `serde_json` (matching the existing `extra` handling in `identity-driver-sql`'s `user`/`group` entities), not a native JSON/JSONB column type. |

---

### 2. API Interface & Lifecycle

#### Create (`POST /v3/credentials`)

- **Mandatory Fields**:
  - `type`: The category of the credential.
  - `blob`: A JSON string representing the secret. For EC2, must contain an
    `access` key.
- **Optional Fields**:
  - `project_id`: Required if `type` is `'ec2'`.
  - `user_id`: Defaults to the authenticated user. This default applies only
    when the request is user-scoped; it must not be applied when the caller
    holds a system-scoped token (to match Python Keystone behaviour). Under
    system scope there is no implicit "acting user" to fall back to, so if
    `user_id` is also omitted from the request body the server must reject the
    request with `400 Bad Request` rather than defaulting it to anything (e.g.
    the system-scoped caller's own user, which would silently create a
    credential owned by an operator account).
- **ID Generation**:
  - **EC2**: `SHA-256(blob['access'])` hex-encoded.
  - **Others**: Random UUID.

#### Read (`GET /v3/credentials` & `GET /v3/credentials/{id}`)

- Returns the credential reference.
- **Security**: The `encrypted_blob` and `key_hash` are stripped from the
  response; the `blob` is decrypted to plaintext before serialisation.
- **Wire format of `blob`**: Python Keystone returns `blob` as a JSON-encoded
  **string** (the same string form that was originally submitted on create), not
  as a nested JSON object — clients are expected to `json.loads()` it
  themselves. Keystone-NG must serialise the `blob` field in its API response
  the same way (a string value), not as a parsed/nested object, or existing SDKs
  and clients that call `json.loads(cred["blob"])` will break against
  Keystone-NG.
- **List filtering — two-phase policy check** (required to address
  CVE-2019-19687): The `GET /v3/credentials` endpoint first enforces the
  `identity:list_credentials` policy and applies driver-level hints (e.g.
  `user_id`, `type` query parameters). It then iterates the returned set and
  re-enforces `identity:get_credential` on each individual credential, dropping
  any record the caller is not permitted to read. This ensures that users with a
  project role cannot view credentials belonging to other users when
  `enforce_scope` is false. The performance implication is accepted and matches
  Python Keystone behaviour.
  - **Policy target correctness**: The per-item re-enforcement must build its
    policy target from _that record's own_ `user_id`/`project_id`, not from the
    requester's identity or scope. Evaluating `identity:get_credential` against
    the wrong target (e.g. the caller's own attributes, or a cached target from
    the first item) would make the re-check a no-op and reintroduce a variant of
    CVE-2019-19687 rather than closing it.

#### Delegation Project Boundary (OSSA-2026-015)

All CRUD operations on `/v3/credentials` must bind delegated authentication
(trust-scoped tokens, application credentials) to the delegation's own
`project_id`, not just the credential's `user_id`. Checking ownership via
`user_id` alone is insufficient: a stolen or reused trust/application-credential
token scoped to project A must not be able to read, modify, or delete a
credential belonging to the same user but bound to project B, nor reach
credentials with no project binding at all (e.g. TOTP/MFA seeds).

- The policy engine receives `input.credentials.is_delegated` (derived from
  [`AuthenticationContext::is_delegated`], true for trust/application-credential
  auth, including when carried forward through a re-scoped token) on every
  request.
- The boundary is anchored on `input.credentials.delegated_project_id` — the
  delegation's own **immutable** project taken directly from the authentication
  chain held in [`ValidatedSecurityContext`] (`trust.project_id` /
  `application_credential.project_id`), **not** on
  `input.credentials.project_id` (the request's token scope). Sourcing the
  boundary from the chain rather than the scope means a scope rebind can never
  move a delegated caller's boundary. The two are pinned equal at token-issuance
  time ([`SecurityContext::validate_scope_boundaries`]), so policies
  additionally assert `project_id == delegated_project_id` for delegated callers
  as a scope-drift tripwire that fails closed.
- **Show/Delete/Update**: a delegated caller may only act on a credential whose
  `project_id` equals `delegated_project_id`; unscoped credentials
  (`project_id == null`) are unreachable via any delegated caller.
- **Update**: additionally, a delegated caller's patch must not move the
  credential's `project_id` outside the delegation's own
  (`delegated_project_id`) project.
- **Create**: a delegated caller's new credential must set `project_id` equal to
  `delegated_project_id`; delegated callers cannot create unscoped credentials.
- **List**: unaffected directly — the delegation boundary is enforced entirely
  by the per-item `identity/credential/show` re-check described above.
- Non-delegated authentication (password, token, TOTP, ...) is unaffected;
  `user_id`-only ownership remains sufficient.
- **Effective-role bounding on redemption**: a trust presented on a plain
  project scope (an EC2 credential created under a trust, redeemed at
  `POST /v3/ec2tokens`, where the scope is rebuilt from the credential's project
  rather than the trust's own `TrustProject` scope) has its effective roles
  bounded by the trust's delegated role set, never the trustee's own project
  assignments — mirroring the application-credential role intersection so a
  delegated EC2 credential can never widen its role set beyond the delegation.

#### Restricted Application Credentials and EC2 (OSSA-2026-005)

A _restricted_ application credential (`unrestricted == false`) must not be
usable to create an `ec2`-type credential at all, via either
`POST /v3/credentials` or `POST /v3/users/{user_id}/credentials/OS-EC2`. This is
independent of the project-boundary check above and of the delegation role set:
an EC2 credential, once created, authenticates via `POST /v3/ec2tokens` on its
own terms (see §1, "Server-managed, never client-settable") — restricting _who
may create one_ is the only point at which a restricted application credential's
intentionally narrow capability set can be enforced against this particular
escape hatch.

- The policy engine receives `input.credentials.auth_type` (e.g.
  `"application_credential"`) and, for application-credential authentication
  only, `input.credentials.unrestricted` (`Some(bool)`; absent/`null` for every
  other auth method).
- `identity/credential/create` denies when
  `auth_type == "application_credential"`, `unrestricted` is falsy, and the
  target credential's `type == "ec2"`; every other credential type is
  unaffected.
- `identity/os_ec2/create_credential` applies the same restricted-app-cred
  denial unconditionally, since every credential created through that endpoint
  is `ec2`-typed.

#### Update (`PATCH /v3/credentials/{id}`)

- **Updatable**: `type`, `blob`, `project_id`.
- **Immutable**: `user_id` and `project_id` may not be changed to point at a
  user or project the acting user has no access to (CVE-2020-12691). Within the
  `blob`, the following fields are additionally immutable: `access` (the EC2
  access key — changing it would desynchronize the record from its
  SHA-256-derived `id`), `trust_id`, `app_cred_id`, and `access_token_id`.
- **Process**: Updating the `blob` triggers automatic re-encryption with the
  current Primary Key and updates `key_hash`.

#### Delete (`DELETE /v3/credentials/{id}`)

- Supports deletion by ID, by User, or by Project.

#### Indirect User-Centric Endpoints (`/v3/users/{user_id}/credentials/OS-EC2`)

These endpoints provide legacy and user-scoped access to EC2 credentials:

- **Listing**: `GET` calls `list_credentials_for_user` filtered by `type='ec2'`.
  Results are flattened from the `blob` into explicit `access` and `secret`
  fields.
- **Automatic Creation**: `POST` can automatically generate `access` and
  `secret` keys via UUIDs if they are omitted from the request.
- **Plaintext ID Lookup**: For `GET` and `DELETE` operations, the
  `credential_id` provided in the URL is the **plaintext access key**. The
  server must hash this key (`SHA-256`) to locate the record in the database.

### 3. System Integration & Dependencies

The Credentials Provider is not only a standalone API but a critical component
integrated into several core Keystone workflows.

#### Authentication Pipeline (TOTP/MFA)

The provider is a **blocking dependency** for the authentication flow when TOTP
is enabled:

- **Workflow**: The `TOTP` auth plugin calls
  `list_credentials_for_user(user_id, type='totp')` during the token issuance
  process.
- **Operation**: The system decrypts all TOTP seeds for the user and generates
  current/previous window passcodes to verify the user's input.
- **Performance Requirement**: Because this occurs during the login path,
  `list_credentials_for_user` must be highly performant to avoid increasing
  authentication latency. A single TOTP decryption (Fernet AES-128-CBC) is
  approximately 0.1ms. For a user with multiple TOTP credentials, the cost
  scales linearly. If latency becomes a bottleneck, consider caching
  **decrypted** TOTP seeds in memory with a short TTL (e.g., 60 seconds). The
  cache must store the plaintext seed (not the encrypted blob), and its TTL must
  be well within the key rotation window. In a multi-node deployment (Python
  nodes + Rust nodes sharing the same DB), each node maintains its own
  in-process cache; this is safe because TOTP seeds are not changed by key
  rotation — only the encrypted form changes — and the decrypted value remains
  stable across rotations.

#### Identity Lifecycle Management

The provider must support cascading deletions to prevent orphaned secrets:

- **User Deletion**: When a user is deleted, the system must call
  `delete_credentials_for_user(user_id)` to wipe all associated secrets.
- **Project Deletion**: When a project is deleted, the system must call
  `delete_credentials_for_project(project_id)` (primarily impacting EC2
  credentials bound to projects).

#### API Transformation Layer

The provider supports the legacy `/v3/users/{user_id}/credentials/OS-EC2`
interface:

- **Flattening**: The provider's `blob` output is flattened into explicit
  `access` and `secret` fields.
- **Plaintext Mapping**: The provider must support resolving credentials using
  the SHA-256 hash of a plaintext access key provided in the URL.

---

### 4. Encryption Architecture

The provider uses **Fernet (symmetric encryption)**, which is built upon:

- **AES-128 in CBC mode** for encryption.
- **HMAC-SHA256** for authentication.
- **Base64url encoding** for the final encrypted token.

#### Key Management (The Key Repository)

- **Configuration**:
  - `[credential] provider`: Defaults to `fernet`.
  - `[credential] key_repository`: Path to the keys directory (default:
    `/etc/keystone/credential-keys/`).
  - **Important**: This repository must be separate from the `[fernet_tokens]`
    repository.
- **Storage**: Keys are stored as individual files in a filesystem directory.
- **Naming**: Files use integer names. The highest number is the **Primary
  Key**.
- **Cross-node synchronization (required precondition)**: Because the key
  repository is a local filesystem directory, not a table in the shared
  database, the whole byte-compatibility story in this section only holds if
  every Python node and every Rust node reads the _same_ set of key files (e.g.
  a shared network filesystem, or a config-management job that distributes the
  directory to all nodes). `credential_setup` and `credential_rotate` are
  cluster-wide operations: a run is not complete until the resulting key files
  have been propagated to every node of both services. Keystone-NG must document
  this as a deployment requirement, not assume it happens implicitly from
  "sharing the same database".
- **Maximum active keys**: The credential key repository is **hard-capped at 3
  active keys** (`MAX_ACTIVE_KEYS = 3`). This matches the Python Keystone
  constant and is intentionally not configurable. Unlike Fernet token key
  rotation, credential key rotation is driven by `key_hash` tracking, not by a
  configurable window. The Rust implementation must enforce this same limit when
  loading the key repository.
- **Rotation Logic** (staged-key promotion, not primary renumbering):
  1. Setup (`credential_setup`) creates the first key as `0.tmp` $\rightarrow$
     `0` (staged; not yet used for encryption).
  2. On rotation (`credential_rotate`), the **staged key `0` is renamed** to
     `(current_primary_index + 1)` — e.g. if `1` is the current primary, `0` is
     renamed to `2`. This renamed file is the new Primary. The old primary (`1`)
     is left in place, unchanged, and is still used for decryption.
  3. A fresh key is generated and written as the new staged `0.tmp`
     $\rightarrow$ `0`, ready for the next rotation cycle.
  4. If the number of key files now exceeds `MAX_ACTIVE_KEYS` (3), the oldest
     non-staged key file(s) are deleted to bring the count back down to 3.

  Note the staged key is never renumbered "in place" to become primary while
  simultaneously incrementing some other file — those are the same rename
  operation applied to the _staged_ file, not the outgoing primary. An
  implementation that instead renames the outgoing primary upward while
  separately trying to promote `0` (as an earlier ambiguous phrasing of this
  section could be read) produces two files claiming to be primary and must be
  avoided.

- **Security**:
  - Directory must not be world-readable.
  - Files are created with `umask 0o177` and a temporary-file-then-rename
    strategy to ensure atomicity.
  - A **Null Key** (`base64.urlsafe_b64encode(b'\x00' * 32)`) is provided as a
    fallback to facilitate upgrades. **The Null Key must be removed immediately
    after initial setup.** Any credential encrypted with the Null Key is
    effectively stored in plaintext with a well-known key. It exists solely as a
    transient migration aid and carries zero production tolerance.
  - **Startup enforcement**: Keystone-NG must check the key repository on
    startup. If any key file decodes to 32 null bytes (the Null Key), it must
    emit a hard warning log. Whether this is a hard-refuse-to-start condition
    must be controlled by an explicit, named configuration value (e.g.
    `[credential] insecure_allow_null_key`, defaulting to `false`) rather than
    an undefined "production mode" — refuse to start unless the operator has
    explicitly opted in. The Python service emits a warning on every encryption
    operation that uses the Null Key; Keystone-NG matches this behaviour and
    adds the startup gate.

#### `key_hash` Specification

> **This is a cross-service compatibility contract.** Python Keystone and
> Keystone-NG share the same `credential` table; a `key_hash` written by one
> service must be interpretable by the other's `credential_migrate` and
> `credential_rotate` commands.

The `key_hash` column is computed as follows (derived from
`keystone/credential/providers/fernet/core.py`):

```
key_hash = SHA-1( keys[0] )   # hexdigest, lowercase
```

Where `keys[0]` is the **raw bytes of the primary key file as read from disk** —
that is, the base64url-encoded key string, encoded as UTF-8, **before**
base64url-decoding. This matches Python's `hashlib.sha1(keys[0]).hexdigest()`
where `keys[0]` is a `bytes` object obtained by reading the key file and
stripping the trailing newline.

Important notes:

- The hash function is **SHA-1**, not SHA-256. Although SHA-1 is not recommended
  for security-sensitive uses, it is used here solely as a key-identifier (not
  for authentication), matching the Python implementation. Changing this to
  SHA-256 would silently break `credential_migrate` and `credential_rotate`
  against an existing database.
- The output is a **lowercase hex string** (40 characters), stored in the
  `key_hash` `String(64)` column.
- The input is the **base64url-encoded key bytes** as they appear in the file,
  not the raw 32-byte AES key they decode to.

#### Management Commands (`keystone-manage` / `keystone-ng manage`)

Administrative tasks are handled via three specific commands. **These commands
must not be run simultaneously from both the Python and Rust services against
the same database.** Because `credential_rotate` performs a safety check
followed by a key promotion in two steps, concurrent execution from two nodes
can race: one node's migrate could change `key_hash` values between another
node's check and promote. Operational runbooks must treat these commands as
mutually exclusive across services.

1. **`credential_setup`**: Populates the `key_repository` with initial keys.
   Must be run once during deployment.
2. **`credential_migrate`**: Identifies credentials encrypted with older keys
   (where `key_hash` $\neq$ SHA-1 hex of the current Primary Key) and
   re-encrypts them using the current Primary Key. Runs in batch chunks
   (default: 1000 credentials per transaction) with `COMMIT` between batches.
   Safe to run concurrently with active auth — reads are unaffected, writes are
   idempotent.
3. **`credential_rotate`**:
   - **Safety Check**: Verifies that _all_ credentials are already encrypted
     with the current Primary Key (i.e. all `key_hash` values equal the SHA-1
     hex of the current primary).
   - **Action**: Promotes a new key to Primary.
   - **Failure**: Aborts if any credential still uses an older key to prevent
     "over-rotation" (which would make those credentials indecipherable).

#### Encryption/Decryption Workflow

- **Encryption**: Use Primary Key $\rightarrow$ Encrypt $\rightarrow$ Store
  `encrypted_blob` and `SHA-1(primary key file bytes as UTF-8)` as `key_hash`.
- **Decryption**: Use `MultiFernet` (all active keys in repo, up to
  `MAX_ACTIVE_KEYS = 3`) to decrypt. The system attempts decryption with all
  available keys until one succeeds.

#### Re-encryption & Safety

To prevent data loss during rotation:

1. **`credential_migrate`**: Decrypts all credentials and re-encrypts them with
   the current Primary Key, updating `key_hash` to the SHA-1 of the new primary.
2. **`credential_rotate`**:
   - **Check**: Aborts if any credential's `key_hash` $\neq$ SHA-1 of current
     Primary Key's file bytes.
   - **Action**: Promotes a new primary key only after successful migration.

---

### 5. EC2 Credentials & Authentication

EC2 credentials enable AWS-style authentication, allowing clients to prove
identity via request signing without transmitting the secret key.

#### Request Body Structure (`POST /v3/ec2tokens`)

The request body is a JSON object with a top-level `"credentials"` key:

```json
{
  "credentials": {
    "access": "AKIAIOSFODNN7EXAMPLE",
    "signature": "<computed-signature>",
    "host": "identity.example.com:5000",
    "verb": "GET",
    "path": "/",
    "params": {
      "Action": "DescribeInstances",
      "SignatureVersion": "2",
      "SignatureMethod": "HmacSHA256",
      "Timestamp": "2026-06-11T12:00:00Z",
      "AWSAccessKeyId": "AKIAIOSFODNN7EXAMPLE"
    },
    "headers": {
      "Authorization": "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20260611/RegionOne/ec2/aws4_request, SignedHeaders=host;x-amz-date, Signature=...",
      "X-Amz-Date": "20260611T120000Z"
    },
    "body_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
  }
}
```

The server extracts `credentials["access"]` to locate the credential record, and
passes the full `credentials` dict to the signature verification logic. The
`body_hash` is the SHA-256 hex digest of the request body (required for SigV4;
use the empty-string hash for requests with no body).

#### Signature Version Detection and Dispatch

The server determines which signing algorithm to use via the following
**ordered** decision procedure, sourced from `Ec2Signer.generate()` in
`keystoneclient.contrib.ec2.utils`:

1. **Read `params["SignatureVersion"]`** from the credentials dict.

2. **If `SignatureVersion == "0"`** → use Version 0 algorithm.

3. **If `SignatureVersion == "1"`** → use Version 1 algorithm.

4. **If `SignatureVersion == "2"`** → use Version 2 algorithm.

5. **If `SignatureVersion` is absent or does not match `"0"`, `"1"`, `"2"`** →
   attempt SigV4 detection via `_v4_creds()`:
   - Check `credentials["headers"]["Authorization"]` — if it starts with
     `"AWS4-HMAC-SHA256"`, use Version 4.
   - Otherwise check `credentials["params"]["X-Amz-Algorithm"]` — if it equals
     `"AWS4-HMAC-SHA256"`, use Version 4.
   - **Important**: AWS removed the `SignatureVersion` field from the SigV4
     spec. SigV4 requests therefore never carry `SignatureVersion` in `params`;
     the `_v4_creds` detection path is not a fallback — it is the primary
     detection mechanism for SigV4.

6. **If no version is identified** → raise `400 Bad Request` (unknown signature
   format).

This means **the `SignatureVersion` query parameter is authoritative for
v0/v1/v2, but absent for v4**. The Rust implementation must replicate this exact
precedence: do not assume SigV4 when `SignatureVersion` is simply missing —
check the `Authorization` header or `X-Amz-Algorithm` param explicitly.

#### Per-Version Signature Algorithms

All versions use the decrypted `secret` from the credential blob as the key
material.

**Version 0 (Keystone-compatible, HMAC-SHA1)**

Concatenate `Action` and `Timestamp` params, then HMAC-SHA1:

```
string_to_sign = params["Action"] + params["Timestamp"]   # UTF-8 bytes
signature      = Base64( HMAC-SHA1(secret_key, string_to_sign) )
```

**Version 1 (Keystone-extended, HMAC-SHA1)**

Iterate all params sorted case-insensitively by key, concatenate key+value, then
HMAC-SHA1:

```
sorted_pairs   = sort params by key.lower()
string_to_sign = concat(key + value for key, value in sorted_pairs)  # UTF-8 bytes
signature      = Base64( HMAC-SHA1(secret_key, string_to_sign) )
```

**Version 2 (AWS Query, HMAC-SHA256 preferred / HMAC-SHA1 fallback)**

Build a canonical query string (keys and values percent-encoded with
`safe='-_~'`, sorted, joined with `&`), then HMAC:

```
canonical_qs   = "&".join( quote(k) + "=" + quote(v, safe='-_~')
                           for k, v in sorted(params.items()) )
string_to_sign = verb + "\n" + host + "\n" + path + "\n" + canonical_qs
```

Use HMAC-SHA256 if available (set `params["SignatureMethod"] = "HmacSHA256"`),
otherwise fall back to HMAC-SHA1. The signature is Base64 of the HMAC digest.

**Version 4 (SigV4, HMAC-SHA256 throughout)**

SigV4 is a multi-stage process. All HMAC operations use SHA-256.

_Step 1 — Canonical Request:_

```
cr = "\n".join([
    verb.upper(),
    path,
    canonical_qs(verb, params),   # empty string for POST
    canonical_header_str(),        # lowercased key:stripped_value pairs + trailing \n
    auth_param("SignedHeaders"),   # from Authorization header or X-Amz-SignedHeaders param
    body_hash                      # SHA-256 hex of request body
])
```

`canonical_header_str()` iterates only the headers listed in `SignedHeaders`
(from the `Authorization` header or the `X-Amz-SignedHeaders` query param).
Header keys are lowercased and stripped; values are stripped. Each entry is
`key:value`, lines joined by `\n`, with a trailing `\n`.

**Boto compatibility quirk**: Boto versions < 2.9.3 strip the port from the
`Host` header when signing. The server detects this via the `User-Agent` header
(regex `Boto/2\.[0-9]\.[0-2]`). When detected, the `host` entry in
`canonical_header_str` uses only the hostname, dropping the port. This is
**separate from** the port-stripping fallback in `_check_signature` and runs
inside the canonical request construction itself.

_Step 2 — String-to-Sign:_

```
string_to_sign = "\n".join([
    "AWS4-HMAC-SHA256",
    param_date,                    # X-Amz-Date header (YYYYMMDDTHHMMSSZ), or X-Amz-Date param
    credential_scope,              # date/region/service/aws4_request from Credential field
    SHA256(cr.encode("utf-8")).hexdigest()
])
```

The date used in `param_date` must match the `YYYYMMDD` prefix in the Credential
scope (`credential_split[1]`). If they do not match, the server raises an error
immediately (no signature attempt).

_Step 3 — Derived Signing Key:_

```
k_date    = HMAC-SHA256( b"AWS4" + secret_key.encode(), date_str )
k_region  = HMAC-SHA256( k_date,    region )
k_service = HMAC-SHA256( k_region,  service )
k_signing = HMAC-SHA256( k_service, "aws4_request" )
```

`region` and `service` are extracted from `credential_scope` (positions 2 and 3
of the `/`-split). For Keystone EC2, `service` is typically `ec2`; for S3
tokens, `service` must be `s3`.

_Step 4 — Final Signature:_

```
signature = HMAC-SHA256( k_signing, string_to_sign.encode("utf-8") ).hexdigest()
```

Note: the final signature is a **hex digest** (lowercase), not Base64.

#### Signature Verification Flow

The full verification procedure in `EC2TokensResource._check_signature()`:

1. Instantiate the signer with the decrypted secret key.
2. Call `signer.generate(credentials)` to produce the expected signature.
3. If `credentials["signature"]` is absent → raise `401` ("EC2 signature not
   supplied").
4. Perform a **constant-time string comparison** between the client-supplied
   `credentials["signature"]` and the generated signature. Use
   `hmac.compare_digest` (or equivalent) to prevent timing attacks.
5. **Port-stripping fallback**: If comparison fails and `credentials["host"]`
   contains `:`, parse the host, strip the port (use hostname only),
   reinitialise the signer (a fresh HMAC instance is required to avoid state
   contamination), regenerate the signature, and repeat the constant-time
   comparison.
6. If either comparison succeeds → proceed to token issuance.
7. If both fail → raise `401` ("Invalid EC2 signature").

The signer **must be reinitialised** between the original attempt and the
port-stripping retry. The Python HMAC object is stateful (accumulated via
`update()`); reusing it after a failed attempt produces incorrect results.

#### Timestamp Validation (Replay Attack Prevention)

**Two timestamp locations depending on signature version** (CVE-2020-12692 fix):

- **v0 / v1 / v2**: Timestamp is in `credentials["params"]["Timestamp"]`.
  Format: ISO 8601 (`2026-06-11T12:00:00Z`).
- **v4**: Timestamp is in `credentials["headers"]["X-Amz-Date"]` or
  `credentials["params"]["X-Amz-Date"]`. Format: `YYYYMMDDTHHMMSSZ`.

The server must check both locations and reject any request where the timestamp
is outside the configured TTL window. The TTL is read from `[ec2] auth_ttl` in
the shared `keystone.conf`, **defaulting to 300 seconds (5 minutes)** — this is
the Python Keystone default and must not be confused with the 4-hour window that
is only an AWS SigV2 recommendation, not what Keystone implements. Keystone-NG
must read the `[ec2] auth_ttl` config value from `keystone.conf` and apply it
identically.

Prior to the CVE-2020-12692 fix, SigV4 requests had no timestamp check because
the timestamp appears in the `Authorization` header rather than a query
parameter, and the original implementation only inspected query parameters.
Keystone-NG must check both locations from the start.

#### The `/v3/ec2tokens` API Interface

**Step-by-Step Authentication Algorithm:**

1. **Request Parsing**: Parse the JSON body; extract the `credentials` object.
   Accept the body under either the top-level `"credentials"` key, or a legacy
   `"ec2Credentials"` key (Python Keystone accepts both for backwards compat).
2. **Policy Enforcement**: Enforce `identity:ec2tokens_validate` RBAC. **Note**:
   As of CVE-2025-65073, this endpoint now requires the caller to be
   authenticated (a user in the `service` group). Earlier versions treated
   `/v3/ec2tokens` as fully unauthenticated. Keystone-NG must enforce this
   policy and not mark the endpoint as `@unenforced_api`.
3. **Credential Lookup**: Query the `credential` table using `SHA-256(access)`
   as the record ID. Return `401` if not found. **Type guard**: reject (`401`)
   any record whose `type != "ec2"`. The lookup keys on `SHA-256(access) == id`,
   an invariant only established for `ec2`-type credentials at creation (see §1,
   "Automatic Creation"); without this guard a credential mislabelled to a
   non-`ec2` type — thereby dodging the `ec2`-only create-time guards (project
   binding, delegation stamping, the restricted-app-cred gate of OSSA-2026-005)
   — could still be redeemed here if its id ever collided with an access hash.
4. **User/Project Validation**: After locating the credential, verify:
   - The owning user is enabled (`identity_api.assert_user_enabled`).
   - The user's domain is enabled.
   - The bound project is enabled (`resource_api.assert_project_enabled`).
     Return `401` for any disabled entity.
5. **Secret Decryption**: Decrypt `encrypted_blob` via the Fernet provider to
   recover the plaintext `secret` key.
6. **Timestamp Validation**: Extract the timestamp per the version-dependent
   rules above. Reject with `401` if outside the `[ec2] auth_ttl` window.
7. **Signature Verification**: Run the version-detection dispatch and
   `_check_signature` procedure described above.
8. **Token Issuance**: On success, issue a standard Keystone token scoped to the
   credential's `project_id` and `user_id`. Return the token in the response
   body and in the `X-Subject-Token` header.
9. **Failure**: Return `401 Unauthorized` for any verification failure.

**Credential metadata in the token**: If the EC2 credential was created via a
trust (`trust_id` in the blob) or application credential (`app_cred_id`), this
delegation metadata must be passed through to the token provider so it resolves
the correct (bounded) role assignments — the trust/application-credential
authentication context is rebuilt so the effective roles are bounded by the
delegation's role set, never the owner's full project assignments. Omitting this
was a historical bug fixed in Python Keystone. `access_token_id` (OAuth1) is
**rejected** until OAuth1 delegation is implemented: redeeming such a credential
would otherwise fall through to an unbounded EC2 authentication and silently
drop the OAuth1 restriction.

**Policy-input hygiene**: the credential `blob` holds the _decrypted_ secret
(EC2 secret key, TOTP seed). No credential policy rule references it, so the API
layer strips `blob` from every credential object before it is sent to the policy
engine (`identity/credential/{create,show,update}` and the per-item `show`
re-check on list). Shipping the plaintext secret to an external OPA would expose
it to decision logging, turning the authorization channel into a secret
exfiltration path.

#### Error Codes

| Status | Condition                                                                         |
| :----- | :-------------------------------------------------------------------------------- |
| `401`  | Access key not found, signature mismatch, missing signature, or timestamp expired |
| `401`  | Owning user, domain, or project is disabled                                       |
| `403`  | Policy check fails (`identity:ec2tokens_validate`)                                |
| `409`  | EC2 access key hash collision (create)                                            |
| `422`  | Invalid blob JSON structure or missing fields                                     |
| `404`  | User or project no longer exists                                                  |

---

### 6. Access Control & Permissions

#### RBAC Policies

- **`get_credential` / `list_credentials`**:
  `ADMIN_OR_SYSTEM_READER_OR_CRED_OWNER`.
- **`create` / `update` / `delete`**: `ADMIN_OR_CRED_OWNER`.

#### OS-EC2 Endpoint Policies

The legacy user-centric endpoints (`/v3/users/{user_id}/credentials/OS-EC2`)
enforce the following access controls:

- **`GET` (list)**: `identity:os-ec2:read_credential`. Requires the requester to
  be the credential owner or an administrator.
- **`POST` (create)**: `identity:os-ec2:create_credential`. Requires owner or
  admin authorization. When called via application credential, the project ID
  must match the app credential's bound project.
- **`GET/{credential_id}` (read)**: `identity:os-ec2:read_credential`. The
  `credential_id` is resolved via SHA-256 hash of the plaintext access key.
- **`DELETE/{credential_id}` (delete)**: `identity:os-ec2:delete_credential`.
  Same access rules as read.

#### Guardrails

- **Application Credentials**: Must be **`unrestricted`** to manage other
  credentials.
- **EC2 Project Match**: When creating EC2 credentials via an application
  credential, the `project_id` must match the application credential's project.
