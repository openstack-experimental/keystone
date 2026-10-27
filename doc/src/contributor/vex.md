# VEX statements

`deny.toml` silences an advisory only when the project has judged what it
means for Keystone. That judgment is recorded as an
[OpenVEX](https://openvex.dev) statement in
`supply-chain/vex/keystone.openvex.json`, which ships with every release
(attested, next to the SBOM). `tools/check_vex.py` runs in the
[release gate](../admin/verify-artifacts.md) and fails when a `deny.toml`
ignore has no statement, or a statement has an invalid status or no
justification.

## Current statements

| Advisory                                                                                 | Component             | Status               | Summary                                                                                                                                                                                                                                                     |
| ---------------------------------------------------------------------------------------- | --------------------- | -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) (Marvin, `rsa`)    | `rsa` 0.9.10          | `affected`           | Exposed only when an operator opts into RS256 signing; the default is ES256. No patched release exists.                                                                                                                                                      |
| [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387) (`crypto-bigint`)  | `crypto-bigint` 0.5.5 | `under_investigation` | The patched 0.7.x line is used where possible. 0.5.5 stays behind `elliptic-curve` 0.13 (`p256`, `ecdsa`: ES256) and `rsa` 0.9, which have no release on the patched line. Exploitability for these call sites has not been assessed.                        |

## `rsa` review (RUSTSEC-2023-0071)

- **Private-key operations** happen only when Keystone signs with RSA:
  `key-repository/src/asymmetric/jwt_bridge.rs` loads the key for
  `jsonwebtoken`, which signs RS256 through the `rsa` crate. That is reached
  by the OAuth2 per-domain signing keys when `signing_algorithm = RS256`
  (default `ES256`, ADR 0026 §3) and by the JWS token driver with an RS256 key
  (TOK-2).
- **Public-key operations** (RS256 DPoP proof verification in
  `core/src/oauth2_client/dpop.rs`, federation JWKS, JWKS publication in
  `oauth2_key/jwks.rs`) do not use the private exponent and are not exposed.
- Signing is a server-side operation on server-built payloads, and the
  timing of token issuance is only observable through the issuing endpoint.
  The advisory's own workaround is to avoid `rsa` where an attacker can
  observe timing, so the operator guidance is to keep ES256.

## `crypto-bigint` review (RUSTSEC-2026-0387)

`crypto-bigint` 0.5.5 is in the tree through `elliptic-curve` 0.13, which
`p256` and `ecdsa` (the default ES256 signing path) and `rsa` use. Neither has
a release on the patched `crypto-bigint` line. The advisory says exploitability
depends on the algorithm, compiler, target CPU and an observer of the side
channel. Until that is assessed for these call sites the status stays
`under_investigation`, tracked as work item V1 in the
[CRA requirements](cra-requirements.md).

## Removed statements

The three `zip` advisories (RUSTSEC-2026-0367/0368/0369) no longer apply:
`zip` is a build-dependency of `utoipa-swagger-ui` only and the lockfile pins
9.0.5, which contains the fix. Their `deny.toml` ignores were removed.

## Changing a statement

1. Edit `supply-chain/vex/keystone.openvex.json` (status, justification or
   action statement) in the same change as the `deny.toml` edit.
2. Run `python3 tools/check_vex.py`.
3. A `not_affected` statement needs a `justification` or `impact_statement`;
   an `affected` statement needs an `action_statement`.
