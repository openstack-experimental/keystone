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
| [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387) (`crypto-bigint`)  | `crypto-bigint` 0.5.5 | `affected`           | Reached only through `jsonwebtoken`'s `rust_crypto` backend (`p256`/`ecdsa` 0.13), which signs the default ES256 tokens. The operations the advisory names run on secret scalars. Remote exploitation is judged impractical; residual risk accepted until `jsonwebtoken` moves to a patched `p256`. |

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

The advisory covers `crypto-bigint` before 0.7.6: subtraction, zero counting,
division, Montgomery multiplication and some equality checks can branch on
secret values, depending on compiler and target CPU.

- **Where 0.5.5 comes from.** Only `elliptic-curve` 0.13, reached through
  `p256` 0.13, `p384` 0.13 and `ecdsa` 0.16, which `jsonwebtoken` pulls in
  with its `rust_crypto` backend. `rsa` 0.9 does not use `crypto-bigint`: it
  does its big-number arithmetic with `num-bigint-dig`, so this advisory does
  not touch RS256 (that is RUSTSEC-2023-0071 above).
- **Keystone's own code is on the patched line.** The workspace depends on
  `p256` 0.14, which uses `crypto-bigint` 0.7. ES256 key generation
  (`key-repository/src/asymmetric/keygen.rs`) and the JWKS and verifying-key
  paths in `jwt_bridge.rs` and `oauth2_key/jwks.rs` therefore run on patched
  code.
- **Exposed operation: ES256 signing.** `jsonwebtoken` 11.1 signs ES256 with
  `p256` 0.13 `SigningKey`. The `p256` 0.13 scalar code calls the affected
  `crypto-bigint` 0.5.5 operations on secret values (`sub_mod`, `mul_wide`,
  `wrapping_sub`) while forming `s = k^-1 (z + r d)`. Keystone signs ES256
  tokens in the JWS token driver (TOK-2) and with the OAuth2 per-domain signing
  keys (the default algorithm). Whether the compiled code branches on secret
  data depends on compiler and CPU; we have not verified that for the release
  binaries and do not claim they are safe.
- **Not exposed.** `p384` 0.13 is used only to verify ES384 signatures (DPoP
  proofs, upstream OIDC tokens); public values only. Keystone never generates
  P-384 keys. Verification everywhere uses public keys.
- **Why exploitation is judged impractical remotely.** An attacker needs to
  measure the timing of individual ECDSA signing operations (nanosecond to
  microsecond differences) through the token endpoints, across network and
  scheduler noise, and then run a lattice attack on partially recovered
  nonces. Signing nonces are derived deterministically (RFC 6979) from the key
  and message, so the attacker cannot choose them. A co-located or
  microarchitectural observer (shared host, shared cache) is a stronger
  threat. That is a risk we accept, not one we have ruled out.
- **Mitigations available to operators.** Run Keystone on dedicated hosts or
  nodes where it does not share a CPU with untrusted workloads; rotate the
  signing keys on the normal schedule (the OAuth2 and JWS key rotation limits
  the amount of signing data per key).
- **How we close it.** Move off `p256` 0.13 when `jsonwebtoken` releases on
  `p256` 0.14 (11.1.0 is the latest release), or switch `jsonwebtoken` to its
  `aws_lc_rs` backend, which does not use `p256`, `ecdsa` or `rsa` at all.
  The second option changes the crypto provider, so it needs the FIPS and
  crypto-inventory review first. The `deny.toml` ignore stays until then.

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
