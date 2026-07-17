<!--
Thanks for the contribution! Fill in the sections below.
-->

## Summary

<!-- What does this PR change, and why? -->

## Test plan

<!-- How was this verified? cargo test output, manual steps, screenshots, etc. -->

## Security review checklist

**Required if this diff touches authentication, scope, delegation, tokens,
credentials, EC2, trusts, application credentials, or OPA policy input.**
Delete this section entirely if it doesn't apply. See
[`doc/src/security.md`](../doc/src/security.md) §7 for the full context
behind each item.

- [ ] Does any delegation/authorization decision read the **scope**
      (`project_id`, `ScopeInfo`) where it should read the **chain**
      (`authentication_context()`, delegation object)? (I1/I2)
- [ ] New delegation-sensitive policy rule? Is the fact it needs projected
      onto `Credentials` from the chain, and does the rule anchor on
      `delegated_project_id` + carry the scope-drift tripwire? (I2/I3)
- [ ] New scope shape or redemption path for a delegated auth? Are effective
      roles still bounded by the delegation? Added a test that a restricted
      delegation cannot exceed its roles via the new path? (I4)
- [ ] New `ScopeInfo` variant or auth method? Updated
      `validate_scope_boundaries()`, `calculate_effective_roles()`,
      `fully_resolved()`, and `Credentials::try_from` — all without adding a
      wildcard `_ =>` arm? (I5, Gate J)
- [ ] New lookup by a client-derivable key (like `sha256(access)`)? Does it
      re-assert `type`/shape after fetch? (I6)
- [ ] Does any new data reaching OPA include secrets/decrypted blobs? (I7,
      Gate I)
- [ ] New list/collection endpoint? Does it re-check each item with the
      per-item read policy? (I8)
- [ ] Does the change let a narrow auth method be broadened by a
      request-supplied scope? (I5)
- [ ] Are there negative tests proving the escape is blocked, not just
      positive tests proving the happy path works?
- [ ] Does the test drive `ValidatedSecurityContext::new_for_scope()`
      end-to-end, not just the inner helper (`calculate_effective_roles`,
      `validate_scope_boundaries`) in isolation?
