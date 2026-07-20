# METADATA
# title: Credential delegation-boundary helpers
# description: >
#   Shared predicates enforcing the delegation-project boundary (OSSA-2026-015)
#   across every credential-touching policy (identity.credential.*,
#   identity.os_ec2.*). Defined once here so a new delegation-sensitive
#   endpoint imports the check instead of hand-copying it (see
#   `doc/src/contributor/security-model.md` I2/I3 and its reviewer checklist).
package identity.credential

# METADATA
# description: >
#   True when `project_id` is the delegation's own immutable project
#   (chain-derived `input.credentials.delegated_project_id`), with the token
#   scope pinned to the same project as a scope-drift tripwire (I3).
bound_to_own_delegation_project(project_id) if {
	project_id == input.credentials.delegated_project_id
	input.credentials.delegated_project_id != null
	input.credentials.project_id == input.credentials.delegated_project_id
}

# METADATA
# description: >
#   True when the caller is not delegated at all, or is delegated and
#   `project_id` is bound to the delegation's own project.
#
#   Callers MUST pass a value that is never undefined (e.g.
#   `object.get(input.target.credential, "project_id", null)`, not a bare
#   `input.target.credential.project_id`) -- Rego evaluates a function's
#   argument before dispatching to either body below, so an undefined
#   argument makes the whole call (including the "not delegated" fast path,
#   which never reads it) undefined too.
not_delegated_or_bound_to_own_project(project_id) if {
	not input.credentials.is_delegated
}

not_delegated_or_bound_to_own_project(project_id) if {
	input.credentials.is_delegated
	bound_to_own_delegation_project(project_id)
}
