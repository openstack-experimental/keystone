# METADATA
# title: Trust identity/delegation-boundary helpers
# description: >
#   Shared predicates for identity.trust.* policies. `is_trustor`/`is_trustee`
#   decide "did the caller create/consume this trust"; the delegation-project
#   boundary helper mirrors identity.credential's (OSSA-2026-015) for the case
#   where a delegated caller (trust, application credential) itself attempts
#   to create a new trust (see `doc/src/contributor/security-model.md` I2/I3).
package identity.trust

# METADATA
# description: "True when the caller is the trust's trustor."
is_trustor(trust) if {
	trust.trustor_user_id == input.credentials.user_id
}

# METADATA
# description: "True when the caller is the trust's trustee."
is_trustee(trust) if {
	trust.trustee_user_id == input.credentials.user_id
}

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
#   `object.get(input.target.trust, "project_id", null)`, not a bare
#   `input.target.trust.project_id`) -- Rego evaluates a function's argument
#   before dispatching to either body below, so an undefined argument makes
#   the whole call (including the "not delegated" fast path, which never
#   reads it) undefined too.
not_delegated_or_bound_to_own_project(project_id) if {
	not input.credentials.is_delegated
}

not_delegated_or_bound_to_own_project(project_id) if {
	input.credentials.is_delegated
	bound_to_own_delegation_project(project_id)
}
