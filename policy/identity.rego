# METADATA
# description: Core identity predicates and helper rules for Keystone4 policies
package identity

token_subject if {
	input.credentials.user_id == input.target.token.user_id
}

global_role if {
	input.target.role.domain_id == null
}

own_role if {
	input.target.role.domain_id != null
	input.credentials.domain_id == input.target.role.domain_id
}

# Domain role or the global role.
own_role_or_global_role if {
	global_role
}

own_role_or_global_role if {
	own_role
}

own_target if {
	any_domain_id != null
	any_domain_id == input.credentials.domain_id
}

foreign_target if {
	any_domain_id != null
	any_domain_id != input.credentials.domain_id
}

# Collect domain_id from any known wrapped resource key.
# Used by own_target / foreign_target / domain_matches_domain_scope.
any_domain_id := input.target.instance.domain_id if {
	input.target.instance.domain_id
}

any_domain_id := input.target.user.domain_id if {
	input.target.user.domain_id
}

any_domain_id := input.target.group.domain_id if {
	input.target.group.domain_id
}

any_domain_id := input.target.restriction.domain_id if {
	input.target.restriction.domain_id
}

any_domain_id := input.target.project.domain_id if {
	input.target.project.domain_id
}

any_domain_id := input.target.role.domain_id if {
	input.target.role.domain_id
}

any_domain_id := input.target.token.domain_id if {
	input.target.token.domain_id
}

project_domain_matches_domain_scope if {
	input.target.project.domain_id != null
	input.target.project.domain_id = input.credentials.domain_id
}

domain_matches_domain_scope if {
	any_domain_id != null
	any_domain_id = input.credentials.domain_id
}
