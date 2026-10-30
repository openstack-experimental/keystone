# METADATA
# description: Common policies for identity assignments
package identity.assignment

import data.identity

# description: current domain scope matches the domain_id of the project, or the user and of
# the role (or it is a global role)
# For grant: in input.target.
# For revoke: in input.existing.
project_user_role_domain_matches if {
	input.target.project.domain_id != null
	input.target.user.domain_id != null
	input.credentials.domain_id == input.target.user.domain_id
	input.credentials.domain_id == input.target.project.domain_id
	identity.own_role_or_global_role
}

project_user_role_domain_matches if {
	input.existing.project.domain_id != null
	input.existing.user.domain_id != null
	input.credentials.domain_id == input.existing.user.domain_id
	input.credentials.domain_id == input.existing.project.domain_id
	identity.own_role_or_global_role
}

# description: Ensure that the domain_id of the target project is matching the current
# domain scope and the role belongs to the same domain or is global.
# For grant: in input.target.
# For revoke: in input.existing.
project_role_domain_matches if {
	input.target.project.domain_id != null
	input.credentials.domain_id == input.target.project.domain_id
	identity.own_role_or_global_role
}

project_role_domain_matches if {
	input.existing.project.domain_id != null
	input.credentials.domain_id == input.existing.project.domain_id
	identity.own_role_or_global_role
}

# description: Ensure that if a domain_id is explicitly provided, it matches the scope
domain_matches_scope if {
	input.target.assignment.domain_id == null
}

domain_matches_scope if {
	input.target.assignment.domain_id == input.credentials.domain_id
}

# description: Ensure that if a project is provided, its domain matches the scope
project_matches_scope if {
	input.target.project.domain_id == null
	input.target.project.domain_id == null
}

project_matches_scope if {
	input.target.project != null
	input.target.project.domain_id != null
	#input.target.project.domain_id == input.credentials.domain_id
}

# description: Ensure that if a user is provided, their domain matches the scope
user_matches_scope if {
	input.target.user.domain_id == null
}

user_matches_scope if {
	input.target.user.domain_id == input.credentials.domain_id
}

# description: Ensure that if a role is provided, its domain matches the scope
role_matches_scope if {
	input.target.role.domain_id == null
}

role_matches_scope if {
	input.target.role.domain_id == input.credentials.domain_id
}

# Combined check: All provided filters must belong to the scoped domain
all_filters_match_scope if {
	domain_matches_scope
	project_matches_scope
	user_matches_scope
	role_matches_scope
}

# description: The request MUST be constrained to the token's domain.
# This prevents "listing all" by requiring that the target domain
# is explicitly the one the user is managed in.
is_scoped_to_token_domain if {
	input.target.assignment.domain_id == input.credentials.domain_id
}

# description: current domain scope matches the target domain and the role
# belongs to the same domain (or is global).
# For grant/check/list: in input.target.
# For revoke: may be in input.existing.
domain_role_domain_matches if {
	input.target.domain.id != null
	input.credentials.domain_id == input.target.domain.id
	identity.own_role_or_global_role
}

domain_role_domain_matches if {
	input.existing.domain.id != null
	input.credentials.domain_id == input.existing.domain.id
	identity.own_role_or_global_role
}

# description: current domain scope matches the domain of the target domain,
# the user and the role (or it is a global role).
domain_user_role_domain_matches if {
	input.target.user.domain_id != null
	input.credentials.domain_id == input.target.user.domain_id
	domain_role_domain_matches
}

domain_user_role_domain_matches if {
	input.existing.user.domain_id != null
	input.credentials.domain_id == input.existing.user.domain_id
	domain_role_domain_matches
}

# description: current domain scope matches the domain of the target domain,
# the group and the role (or it is a global role).
domain_group_role_domain_matches if {
	input.target.group.domain_id != null
	input.credentials.domain_id == input.target.group.domain_id
	domain_role_domain_matches
}

domain_group_role_domain_matches if {
	input.existing.group.domain_id != null
	input.credentials.domain_id == input.existing.group.domain_id
	domain_role_domain_matches
}

# description: current domain scope matches the domain of the target project,
# the group and the role (or it is a global role).
project_group_role_domain_matches if {
	input.target.group.domain_id != null
	input.credentials.domain_id == input.target.group.domain_id
	project_role_domain_matches
}

project_group_role_domain_matches if {
	input.existing.group.domain_id != null
	input.credentials.domain_id == input.existing.group.domain_id
	project_role_domain_matches
}

# description: list requests carry no role; the current domain scope must
# match the domain of the target domain and the user.
domain_user_domain_matches if {
	input.target.domain.id != null
	input.credentials.domain_id == input.target.domain.id
	input.target.user.domain_id != null
	input.credentials.domain_id == input.target.user.domain_id
}

# description: list requests carry no role; the current domain scope must
# match the domain of the target domain and the group.
domain_group_domain_matches if {
	input.target.domain.id != null
	input.credentials.domain_id == input.target.domain.id
	input.target.group.domain_id != null
	input.credentials.domain_id == input.target.group.domain_id
}

# description: list requests carry no role; the current domain scope must
# match the domain of the target project and the group.
project_group_domain_matches if {
	input.target.project.domain_id != null
	input.credentials.domain_id == input.target.project.domain_id
	input.target.group.domain_id != null
	input.credentials.domain_id == input.target.group.domain_id
}
