package identity.assignment

import data.identity

# current domain scope matches the domain_id of the project, or the user and of
# the role (or it is a global role)
project_user_role_domain_matches if {
	input.target.project.domain_id != null
	input.target.user.domain_id != null
	input.credentials.domain_id == input.target.user.domain_id
	input.credentials.domain_id == input.target.project.domain_id
	identity.own_role_or_global_role
}

# Ensure that the domain_id of the target project is matching the current
# domain scope and the role belongs to the same domain or is global.
project_role_domain_matches if {
	input.target.project.domain_id != null
	input.credentials.domain_id == input.target.project.domain_id
	identity.own_role_or_global_role
}
