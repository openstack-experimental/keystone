# METADATA
# description: Policy for listing roles of a user in a project
package identity.project.user.role.list

import data.identity
import data.identity.assignment

# List direct (non-effective) user roles on the project.
#
# The `input.target` contains resolved project and user objects:
#   project:   `Project`   Resolved Project
#   user:      `User`      Resolved User
#
# The `input.existing` is null
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"reader" in input.credentials.roles
	input.credentials.system == "all"
}

allow if {
	"reader" in input.credentials.roles
	assignment.project_user_role_domain_matches
}

violation contains {"field": "domain_id", "msg": "checking project-user-role assignment requires domain scope matching the domain of all targets."} if {
	not assignment.project_user_role_domain_matches
}
