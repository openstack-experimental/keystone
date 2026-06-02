# METADATA
# description: Policy for creating identity user
package identity.user.create

import data.identity

# Create a new user
#
# The `input.target.user` is the new user object (UserCreate):
#   default_project_id:  string (optional)  The ID of the default project for the user.
#   domain_id:           string            User domain ID.
#   enabled:             bool              If the user is enabled.
#   name:               string            The user name.
#   options:             object (optional)  The resource options for the user.
#   password:            string (optional)  The password for the user.
#
# The `input.existing` is null
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

allow if {
	"manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "creating a new user in domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	"manager" in input.credentials.roles
	not identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "creating a new user requires a manager role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}
