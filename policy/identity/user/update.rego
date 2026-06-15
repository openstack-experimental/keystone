# METADATA
# description: Policy for updating identity user
package identity.user.update

import data.identity

# Update an existing user
#
# The `input.target.user` is the update patch (UserUpdate):
#   default_project_id:  string (optional)  The ID of the default project for the user.
#   enabled:             bool (optional)     If the user is enabled.
#   name:               string (optional)    The user name.
#   options:             object (optional)   The resource options for the user.
#   password:            string (optional)   The password for the user.
#
# The `input.existing.user` is the stored user object (UserResponse):
#   default_project_id:  string (optional)   The ID of the default project for the user.
#   domain_id:           string              User domain ID.
#   enabled:             bool                If the user is enabled.
#   id:                  string              User ID.
#   name:               string              User name.
#   options:             object (optional)    The resource options for the user.
#   password_expires_at: string (optional)    The date and time when the password expires.
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

violation contains {"field": "domain_id", "msg": "updating a user in domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	"manager" in input.credentials.roles
	input.existing.user.domain_id != input.credentials.domain_id
}

violation contains {"field": "domain_id", "msg": "updating a user requires a manager role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}
