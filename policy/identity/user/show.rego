# METADATA
# description: Policy for viewing identity user details
package identity.user.show

import data.identity

# Show user.
#
# The `input.existing.user` is the stored user object (User):
#   default_project_id:  string (optional)  The ID of the default project for the user.
#   domain_id:           string            User domain ID.
#   enabled:             bool              If the user is enabled.
#   id:                  string            User ID.
#   name:               string            User name.
#   options:             object (optional)  The resource options for the user.
#   password_expires_at: string (optional)  The date and time when the password expires.
#
# The `input.target` is null
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

allow if {
	"reader" in input.credentials.roles
	identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "reading a user in domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	"manager" in input.credentials.roles
	not identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "reading a user requires a reader role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "reader" in input.credentials.roles
	identity.domain_matches_domain_scope
}
