# METADATA
# description: Policy for listing roles of a user on system
package identity.system.user.role.list

import data.identity

# List direct (non-effective) user roles on the system.
#
# The `input.target` contains resolved user object:
#   user:      `User`      Resolved User
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
	"reader" in input.credentials.roles
	input.credentials.system == "all"
}

violation contains {"field": "system", "msg": "listing system-user-role assignment requires admin role."} if {
	not "admin" in input.credentials.roles
}

violation contains {"field": "system", "msg": "listing system-user-role assignment requires system scope for reader role."} if {
	"reader" in input.credentials.roles
	input.credentials.system != "all"
}

