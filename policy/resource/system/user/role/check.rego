# METADATA
# description: Policy for checking user roles on system
package identity.system.user.role.check

import data.identity

# Check whether the user has a role assigned on the system.

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

violation contains {"field": "system", "msg": "checking system-user-role assignment requires admin role."} if {
	not "admin" in input.credentials.roles
}

violation contains {"field": "system", "msg": "checking system-user-role assignment requires system scope for reader role."} if {
	"reader" in input.credentials.roles
	input.credentials.system != "all"
}

