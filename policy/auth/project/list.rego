package identity.auth.project.list

import data.identity

# List projects the user is having access to

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"reader" in input.credentials.roles
	input.credentials.system_scope != null
	"all" == input.credentials.system_scope
}
