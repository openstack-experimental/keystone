# METADATA
# description: Policy for listing projects the authentication have access to
package identity.auth.project.list

import data.identity

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"reader" in input.credentials.roles
	input.credentials.system_scope != null
	"all" == input.credentials.system_scope
}
