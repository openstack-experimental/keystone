# METADATA
# description: Policy for listing projects the authentication have access to
package identity.auth.project.list

import data.identity

# List projects the authentication have access to.
#
# The `input.target.project` contains query parameters (ProjectListParameters):
#   (none)
#
# The `input.existing` is null
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"reader" in input.credentials.roles
	input.credentials.system_scope != null
	"all" == input.credentials.system_scope
}
