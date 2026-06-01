# METADATA
# description: Policy for listing domains
package identity.resource.domain.list

import data.identity

# List domains.
#
# The `input.target.domain` contains query parameters (DomainListParameters):
#   ids:  string (optional)  Filter domains by ID.
#   name: string (optional)  Filter domains by name.
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

violation contains {"field": "", "msg": "listing domains requires `reader` role with system scope."} if {
	not input.credentials.is_admin
}
