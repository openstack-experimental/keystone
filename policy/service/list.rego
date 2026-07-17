# METADATA
# title: List services
# description: Policy for listing catalog services
package identity.service.list

import data.identity

# List services.
#
# The `input.target.service` contains query parameters (ServiceListParameters):
#   name:  string (optional)  Filters the response by a service name.
#   type:  string (optional)  Filters the response by a service type.
#
# The `input.existing` is null
#
default allow := false

# METADATA
# description: "`Admin` is allowed by default"
allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

# METADATA
# description: "'reader' in the system scope can list any services."
allow if {
	"reader" in input.credentials.roles
	input.credentials.system != null
	"all" == input.credentials.system
}
