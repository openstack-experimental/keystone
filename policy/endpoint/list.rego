# METADATA
# title: List endpoints
# description: Policy for listing catalog endpoints
package identity.endpoint.list

import data.identity

# List endpoints.
#
# The `input.target.endpoint` contains query parameters (EndpointListParameters):
#   interface:   string (optional)  Filters the response by an interface.
#   service_id:  string (optional)  Filters the response by a service ID.
#   region_id:   string (optional)  Filters the response by a region ID.
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
# description: "'reader' in the system scope can list any endpoints."
allow if {
	"reader" in input.credentials.roles
	input.credentials.system_scope != null
	"all" == input.credentials.system_scope
}
