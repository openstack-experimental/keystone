# METADATA
# title: List registered limits
# description: Policy for listing registered limits
package identity.registered_limit.list

# List registered limits.
#
# The `input.target.registered_limit` contains query parameters
# (RegisteredLimitListParameters):
#   service_id:     string (optional)  Filters the response by a service ID.
#   region_id:      string (optional)  Filters the response by a region ID.
#   resource_name:  string (optional)  Filters the response by a resource name.
#
# The `input.existing` is null
#
# Registered limits are not tenant specific, therefore any authenticated and
# scoped caller may read them. Every item is re-checked with the
# `identity/registered_limit/show` policy.
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
# description: "Any caller holding a system, domain or project scoped token is allowed."
allow if {
	input.credentials.system != null
}

allow if {
	input.credentials.domain_id != null
}

allow if {
	input.credentials.project_id != null
}
