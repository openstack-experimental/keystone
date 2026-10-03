# METADATA
# title: List limits
# description: Policy for listing limits
package identity.limit.list

# List limits.
#
# The `input.target.limit` contains query parameters (LimitListParameters):
#   service_id:     string (optional)  Filters the response by a service ID.
#   region_id:      string (optional)  Filters the response by a region ID.
#   resource_name:  string (optional)  Filters the response by a resource name.
#   project_id:     string (optional)  Filters the response by a project ID.
#   domain_id:      string (optional)  Filters the response by a domain ID.
#
# The `input.existing` is null
#
# Visibility of the individual limits depends on the scope of the caller
# (system and `admin` see everything, a domain scope sees the limits of the
# domain and of its projects, a project scope sees the limits of the project).
# That is enforced per item: every entry is re-checked with the
# `identity/limit/show` policy and the entries that are not readable are
# omitted. The collection policy therefore only requires a scoped token.
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
# description: "Any caller holding a system, domain or project scoped token is allowed to list (entries are filtered individually)."
allow if {
	input.credentials.system != null
}

allow if {
	input.credentials.domain_id != null
}

allow if {
	input.credentials.project_id != null
}
