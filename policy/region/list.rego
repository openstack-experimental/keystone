# METADATA
# title: List regions
# description: Policy for listing catalog regions
package identity.region.list

import data.identity

# List regions.
#
# The `input.target.region` contains query parameters (RegionListParameters):
#   parent_region_id:  string (optional)  Filters the response by a parent region ID.
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
# description: "'reader' in the system scope can list any regions."
allow if {
	"reader" in input.credentials.roles
	input.credentials.system_scope != null
	"all" == input.credentials.system_scope
}
