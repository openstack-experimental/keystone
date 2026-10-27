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
# Any authenticated caller may read regions: python-keystone's default is
# `check_str=''` (any valid token). The admin and system-reader rules below
# are redundant under this default and kept to mirror `auth/project/list`.
default allow := true

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
	input.credentials.system != null
	"all" == input.credentials.system
}
