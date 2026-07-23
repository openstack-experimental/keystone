# METADATA
# title: Create region
# description: Policy for creating a catalog region
package identity.region.create

import data.identity

# Create region.
#
# The `input.target.region` is the new region object (RegionCreate):
#   id:                 string (optional)  The region ID.
#   description:        string (optional)  The region description.
#   parent_region_id:   string (optional)  The ID of the parent region.
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
