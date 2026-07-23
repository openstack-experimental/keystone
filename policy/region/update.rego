# METADATA
# title: Update region
# description: Policy for updating a catalog region
package identity.region.update

import data.identity

# Update region.
#
# The `input.target.region` contains the fields to change (RegionUpdate):
#   description:        string (optional)  New region description.
#   parent_region_id:   string (optional)  New parent region ID.
#
# The `input.existing.region` is the stored region object (Region), or
# null if it does not exist.
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
