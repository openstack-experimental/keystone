# METADATA
# title: Delete region
# description: Policy for deleting a catalog region
package identity.region.delete

import data.identity

# Delete region.
#
# The `input.existing.region` is the stored region object (Region):
#   id:                 string             Region ID.
#   description:        string (optional)  The region description.
#   parent_region_id:   string (optional)  The ID of the parent region.
#
# The `input.target` is null
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
