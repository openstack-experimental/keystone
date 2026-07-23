# METADATA
# title: Show region
# description: Policy for fetching a single catalog region
package identity.region.show

import data.identity

# Show region.
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

# METADATA
# description: "'reader' in the system scope can show any region."
allow if {
	"reader" in input.credentials.roles
	input.credentials.system_scope != null
	"all" == input.credentials.system_scope
}
