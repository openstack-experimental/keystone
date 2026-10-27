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
# description: "'reader' in the system scope can show any region."
allow if {
	"reader" in input.credentials.roles
	input.credentials.system != null
	"all" == input.credentials.system
}
