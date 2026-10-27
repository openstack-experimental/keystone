# METADATA
# title: Show region
# description: Policy for fetching a single catalog region
package identity.region.show

# Show region.
#
# The `input.existing.region` is the stored region object (Region):
#   id:                 string             Region ID.
#   description:        string (optional)  The region description.
#   parent_region_id:   string (optional)  The ID of the parent region.
#
# The `input.target` is null
#
# Any caller holding a valid token may read regions: python-keystone's
# default is `check_str=''`. No role or scope is required.
default allow := false

allow if {
	input.credentials.user_id != ""
}
