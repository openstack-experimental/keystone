# METADATA
# title: List regions
# description: Policy for listing catalog regions
package identity.region.list

# List regions.
#
# The `input.target.region` contains query parameters (RegionListParameters):
#   parent_region_id:  string (optional)  Filters the response by a parent region ID.
#
# The `input.existing` is null
#
# Any caller holding a valid token may read regions: python-keystone's
# default is `check_str=''`. No role or scope is required.
default allow := false

allow if {
	input.credentials.user_id != ""
}
