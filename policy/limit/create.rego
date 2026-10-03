# METADATA
# title: Create limits
# description: Policy for creating limits (batch)
package identity.limit.create

# Create limits.
#
# Invoked once per item of the batch. The `input.target.limit` is the new
# limit (LimitCreate):
#   service_id:       string             The ID of the service.
#   region_id:        string (optional)  The ID of the region.
#   resource_name:    string             The name of the resource.
#   resource_limit:   integer            The limit value.
#   project_id:       string (optional)  The project the limit is set for.
#   domain_id:        string (optional)  The domain the limit is set for.
#   description:      string (optional)  The description.
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
