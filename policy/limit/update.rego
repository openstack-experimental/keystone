# METADATA
# title: Update limit
# description: Policy for updating a limit
package identity.limit.update

# Update limit.
#
# The `input.target.limit` is the patch (LimitUpdate):
#   resource_limit:   integer (optional) New limit value.
#   description:      string (optional)  New description.
#
# The `input.existing.limit` is the stored object (Limit):
#   id:                  string             Limit ID.
#   service_id:          string             The ID of the service.
#   region_id:           string (optional)  The ID of the region.
#   resource_name:       string             The name of the resource.
#   resource_limit:      integer            The limit value.
#   project_id:          string (optional)  The project the limit is set for.
#   domain_id:           string (optional)  The domain the limit is set for.
#   description:         string (optional)  The description.
#   project_domain_id:   string (optional)  The domain of the project (added by
#                                           the handler, `null` for domain limits).
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
