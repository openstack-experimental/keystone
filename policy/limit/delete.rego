# METADATA
# title: Delete limit
# description: Policy for deleting a limit
package identity.limit.delete

# Delete limit.
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
