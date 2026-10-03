# METADATA
# title: Show limit
# description: Policy for fetching a single limit
package identity.limit.show

import data.identity.credential

# Show limit.
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
# This is also invoked by `identity/limit/list`'s per-item re-enforcement
# pass.
#
# Delegation boundary: a trust- or application-credential-scoped caller
# (`input.credentials.is_delegated`) may only read the limits of the project
# the delegation itself is bound to. The boundary is anchored on
# `input.credentials.delegated_project_id` (taken from the authentication
# chain), with the token scope asserted equal as a scope-drift tripwire (see
# `identity.credential.not_delegated_or_bound_to_own_project`).
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
# description: "'reader' in the system scope can show any limit."
allow if {
	"reader" in input.credentials.roles
	input.credentials.system == "all"
}

# METADATA
# description: "A domain scoped caller can show the limits of the domain."
allow if {
	input.credentials.domain_id != null
	input.existing.limit.domain_id == input.credentials.domain_id
}

# METADATA
# description: "A domain scoped caller can show the limits of the projects in the domain."
allow if {
	input.credentials.domain_id != null
	input.existing.limit.project_domain_id == input.credentials.domain_id
}

# METADATA
# description: "A project scoped caller can show the limits of the project (a delegated caller only when bound to the delegation project)."
allow if {
	input.credentials.project_id != null
	input.existing.limit.project_id == input.credentials.project_id
	credential.not_delegated_or_bound_to_own_project(object.get(input.existing.limit, "project_id", null))
}
