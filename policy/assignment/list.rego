# METADATA
# title: List role assignments
# description: Policy for listing identity assignments
package identity.assignment.list

import data.identity
import data.identity.assignment

# List role assignments.
#
# The `input.target.assignment` contains query parameters (RoleAssignmentListParameters):
#   domain_id:    string (optional)  Filters the response by a domain ID.
#   group_id:     string (optional)  Filters the response by a group ID.
#   effective:    bool (optional)    Returns the effective assignments.
#   project_id:   string (optional)  Filters the response by a project ID.
#   role_id:      string (optional)  Filters the response by a role ID.
#   user_id:      string (optional)  Filters the response by a user ID.
#   include_names: bool (optional)    Include names of entities.
#
# The `input.existing` is null
#
default allow := false

# METADATA
# description: "`Admin` is allowed by default"
allow if {
	"admin" in input.credentials.roles
}

# METADATA
# description: "'reader' in the system scope can list any role assignments."
allow if {
	"reader" in input.credentials.roles
	input.credentials.system_scope != null
	"all" == input.credentials.system_scope
}

# METADATA
# description: "`Manager` is allowed if the request is scoped to their domain and all other filters match that domain."
allow if {
	"manager" in input.credentials.roles

	# assignment.all_filters_match_scope
	assignment.is_scoped_to_token_domain
}
