# METADATA
# description: Policy for listing project tags
package identity.resource.project.tag.list

import data.identity
import data.identity.resource.project.tag as tag

# Listing the tags of a project.
#
# The `input.target` is null.
# The `input.existing.project` is the stored resource object (Project):
#   domain_id:    string            The ID of the domain for the project.
#   id:           string            The project ID.
#
default allow := false

allow if {
	input.credentials.is_admin
}

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"reader" in input.credentials.roles
	input.credentials.system == "all"
}

allow if {
	"reader" in input.credentials.roles
	identity.domain_matches_domain_scope
}

# A caller scoped to the project itself may read its tags.
allow if {
	tag.is_own_project
}

violation contains {"field": "domain_id", "msg": "listing the tags of a project requires system admin or `reader` role with system scope or domain scope."} if {
	not input.credentials.is_admin
	not "reader" in input.credentials.roles
	identity.domain_matches_domain_scope
}
