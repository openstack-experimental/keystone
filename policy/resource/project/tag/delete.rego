# METADATA
# description: Policy for deleting project tags
package identity.resource.project.tag.delete

import data.identity

# Deleting the tags of a project.
#
# The `input.target.tag` is the tag being deleted (absent when deleting all tags).
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
	"manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "deleting the tags of a project requires system admin or `manager` role in the domain scope."} if {
	not input.credentials.is_admin
	not "manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}
