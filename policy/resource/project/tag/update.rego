# METADATA
# description: Policy for updating (replacing or adding) project tags
package identity.resource.project.tag.update

import data.identity

# Updating the tags of a project.
#
# The `input.target.tags` is the new set of tags when replacing all tags, or
# `input.target.tag` is the single tag being added.
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

violation contains {"field": "domain_id", "msg": "updating the tags of a project requires system admin or `manager` role in the domain scope."} if {
	not input.credentials.is_admin
	not "manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}
