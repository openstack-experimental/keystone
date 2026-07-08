# METADATA
# description: Policy for listing SCIM-provisioned groups (ADR 0024 §3, §8)
package identity.scim.group.list

import data.identity

# List SCIM-provisioned groups owned by the realm.
#
# The `input.target.group` carries at least:
#   domain_id: string  Domain the realm is scoped to.
#
# The `input.existing` is null.
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

allow if {
	"manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}

allow if {
	"scim_provisioner" in input.credentials.roles
	identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "listing SCIM groups in a domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	not identity.domain_matches_domain_scope
}

violation contains {"field": "roles", "msg": "listing SCIM groups requires a scim_provisioner or manager role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	not "scim_provisioner" in input.credentials.roles
	identity.domain_matches_domain_scope
}
