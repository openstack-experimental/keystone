# METADATA
# description: Policy for viewing a SCIM realm (ADR 0024 §2.A)
package identity.scim_realm.show

import data.identity

# Show a SCIM realm.
#
# The `input.existing.scim_realm` is the stored realm object:
#   domain_id:     string  Domain owning the realm.
#   provider_id:   string  The provider_id coordinate this realm authorizes.
#   display_name:  string  Administrative display name.
#   enabled:       bool    Whether the realm currently authorizes provisioning.
#
# The `input.target` is null
#
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

violation contains {"field": "domain_id", "msg": "reading a SCIM realm in a domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	"manager" in input.credentials.roles
	not identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "reading a SCIM realm requires a manager role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}
