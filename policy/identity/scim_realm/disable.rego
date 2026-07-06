# METADATA
# description: Policy for updating a SCIM realm, including the enable/disable
#   toggle (ADR 0024 §2.B, the Realm Activation Gate)
package identity.scim_realm.disable

import data.identity

# Update (including enable/disable) a SCIM realm.
#
# The `input.target.scim_realm` is the update patch (ScimRealmUpdate):
#   display_name: string (optional)  New display name.
#   enabled:      bool (optional)    Enable/disable toggle.
#
# The `input.existing.scim_realm` is the stored realm object.
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

violation contains {"field": "domain_id", "msg": "updating a SCIM realm in a domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	"manager" in input.credentials.roles
	input.existing.scim_realm.domain_id != input.credentials.domain_id
}

violation contains {"field": "domain_id", "msg": "updating a SCIM realm requires a manager role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}
