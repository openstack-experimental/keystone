# METADATA
# description: Policy for registering a new SCIM realm (ADR 0024 §2.A)
package identity.scim_realm.create

import data.identity

# Register a SCIM realm.
#
# The `input.target.scim_realm` is the creation payload:
#   domain_id:     string  Domain owning the realm.
#   provider_id:   string  The provider_id coordinate this realm authorizes.
#   display_name:  string  Administrative display name.
#
# The `input.existing` is null
#
# Per ADR 0021 §5.A / ADR 0024 §8, realm CRUD requires the `manager` role
# (domain-scoped) or `admin` (cross-domain). Realm CRUD is invoked by a
# Fernet-authenticated human operator, not the SCIM API key itself, so
# `manager`/`admin` here can be backed by a real RoleAssignment.
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

violation contains {"field": "domain_id", "msg": "registering a SCIM realm in a domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	"manager" in input.credentials.roles
	not identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "registering a SCIM realm requires a manager role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	identity.domain_matches_domain_scope
}
