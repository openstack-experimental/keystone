# METADATA
# description: Policy for soft-disabling a SCIM-provisioned user (ADR 0024 §3, §6.A, §8)
package identity.scim.user.delete

import data.identity

# `DELETE` (soft-disable) a SCIM-provisioned user.
#
# The `input.existing.user` is the stored `UserResponse`.
#
# The Ownership Fencing Algorithm (ADR 0024 §3.C) has already run in the
# handler before this policy is evaluated — this is a second, independent
# authorization check, not a substitute for it (§8).
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

violation contains {"field": "domain_id", "msg": "disabling a SCIM user in a domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	not identity.domain_matches_domain_scope
}

violation contains {"field": "roles", "msg": "disabling a SCIM user requires a scim_provisioner or manager role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	not "scim_provisioner" in input.credentials.roles
	identity.domain_matches_domain_scope
}
