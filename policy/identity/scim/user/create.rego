# METADATA
# description: Policy for provisioning a SCIM user (ADR 0024 §3, §8)
package identity.scim.user.create

import data.identity

# Create a new SCIM-provisioned user.
#
# The `input.target.user` carries at least:
#   domain_id: string  Domain the realm is scoped to.
#
# The `input.existing` is null.
#
# The Realm Activation Gate (ADR 0024 §2.B) and the domain-only scope
# restriction (§2.C) are already enforced by the `ScimRealmAuth` extractor
# before this policy runs. This check additionally requires the realm's
# ephemeral identity to carry the `scim_provisioner` role. Since SCIM
# resource CRUD is invoked exclusively via API-key ingress (ADR 0021),
# `manager`/`admin`/`scim_provisioner` here are never backed by a real
# RoleAssignment -- API keys carry no Role at all. Each is simply a string
# an operator configures the realm's own MappingRuleSet (ADR 0020 UME) to
# emit as `Authorization::Domain{roles}` at request time (ADR 0024 §8).
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

violation contains {"field": "domain_id", "msg": "provisioning a SCIM user in a domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	not identity.domain_matches_domain_scope
}

violation contains {"field": "roles", "msg": "provisioning a SCIM user requires a scim_provisioner or manager role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "manager" in input.credentials.roles
	not "scim_provisioner" in input.credentials.roles
	identity.domain_matches_domain_scope
}
