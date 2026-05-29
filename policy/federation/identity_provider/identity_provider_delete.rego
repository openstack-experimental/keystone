# METADATA
# description: Policy for deleting identity providers
package identity.federation.identity_provider.delete

import data.identity.federation as common_federation

# Delete identity provider.
#
# The `input.target.identity_provider` is the stored IDP object (IdentityProvider):
#   domain_id:    string        Domain ID
#   id:           string        IDP ID
#
# The `input.existing` is null
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	common_federation.own_idp
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "deleting the global identity provider requires `admin` role."} if {
	common_federation.global_idp
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "deleting the identity provider owned by the other domain requires `admin` role."} if {
	common_federation.foreign_idp
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "deleting the identity provider requires `manager` role."} if {
	common_federation.own_idp
	not "manager" in input.credentials.roles
}
