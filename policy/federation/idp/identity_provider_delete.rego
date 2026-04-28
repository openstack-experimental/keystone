# METADATA
# description: Policy for deleting identity providers
package identity.identity_provider_delete

import data.identity

# Show identity provider.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_idp
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "deleting the global identity provider requires `admin` role."} if {
	identity.global_idp
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "deleting the identity provider owned by the other domain requires `admin` role."} if {
	identity.foreign_idp
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "deleting the identity provider requires `manager` role."} if {
	identity.own_idp
	not "manager" in input.credentials.roles
}
