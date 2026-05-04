# METADATA
# description: Policy for creating identity providers
package identity.identity_provider_create

import data.identity

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_idp
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "creating identity provider for other domain requires `admin` role."} if {
	identity.foreign_idp
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "creating global identity provider requires `admin` role."} if {
	identity.global_idp
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "creating identity provider requires `manager` role."} if {
	identity.own_idp
	not "member" in input.credentials.roles
}
