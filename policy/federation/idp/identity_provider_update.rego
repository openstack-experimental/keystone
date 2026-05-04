# METADATA
# description: Policy for updating identity providers
package identity.identity_provider_update

import data.identity

# Update identity provider.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_idp
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "updating identity provider for other domain requires `admin` role."} if {
	identity.foreign_idp
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "updating global identity provider requires `admin` role."} if {
	identity.global_idp
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "updating identity provider requires `manager` role."} if {
	identity.own_idp
	not "member" in input.credentials.roles
}
