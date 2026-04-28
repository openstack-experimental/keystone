# METADATA
# description: Policy for listing identity providers
package identity.identity_provider_list

import data.identity

# List identity providers

default allow := false

default can_see_other_domain_resources := false

can_see_other_domain_resources if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_idp
	"reader" in input.credentials.roles
}

allow if {
	identity.global_idp
	"reader" in input.credentials.roles
}

allow if {
	"admin" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "listing federated identity providers owned by other domain requires `admin` role."} if {
	identity.foreign_identity_provider
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "listing federated identity providers owned by the domain requires `reader` role."} if {
	identity.own_idp
	not "reader" in input.credentials.roles
}

violation contains {"field": "role", "msg": "listing global federated identity providers requires `reader` role."} if {
	identity.global_idp
	not "reader" in input.credentials.roles
}
