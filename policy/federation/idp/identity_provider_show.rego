# METADATA
# description: Policy for viewing identity provider details
package identity.identity_provider_show

import data.identity

# Show identity provider.

default allow := false

allow if {
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

violation contains {"field": "domain_id", "msg": "fetching identity provider details owned by other domain requires `admin` role."} if {
	identity.foreign_idp
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "fetching own identity provider details requires `reader`."} if {
	identity.own_idp
	not "reader" in input.credentials.roles
}

violation contains {"field": "role", "msg": "fetching global identity provider details requires `reader`."} if {
	identity.global_idp
	not "reader" in input.credentials.roles
}
