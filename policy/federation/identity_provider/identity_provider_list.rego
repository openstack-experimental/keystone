# METADATA
# description: Policy for listing identity providers
package identity.federation.identity_provider.list

import data.identity.federation as common_federation

# List identity providers
#
# The `input.target.identity_provider` contains query parameters (IdentityProviderListParameters):
#   name:       string (optional)  Filters the response by IDP name.
#   domain_id:  string (optional)  Filters the response by a domain ID.
#   limit:      integer (optional) Limit number of entries.
#   marker:     string (optional)  Page marker.
#
# The `input.existing` is null
#
default allow := false

default can_see_other_domain_resources := false

can_see_other_domain_resources if {
	"admin" in input.credentials.roles
}

allow if {
	common_federation.own_idp
	"reader" in input.credentials.roles
}

allow if {
	common_federation.global_idp
	"reader" in input.credentials.roles
}

allow if {
	"admin" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "listing federated identity providers owned by other domain requires `admin` role."} if {
	common_federation.foreign_idp
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "listing federated identity providers owned by the domain requires `reader` role."} if {
	common_federation.own_idp
	not "reader" in input.credentials.roles
}

violation contains {"field": "role", "msg": "listing global federated identity providers requires `reader` role."} if {
	common_federation.global_idp
	not "reader" in input.credentials.roles
}
