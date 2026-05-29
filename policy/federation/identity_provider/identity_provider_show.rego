# METADATA
# description: Policy for viewing identity provider details
package identity.federation.identity_provider.show

import data.identity.federation as common_federation

# Show identity provider.
#
# The `input.target.identity_provider` is the stored IDP object (IdentityProvider):
#   id:                    string            The ID of the federated identity provider.
#   name:                  string            The Name of the federated identity provider.
#   domain_id:             string (optional)  The ID of the domain this identity provider belongs to.
#   enabled:               bool              Identity provider `enabled` property.
#   oidc_discovery_url:    string (optional)  OIDC discovery endpoint.
#   oidc_client_id:        string (optional)  The oidc `client_id`.
#   oidc_response_mode:    string (optional)  The oidc response mode.
#   oidc_response_types:   array (optional)   List of supported response types.
#   jwks_url:              string (optional)  URL to fetch JsonWebKeySet.
#   jwt_validation_pubkeys: array (optional)   List of the jwt validation public keys.
#   bound_issuer:          string (optional)  The bound issuer.
#   default_mapping_name:  string (optional)  Default attribute mapping name.
#   provider_config:       object (optional)  Additional provider configuration.
#
# The `input.existing` is null
#
default allow := false

allow if {
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

violation contains {"field": "domain_id", "msg": "fetching identity provider details owned by other domain requires `admin` role."} if {
	common_federation.foreign_idp
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "fetching own identity provider details requires `reader`."} if {
	common_federation.own_idp
	not "reader" in input.credentials.roles
}

violation contains {"field": "role", "msg": "fetching global identity provider details requires `reader`."} if {
	common_federation.global_idp
	not "reader" in input.credentials.roles
}
