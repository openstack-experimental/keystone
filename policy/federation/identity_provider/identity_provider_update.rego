# METADATA
# description: Policy for updating identity providers
package identity.federation.identity_provider.update

import data.identity.federation as common_federation

# Update identity provider.
#
# The `input.target.identity_provider` is the update patch (IdentityProviderUpdate):
#   name:                    string (optional)  The new name.
#   enabled:                 bool (optional)    Identity provider `enabled` property.
#   oidc_discovery_url:      string (optional)  The new OIDC discovery endpoint.
#   oidc_client_id:          string (optional)  The new oidc `client_id`.
#   oidc_client_secret:      string (optional)  The new oidc `client_secret`.
#   oidc_response_mode:      string (optional)  The new oidc response mode.
#   oidc_response_types:     array (optional)   The new oidc response types.
#   jwks_url:                string (optional)  New URL to fetch JsonWebKeySet.
#   jwt_validation_pubkeys:  array (optional)   The list of the jwt validation public keys.
#   bound_issuer:            string (optional)  The new bound issuer.
#   default_mapping_name:    string (optional)  New default attribute mapping name.
#   provider_config:         object (optional)  New additional provider configuration.
#
# The `input.existing.identity_provider` is the stored IDP object (IdentityProvider):
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
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	common_federation.own_idp
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "updating identity provider for other domain requires `admin` role."} if {
	common_federation.foreign_idp
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "updating global identity provider requires `admin` role."} if {
	common_federation.global_idp
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "updating identity provider requires `manager` role."} if {
	common_federation.own_idp
	not "member" in input.credentials.roles
}
