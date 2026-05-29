# METADATA
# description: Policy for creating federation mappings
package identity.federation.mapping.create

import data.identity.federation as common_federation

# Create mapping.
#
# The `input.target.mapping` is the new mapping object (MappingCreate):
#   id:                    string (optional)  Attribute mapping ID.
#   name:                  string            Attribute mapping name.
#   domain_id:             string (optional)  `domain_id` owning the attribute mapping.
#   idp_id:                string            ID of the federated identity provider.
#   type:                  string (optional)  Attribute mapping type ([oidc, jwt]).
#   enabled:               bool              Mapping enabled property.
#   allowed_redirect_uris: array (optional)   List of allowed redirect urls.
#   user_id_claim:         string            `user_id` claim name.
#   user_name_claim:       string            `user_name` claim name.
#   domain_id_claim:       string (optional)  `domain_id` claim name.
#   groups_claim:          string (optional)  `groups` claim name.
#   bound_audiences:       array (optional)   List of audiences.
#   bound_subject:         string (optional)  Token subject value.
#   bound_claims:          object             Additional claims.
#   oidc_scopes:           array (optional)   List of OIDC scopes.
#   token_project_id:      string (optional)  Fixed project_id for the token.
#   token_restriction_id:   string (optional)  Token restrictions.
#
# The `input.existing` is null
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	common_federation.own_mapping
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "creating mapping for other domain requires `admin` role."} if {
	common_federation.foreign_mapping
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "creating global mapping requires `admin` role."} if {
	common_federation.global_mapping
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "creating mapping requires `manager` role."} if {
	common_federation.own_mapping
	not "member" in input.credentials.roles
}
