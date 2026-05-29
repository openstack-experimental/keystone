# METADATA
# description: Policy for listing federation mappings
package identity.federation.mapping.list

import data.identity
import data.identity.federation as common_federation

# List mappings.
#
# The `input.target.mapping` contains query parameters (MappingListParameters):
#   domain_id: string (optional)  Filters the response by a domain ID.
#   idp_id:    string (optional)  Filters the response by a idp ID.
#   name:      string (optional)  Filters the response by IDP name.
#   limit:     integer (optional) Limit number of entries.
#   marker:    string (optional)  Page marker.
#   type:      string (optional)  Filters the response by a mapping type.
#
# The `input.existing` is null
#
default allow := false

allow if {
	common_federation.own_mapping
	"reader" in input.credentials.roles
}

allow if {
	common_federation.global_mapping
	"reader" in input.credentials.roles
}

allow if {
	"admin" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "listing federated mappings owned by other domain requires `admin` role."} if {
	common_federation.foreign_mapping
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "listing federated mappings owned by the domain requires `reader` role."} if {
	common_federation.own_mapping
	not "reader" in input.credentials.roles
}

violation contains {"field": "role", "msg": "listing global federated mappings requires `reader` role."} if {
	common_federation.global_mapping
	not "reader" in input.credentials.roles
}
