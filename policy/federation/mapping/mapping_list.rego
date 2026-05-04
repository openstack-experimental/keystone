# METADATA
# description: Policy for listing federation mappings
package identity.mapping_list

import data.identity

# List mappings.

default allow := false

allow if {
	identity.own_mapping
	"reader" in input.credentials.roles
}

allow if {
	identity.global_mapping
	"reader" in input.credentials.roles
}

allow if {
	"admin" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "listing federated mappings owned by other domain requires `admin` role."} if {
	identity.foreign_mapping
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "listing federated mappings owned by the domain requires `reader` role."} if {
	identity.own_mapping
	not "reader" in input.credentials.roles
}

violation contains {"field": "role", "msg": "listing global federated mappings requires `reader` role."} if {
	identity.global_mapping
	not "reader" in input.credentials.roles
}
