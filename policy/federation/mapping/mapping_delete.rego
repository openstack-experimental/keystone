# METADATA
# description: Policy for deleting federation mappings
package identity.mapping_delete

import data.identity

# Show mapping.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_mapping
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "deleting the global mapping requires `admin` role."} if {
	identity.global_mapping
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "deleting the mapping owned by the other domain requires `admin` role."} if {
	identity.foreign_mapping
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "deleting the mapping requires `manager` role."} if {
	identity.own_mapping
	not "manager" in input.credentials.roles
}
