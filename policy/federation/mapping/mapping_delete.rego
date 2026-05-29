# METADATA
# description: Policy for deleting federation mappings
package identity.federation.mapping.delete

import data.identity.federation as common_federation

# Delete mapping.
#
# The `input.target.mapping` is the stored mapping object (Mapping):
#   domain_id:    string        domain ID
#   id:           string        mapping ID
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

violation contains {"field": "domain_id", "msg": "deleting the global mapping requires `admin` role."} if {
	common_federation.global_mapping
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "deleting the mapping owned by the other domain requires `admin` role."} if {
	common_federation.foreign_mapping
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "deleting the mapping requires `manager` role."} if {
	common_federation.own_mapping
	not "manager" in input.credentials.roles
}
