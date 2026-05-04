# METADATA
# description: Policy for viewing federation mapping details
package identity.mapping_show

import data.identity

# Show identity provider.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_mapping
	"reader" in input.credentials.roles
}

allow if {
	identity.global_mapping
	"reader" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "fetching mapping details owned by other domain requires `admin` role."} if {
	identity.foreign_mapping
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "fetching own mapping details requires `reader`."} if {
	identity.own_mapping
	not "reader" in input.credentials.roles
}

violation contains {"field": "role", "msg": "fetching global mappingdetails requires `reader`."} if {
	identity.global_mapping
	not "reader" in input.credentials.roles
}
