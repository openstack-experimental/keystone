package identity.k8s_auth.role.delete

import data.identity

# Delete k8s auth role.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_target
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "deleting k8s_auth role for other domain requires `admin` role."} if {
	identity.foreign_target
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "deleting k8s_auth role requires `manager` role."} if {
	identity.own_target
	not "member" in input.credentials.roles
}
