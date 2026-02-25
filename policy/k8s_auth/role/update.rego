package identity.k8s_auth.role.update

import data.identity

# Update k8s auth role.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_idp
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "updating k8s_auth role for other domain requires `admin` role."} if {
	identity.foreign_target
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "updating k8s_auth role requires `manager` role."} if {
	identity.own_target
	not "member" in input.credentials.roles
}
