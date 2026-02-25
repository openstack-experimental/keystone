package identity.k8s_auth.instance.update

import data.identity

# Update k8s auth instance.

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_idp
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "updating k8s_auth instance for other domain requires `admin` role."} if {
	identity.foreign_target
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "updating k8s_auth instance requires `manager` role."} if {
	identity.own_target
	not "member" in input.credentials.roles
}
