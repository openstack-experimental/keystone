package identity.k8s_auth.role.list

import data.identity

# List k8s auth role.

default allow := false

can_see_other_domain_resources if {
	"admin" in input.credentials.roles
}

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_target
	"reader" in input.credentials.roles
}

# allow listing when the domain_id is unset. Code is responsible for setting
# domain_id to the current one.
allow if {
	input.target.domain_id == null
	"reader" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "listing k8s_auth roles for other domain requires `admin` role."} if {
	identity.foreign_target
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "listing k8s_auth roles requires `reader` role."} if {
	identity.own_target
	not "reader" in input.credentials.roles
}
