package identity.k8s_auth.role.create

import data.identity

# # Create k8s auth role.

# # Input:
# * input.target.instance - auth_instance object
# * input.target.role - auth_role object

default allow := false

own_instance if {
	input.target.instance.domain_id != null
	input.target.instance.domain_id == input.credentials.domain_id
}

foreign_instance if {
	input.target.instance.domain_id != null
	input.target.instance.domain_id != input.credentials.domain_id
}

allow if {
	"admin" in input.credentials.roles
}

allow if {
	own_instance
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "creating k8s_auth role for other domain requires `admin` role."} if {
	foreign_instance
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "creating k8s_auth role requires `manager` role."} if {
	own_instance
	not "member" in input.credentials.roles
}
