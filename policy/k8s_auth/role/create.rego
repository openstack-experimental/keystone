# METADATA
# description: Policy for creating k8s auth roles
package identity.k8s_auth.role.create

import data.identity

# Create k8s auth role.
#
# The `input.target.instance` is the instance context:
#   domain_id:    string        domain ID
#
# The `input.target.role` is the new role object (K8sAuthRoleCreate):
#   bound_audience:                string (optional)  Optional Audience claim to verify in the JWT.
#   bound_service_account_names:   array              List of service account names able to access this role.
#   bound_service_account_namespaces: array            List of namespaces allowed to access this role.
#   enabled:                       bool              If the role is enabled.
#   name:                          string            K8s auth role name.
#   token_restriction_id:           string            A token restriction ID.
#
# The `input.existing` is null
#
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
