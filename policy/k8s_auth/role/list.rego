# METADATA
# description: Policy for listing k8s auth roles
package identity.k8s_auth.role.list

import data.identity

# List k8s auth role.
#
# The `input.target.role` contains query parameters (K8sAuthRoleListParameters):
#   auth_instance_id: string (optional)  K8s auth instance id.
#   domain_id:        string (optional)  Domain id.
#   name:             string (optional)  Name.
#
# The `input.existing` is null
#
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
	input.target.role.domain_id == null
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
