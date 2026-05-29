# METADATA
# description: Policy for viewing k8s auth role details
package identity.k8s_auth.role.show

import data.identity

# Show k8s auth role.
#
# The `input.target.role` is the stored role object (K8sAuthRole):
#   auth_instance_id:                string            ID of the K8s auth instance this role belongs to.
#   bound_audience:                  string (optional)  Optional Audience claim to verify in the JWT.
#   bound_service_account_names:     array              List of service account names able to access this role.
#   bound_service_account_namespaces: array              List of namespaces allowed to access this role.
#   domain_id:                       string            Domain ID owning the K8s auth role configuration.
#   enabled:                         bool              If the role is enabled.
#   id:                              string            K8s auth role ID.
#   name:                            string            K8s auth role name.
#   token_restriction_id:             string            A token restriction ID.
#
# The `input.existing` is null
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_target
	"reader" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "showing k8s_auth role for other domain requires `admin` role."} if {
	identity.foreign_target
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "showing k8s_auth role requires `reader` role."} if {
	identity.own_target
	not "member" in input.credentials.roles
}
