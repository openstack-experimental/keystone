# METADATA
# description: Policy for updating k8s auth roles
package identity.k8s_auth.role.update

import data.identity

# Update k8s auth role.
#
# The `input.target.role` is the update patch (K8sAuthRoleUpdate):
#   bound_audience:                  string (optional)  Optional Audience claim to verify in the JWT.
#   bound_service_account_names:     array (optional)   List of service account names able to access this role.
#   bound_service_account_namespaces: array (optional)   List of namespaces allowed to access this role.
#   enabled:                         bool (optional)    If the role is enabled.
#   name:                            string (optional)  K8s auth role name.
#   token_restriction_id:             string (optional)  A token restriction ID.
#
# The `input.existing.role` is the stored role object (K8sAuthRole):
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
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_target
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
