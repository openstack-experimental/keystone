# METADATA
# description: Policy for updating k8s auth instances
package identity.k8s_auth.instance.update

import data.identity

# Update k8s auth instance.
#
# The `input.target.instance` is the update patch (K8sAuthInstanceUpdate):
#   ca_cert:             string (optional)  PEM encoded CA cert.
#   disable_local_ca_jwt: bool (optional)   Disable defaulting to local CA cert and JWT.
#   enabled:             bool (optional)    If the instance is enabled.
#   host:                string (optional)  Host of the Kubernetes API server.
#   name:                string (optional)  K8s auth name.
#
# The `input.existing.instance` is the stored instance object (K8sAuthInstance):
#   ca_cert:             string (optional)  PEM encoded CA cert.
#   disable_local_ca_jwt: bool              Disable defaulting to local CA cert and JWT.
#   domain_id:           string            Domain ID owning the K8s auth configuration.
#   enabled:             bool              If the instance is enabled.
#   host:                string            Host of the Kubernetes API server.
#   id:                  string            K8s auth configuration ID.
#   name:                string (optional)  K8s auth name.
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_target
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
