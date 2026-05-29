# METADATA
# description: Policy for creating k8s auth instances
package identity.k8s_auth.instance.create

import data.identity

# Create k8s auth instance.
#
# The `input.target.instance` is the new instance object (K8sAuthInstanceCreate):
#   ca_cert:             string (optional)  PEM encoded CA cert.
#   disable_local_ca_jwt: bool (optional)   Disable defaulting to local CA cert and JWT.
#   domain_id:           string            Domain ID owning the K8s auth instance.
#   enabled:             bool              If the instance is enabled.
#   host:                string            Host of the Kubernetes API server.
#   name:                string (optional)  K8s auth name.
#
# The `input.existing` is null
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	identity.own_target
	"manager" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "creating k8s_auth instance for other domain requires `admin` role."} if {
	identity.foreign_target
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "creating k8s_auth instance requires `manager` role."} if {
	identity.own_target
	not "member" in input.credentials.roles
}
