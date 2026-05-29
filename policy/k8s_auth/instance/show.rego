# METADATA
# description: Policy for viewing k8s auth instance details
package identity.k8s_auth.instance.show

import data.identity

# Show k8s auth instance.
#
# The `input.target.instance` is the stored instance object (K8sAuthInstance):
#   ca_cert:             string (optional)  PEM encoded CA cert.
#   disable_local_ca_jwt: bool              Disable defaulting to local CA cert and JWT.
#   domain_id:           string            Domain ID owning the K8s auth configuration.
#   enabled:             bool              If the instance is enabled.
#   host:                string            Host of the Kubernetes API server.
#   id:                  string            K8s auth configuration ID.
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
	"reader" in input.credentials.roles
}

violation contains {"field": "domain_id", "msg": "showing k8s_auth instance for other domain requires `admin` role."} if {
	identity.foreign_target
	not "admin" in input.credentials.roles
}

violation contains {"field": "role", "msg": "showing k8s_auth instance requires `reader` role."} if {
	identity.own_target
	not "member" in input.credentials.roles
}
