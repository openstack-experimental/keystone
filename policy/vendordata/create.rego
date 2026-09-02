# METADATA
# description: Policy for signing a per-instance vendor data attestation JWT (SPIRE integration plan, Phase 2)
package identity.vendordata.create

default allow := false

allow if {
	"service" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

violation contains {"field": "role", "msg": msg} if {
	not "service" in input.credentials.roles
	not input.credentials.is_admin
	msg := "signing a vendor data attestation JWT requires the service role."
}
