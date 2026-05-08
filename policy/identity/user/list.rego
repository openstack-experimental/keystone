# METADATA
# description: Policy for listing users
package identity.user.list

import data.identity

default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	"reader" in input.credentials.roles
	input.credentials.system == "all"
}

allow if {
	"reader" in input.credentials.roles
	identity.domain_matches_domain_scope
}

#allow if {
#  response := http.send({
#    "method": "HEAD",
#    "url": sprintf("https://localhost:8215/v3/projects/%s/users/%s/roles/reader", [input.credentials.project_id, input.credentials.user_id]),
#    "tls_client_cert_file": "/tmp/certs/svid.0.pem",
#    "tls_client_key_file": "/tmp/certs/svid.0.key",
#    "tls_ca_cert_file": "/tmp/certs/bundle.0.pem",
#    "tls_insecure_skip_verify": true
#  })
#  response.status_code == 200
#}

violation contains {"field": "domain_id", "msg": "listing users in domain different to the domain scope requires `admin` role."} if {
	not "admin" in input.credentials.roles
	"manager" in input.credentials.roles
	not identity.domain_matches_domain_scope
}

violation contains {"field": "domain_id", "msg": "listing users requires a reader role with the domain scope."} if {
	not "admin" in input.credentials.roles
	not "reader" in input.credentials.roles
	identity.domain_matches_domain_scope
}
