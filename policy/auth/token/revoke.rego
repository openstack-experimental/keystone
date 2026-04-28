# METADATA
# description: Policy for revoking authentication tokens
package identity.auth.token.revoke

import data.identity

default allow := false

allow if {
	"admin" in input.credentials.roles
}

# allow if {
# 	"service" in input.credentials.roles
# }

# allow if {
# 	"reader" in input.credentials.roles
# 	input.credentials.system_scope != null
# 	"all" == input.credentials.system_scope
# }

# METADATA
# description: Token owner can revoke own token
allow if {
	identity.token_subject
}
