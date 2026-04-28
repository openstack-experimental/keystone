# METADATA
# description: Policy for viewing authentication token details
package identity.auth.token.show

import data.identity

default allow := false

allow if {
	"admin" in input.credentials.roles
}

# METADATA
# description: Service scope can inspect tokens
allow if {
	"service" in input.credentials.roles
}

# METADATA
# description: "'reader' in the system scope can inspect tokens"
allow if {
	"reader" in input.credentials.roles
	input.credentials.system_scope != null
	"all" == input.credentials.system_scope
}

# METADATA
# description: Token owner can inspect own token
allow if {
	identity.token_subject
}
