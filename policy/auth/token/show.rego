# METADATA
# description: Policy for viewing authentication token details
package identity.auth.token.show

import data.identity

# View authentication token details.
#
# The `input.target.token` is the stored token object (Token):
#   audit_ids:    array              A list of one or two audit IDs.
#   methods:      array              The authentication methods.
#   expires_at:   datetime           The date and time when the token expires.
#   issued_at:    datetime           The date and time when the token was issued.
#   user:         object             A user object.
#   domain:       object (optional)  A domain object.
#   project:      object (optional)  A project object.
#   trust:        object (optional)  A trust object.
#   roles:        array (optional)   A list of role objects.
#   system:       object (optional)  A system object.
#   catalog:      object (optional)  A catalog object.
#
# The `input.existing` is null
#
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
