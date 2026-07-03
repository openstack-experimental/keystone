# METADATA
# title: Read OS-EC2 credential
# description: Policy for listing/showing a user's EC2 credentials (OS-EC2 legacy API)
package identity.os_ec2.read_credential

# Read (list or show) OS-EC2 credentials.
#
# List passes `input.target = {"user_id": <path user_id>}` and
# `input.existing = null`.
#
# Show passes `input.target = null` and
# `input.existing = {"user_id": <path user_id>, "credential": <Ec2Credential or null>}`.
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

# METADATA
# description: "A user may list their own EC2 credentials (list request)."
allow if {
	input.target.user_id == input.credentials.user_id
}

# METADATA
# description: "A user may read their own EC2 credential (show request)."
allow if {
	input.existing.user_id == input.credentials.user_id
}
