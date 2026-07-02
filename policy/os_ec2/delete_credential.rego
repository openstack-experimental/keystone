# METADATA
# title: Delete OS-EC2 credential
# description: Policy for deleting a user's EC2 credential by plaintext access key (OS-EC2 legacy API)
package identity.os_ec2.delete_credential

# Delete an OS-EC2 credential.
#
# `input.target` is null.
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
# description: "A user may delete their own EC2 credential."
allow if {
	input.existing.user_id == input.credentials.user_id
}
