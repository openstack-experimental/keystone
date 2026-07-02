# METADATA
# title: Create OS-EC2 credential
# description: Policy for creating an EC2 credential for a user (OS-EC2 legacy API)
package identity.os_ec2.create_credential

# Create an OS-EC2 credential.
#
# `input.target = {"user_id": <path user_id>, "tenant_id": <requested project_id>}`.
# `input.existing` is null.
#
default allow := false

allow if {
	"admin" in input.credentials.roles
}

allow if {
	input.credentials.is_admin
}

# METADATA
# description: "A user may create EC2 credentials for themselves."
allow if {
	"member" in input.credentials.roles
	input.target.user_id == input.credentials.user_id
}
