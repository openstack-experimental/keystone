# METADATA
# title: Create OS-EC2 credential
# description: Policy for creating an EC2 credential for a user (OS-EC2 legacy API)
package identity.os_ec2.create_credential

import data.identity.credential as credential_common

# Create an OS-EC2 credential.
#
# `input.target = {"user_id": <path user_id>, "tenant_id": <requested project_id>}`.
# `input.existing` is null.
#
# - Delegation boundary (OSSA-2026-015): a delegated caller (trust,
#   application credential) may only create an EC2 credential bound to its
#   own delegation project.
# - Restricted application credentials (OSSA-2026-005 / CVE-2026-33551):
#   a *restricted* application credential must not be usable to mint an
#   EC2/S3 credential at all — once used via `/v3/ec2tokens`, an EC2
#   credential authenticates independently of its creator's own role
#   restriction, so allowing this would let a reader-only restricted
#   app-cred obtain a credential carrying the parent user's full
#   permissions.
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
	not is_restricted_app_cred
	credential_common.not_delegated_or_bound_to_own_project(object.get(input.target, "tenant_id", null))
}

# METADATA
# description: "A restricted application credential may never create an EC2 credential."
is_restricted_app_cred if {
	input.credentials.auth_type == "application_credential"
	not input.credentials.unrestricted
}
