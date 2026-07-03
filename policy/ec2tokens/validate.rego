# METADATA
# description: Policy for validating a signed EC2 request (POST /v3/ec2tokens)
package identity.ec2tokens.validate

# The `input.target` is empty — the credential referenced by the signed
# request is not known until after signature verification, so this policy
# only gates who may call the endpoint at all (ADR 0019 §5,
# CVE-2025-65073: the endpoint now requires an authenticated caller).
default allow := false

allow if {
	"admin" in input.credentials.roles
}

# METADATA
# description: Service scope can validate EC2 signatures on behalf of end users
allow if {
	"service" in input.credentials.roles
}
