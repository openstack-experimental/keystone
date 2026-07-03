package test_os_ec2_create_credential

import data.identity.os_ec2.create_credential

test_allowed if {
	create_credential.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"user_id": "other", "tenant_id": "pid"}}
	create_credential.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "target": {"user_id": "u1", "tenant_id": "pid"}}
}

test_forbidden if {
	not create_credential.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "target": {"user_id": "other", "tenant_id": "pid"}}
	not create_credential.allow with input as {"credentials": {"roles": []}, "target": {"user_id": "u1", "tenant_id": "pid"}}
}

# OSSA-2026-005 / CVE-2026-33551: restricted application credentials must
# never be able to mint an EC2 credential.
test_restricted_app_cred_forbidden if {
	not create_credential.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "auth_type": "application_credential", "unrestricted": false}, "target": {"user_id": "u1", "tenant_id": "pid"}}
}

test_unrestricted_app_cred_allowed if {
	create_credential.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "auth_type": "application_credential", "unrestricted": true}, "target": {"user_id": "u1", "tenant_id": "pid"}}
}

# OSSA-2026-015: delegation project boundary applies here too, anchored on
# the delegation's own immutable project (`delegated_project_id`).
test_delegated_allowed if {
	create_credential.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "pid", "delegated_project_id": "pid"}, "target": {"user_id": "u1", "tenant_id": "pid"}}
}

test_delegated_forbidden if {
	# Requested tenant differs from the delegation's project.
	not create_credential.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "other_pid", "delegated_project_id": "other_pid"}, "target": {"user_id": "u1", "tenant_id": "pid"}}

	# Scope-drift tripwire: token scope diverges from the delegation's project.
	not create_credential.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "other_pid", "delegated_project_id": "pid"}, "target": {"user_id": "u1", "tenant_id": "pid"}}
}
