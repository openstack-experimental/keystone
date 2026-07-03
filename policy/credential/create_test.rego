package test_credential_create

import data.identity.credential.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"credential": {"user_id": "other"}}}
	create.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "target": {"credential": {}}}
	create.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "target": {"credential": {"user_id": "u1"}}}
}

test_forbidden if {
	not create.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "target": {"credential": {"user_id": "other"}}}
	not create.allow with input as {"credentials": {"roles": []}, "target": {"credential": {}}}
}

# OSSA-2026-015: delegated (trust/app-cred) caller may only create a
# credential bound to its own delegation project.
test_delegated_allowed if {
	create.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p1", "delegated_project_id": "p1"}, "target": {"credential": {"user_id": "u1", "project_id": "p1"}}}
}

test_delegated_forbidden if {
	# Different project than the delegation.
	not create.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p1", "delegated_project_id": "p1"}, "target": {"credential": {"user_id": "u1", "project_id": "p2"}}}

	# No project_id at all (would create an unscoped credential via delegation).
	not create.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p1", "delegated_project_id": "p1"}, "target": {"credential": {"user_id": "u1"}}}

	# Scope-drift tripwire: token scope diverges from the delegation's project.
	not create.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p2", "delegated_project_id": "p1"}, "target": {"credential": {"user_id": "u1", "project_id": "p1"}}}
}

# OSSA-2026-005 / CVE-2026-33551: a restricted application credential must
# never be able to create an ec2-type credential (regardless of project),
# but is unaffected for other credential types (e.g. totp).
test_restricted_app_cred_forbidden if {
	not create.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "auth_type": "application_credential", "unrestricted": false, "is_delegated": true, "project_id": "p1", "delegated_project_id": "p1"}, "target": {"credential": {"user_id": "u1", "type": "ec2", "project_id": "p1"}}}
}

test_restricted_app_cred_allowed_for_non_ec2 if {
	create.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "auth_type": "application_credential", "unrestricted": false, "is_delegated": true, "project_id": "p1", "delegated_project_id": "p1"}, "target": {"credential": {"user_id": "u1", "type": "totp", "project_id": "p1"}}}
}

test_unrestricted_app_cred_allowed_for_ec2 if {
	create.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "auth_type": "application_credential", "unrestricted": true, "is_delegated": true, "project_id": "p1", "delegated_project_id": "p1"}, "target": {"credential": {"user_id": "u1", "type": "ec2", "project_id": "p1"}}}
}
