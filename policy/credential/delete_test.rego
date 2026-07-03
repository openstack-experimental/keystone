package test_credential_delete

import data.identity.credential.delete

test_allowed if {
	delete.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"credential": {"user_id": "other"}}}
	delete.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "existing": {"credential": {"user_id": "u1"}}}
}

test_forbidden if {
	not delete.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "existing": {"credential": {"user_id": "other"}}}
	not delete.allow with input as {"credentials": {"roles": []}, "existing": {"credential": {"user_id": "u1"}}}
}

# OSSA-2026-015: delegated (trust/app-cred) caller bounded to its own project.
test_delegated_allowed if {
	delete.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p1", "delegated_project_id": "p1"}, "existing": {"credential": {"user_id": "u1", "project_id": "p1"}}}
}

test_delegated_forbidden if {
	not delete.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p2", "delegated_project_id": "p2"}, "existing": {"credential": {"user_id": "u1", "project_id": "p1"}}}
	not delete.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p1", "delegated_project_id": "p1"}, "existing": {"credential": {"user_id": "u1", "project_id": null}}}

	# Scope-drift tripwire: token scope diverges from the delegation's project.
	not delete.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p2", "delegated_project_id": "p1"}, "existing": {"credential": {"user_id": "u1", "project_id": "p1"}}}
}
