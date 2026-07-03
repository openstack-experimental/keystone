package test_credential_update

import data.identity.credential.update

test_allowed if {
	update.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"credential": {"user_id": "other"}}}
	update.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "existing": {"credential": {"user_id": "u1"}}}
}

test_forbidden if {
	not update.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "existing": {"credential": {"user_id": "other"}}}
	not update.allow with input as {"credentials": {"roles": []}, "existing": {"credential": {"user_id": "u1"}}}
}

# OSSA-2026-015: delegated (trust/app-cred) caller bounded to its own project.
test_delegated_allowed if {
	update.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p1", "delegated_project_id": "p1"}, "existing": {"credential": {"user_id": "u1", "project_id": "p1"}}, "target": {"credential": {}}}
}

test_delegated_forbidden if {
	# Delegation bound to a different project than the credential.
	not update.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p2", "delegated_project_id": "p2"}, "existing": {"credential": {"user_id": "u1", "project_id": "p1"}}, "target": {"credential": {}}}

	# Unscoped credential is out-of-scope for delegation entirely.
	not update.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p1", "delegated_project_id": "p1"}, "existing": {"credential": {"user_id": "u1", "project_id": null}}, "target": {"credential": {}}}

	# Patch tries to move the credential out of the delegation's own project.
	not update.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p1", "delegated_project_id": "p1"}, "existing": {"credential": {"user_id": "u1", "project_id": "p1"}}, "target": {"credential": {"project_id": "p2"}}}

	# Scope-drift tripwire: token scope diverges from the delegation's project.
	not update.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p2", "delegated_project_id": "p1"}, "existing": {"credential": {"user_id": "u1", "project_id": "p1"}}, "target": {"credential": {}}}
}
