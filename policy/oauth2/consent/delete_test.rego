package test_oauth2_consent_delete

import data.identity.oauth2.consent.delete

test_allowed if {
	delete.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"user_id": "other", "client_id": "c"}}
	delete.allow with input as {"credentials": {"roles": [], "is_admin": true}, "target": {"user_id": "other", "client_id": "c"}}
	delete.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "target": {"user_id": "u1", "client_id": "c"}}
}

test_forbidden if {
	not delete.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "target": {"user_id": "other", "client_id": "c"}}
	not delete.allow with input as {"credentials": {"roles": []}, "target": {"user_id": "u1", "client_id": "c"}}
	not delete.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true}, "target": {"user_id": "u1", "client_id": "c"}}
	# Scope drift: delegated project differs from the token project.
	not delete.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "project_id": "p1", "delegated_project_id": "p2", "is_delegated": true}, "target": {"user_id": "u1", "client_id": "c"}}
}
