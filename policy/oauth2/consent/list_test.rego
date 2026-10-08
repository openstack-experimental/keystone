package test_oauth2_consent_list

import data.identity.oauth2.consent.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"user_id": "other"}}
	list.allow with input as {"credentials": {"roles": [], "is_admin": true}, "target": {"user_id": "other"}}
	list.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "target": {"user_id": "u1"}}
	list.allow with input as {"credentials": {"roles": [], "user_id": "u1", "is_delegated": false}, "target": {"user_id": "u1"}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "target": {"user_id": "other"}}
	not list.allow with input as {"credentials": {"roles": []}, "target": {"user_id": "u1"}}
	not list.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true}, "target": {"user_id": "u1"}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "user_id": "u1", "system": "all"}, "target": {"user_id": "other"}}
	# Scope drift: delegated project differs from the token project.
	not list.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "project_id": "p1", "delegated_project_id": "p2", "is_delegated": true}, "target": {"user_id": "u1"}}
}
