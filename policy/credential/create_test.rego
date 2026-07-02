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
