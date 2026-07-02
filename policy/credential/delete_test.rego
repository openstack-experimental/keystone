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
