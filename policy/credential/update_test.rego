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
