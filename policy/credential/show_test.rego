package test_credential_show

import data.identity.credential.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"credential": {"user_id": "other"}}}
	show.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "existing": {"credential": {"user_id": "u1"}}}
	show.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}, "existing": {"credential": {"user_id": "other"}}}
}

test_forbidden if {
	not show.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "existing": {"credential": {"user_id": "other"}}}
	not show.allow with input as {"credentials": {"roles": []}, "existing": {"credential": {"user_id": "u1"}}}
}
