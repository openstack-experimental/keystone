package test_credential_list

import data.identity.credential.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"roles": ["member"]}, "target": {"credential": {"user_id": "u1"}}}
	list.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["reader"]}}
}
