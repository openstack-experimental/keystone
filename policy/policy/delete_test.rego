package test_policy_delete

import data.identity.policy.delete

test_allowed if {
	delete.allow with input as {"credentials": {"roles": ["admin"]}}
	delete.allow with input as {"credentials": {"is_admin": true}}
}

test_forbidden if {
	not delete.allow with input as {"credentials": {"roles": []}}
	not delete.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	not delete.allow with input as {"credentials": {"roles": ["member"]}}
	not delete.allow with input as {"credentials": {"roles": ["manager"]}}
}

test_existing_content_does_not_grant if {
	not delete.allow with input as {
		"credentials": {"roles": ["member"]},
		"existing": {"policy": {"id": "pid", "type": "application/json"}},
	}
}
