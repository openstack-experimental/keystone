package test_policy_update

import data.identity.policy.update

test_allowed if {
	update.allow with input as {"credentials": {"roles": ["admin"]}}
	update.allow with input as {"credentials": {"is_admin": true}}
}

test_forbidden if {
	not update.allow with input as {"credentials": {"roles": []}}
	not update.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	not update.allow with input as {"credentials": {"roles": ["member"]}}
	not update.allow with input as {"credentials": {"roles": ["manager"]}}
}

test_target_content_does_not_grant if {
	not update.allow with input as {
		"credentials": {"roles": ["member"]},
		"target": {"policy": {"id": "pid", "type": "text/plain"}},
		"existing": {"policy": {"id": "pid", "type": "application/json"}},
	}
}
