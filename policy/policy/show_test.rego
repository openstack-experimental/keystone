package test_policy_show

import data.identity.policy.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}}
	show.allow with input as {"credentials": {"is_admin": true}}
	show.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
}

test_forbidden if {
	not show.allow with input as {"credentials": {"roles": []}}
	not show.allow with input as {"credentials": {"roles": ["reader"]}}
	not show.allow with input as {"credentials": {"roles": ["reader"], "system": "domain"}}
	not show.allow with input as {"credentials": {"roles": ["member"]}}
}

# Used per-item by the list handler (security model I8): a member must not be
# able to read a stored policy just because it exists.
test_existing_content_does_not_grant if {
	not show.allow with input as {
		"credentials": {"roles": ["member"]},
		"existing": {"policy": {"id": "pid", "type": "application/json"}},
	}
}
