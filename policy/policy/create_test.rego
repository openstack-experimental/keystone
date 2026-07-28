package test_policy_create

import data.identity.policy.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": ["admin"]}}
	create.allow with input as {"credentials": {"is_admin": true}}
}

# Admin-only: unlike show/list there is no system-reader path
# (python keystone uses RULE_ADMIN_REQUIRED here).
test_forbidden if {
	not create.allow with input as {"credentials": {"roles": []}}
	not create.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	not create.allow with input as {"credentials": {"roles": ["member"]}}
	not create.allow with input as {"credentials": {"roles": ["manager"]}}
}

test_target_content_does_not_grant if {
	not create.allow with input as {
		"credentials": {"roles": ["member"]},
		"target": {"policy": {"id": null, "type": "application/json"}},
	}
}
