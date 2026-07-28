package test_policy_list

import data.identity.policy.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"is_admin": true}}
	list.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["reader"]}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "system": "domain"}}
	not list.allow with input as {"credentials": {"roles": ["member"]}}
	not list.allow with input as {"credentials": {"roles": ["manager"]}}
}

# The decision must not depend on the target document at all: a caller who is
# not admin/system-reader stays denied whatever the query carries.
test_target_content_does_not_grant if {
	not list.allow with input as {
		"credentials": {"roles": ["member"]},
		"target": {"policy": {"id": null, "type": "application/json"}},
	}
}
