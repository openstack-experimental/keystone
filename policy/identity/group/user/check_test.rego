package test_group_user_check

import data.identity.group.user.check

test_allowed if {
	check.allow with input as {"credentials": {"roles": ["admin"]}}
	check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"group": {"domain_id": "foo"}, "user": {"domain_id": "foo"}}}
}

test_forbidden if {
	not check.allow with input as {"credentials": {"roles": []}}
	not check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"group": {"domain_id": "foo"}, "user": {"domain_id": "foo1"}}}
	not check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"group": {"domain_id": "foo1"}, "user": {"domain_id": "foo"}}}
	not check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"group": {"domain_id": "foo"}, "user": null}}
	not check.allow with input as {"credentials": {"roles": ["reader"]}, "existing": {"group": {"domain_id": "foo"}, "user": {"domain_id": "foo"}}}
}
