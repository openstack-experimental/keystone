package test_group_user_add

import data.identity.group.user.add

test_allowed if {
	add.allow with input as {"credentials": {"roles": ["admin"]}}
	add.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"group": {"domain_id": "foo"}, "user": {"domain_id": "foo"}}}
}

test_forbidden if {
	not add.allow with input as {"credentials": {"roles": []}}
	not add.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"group": {"domain_id": "foo"}, "user": {"domain_id": "foo1"}}}
	not add.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"group": {"domain_id": "foo1"}, "user": {"domain_id": "foo"}}}
	not add.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"group": {"domain_id": "foo"}, "user": null}}
	not add.allow with input as {"credentials": {"roles": ["manager"]}, "existing": {"group": {"domain_id": "foo"}, "user": {"domain_id": "foo"}}}
}
