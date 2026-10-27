package test_group_user_remove

import data.identity.group.user.remove

test_allowed if {
	remove.allow with input as {"credentials": {"roles": ["admin"]}}
	remove.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"group": {"domain_id": "foo"}, "user": {"domain_id": "foo"}}}
}

test_forbidden if {
	not remove.allow with input as {"credentials": {"roles": []}}
	not remove.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"group": {"domain_id": "foo"}, "user": {"domain_id": "foo1"}}}
	not remove.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"group": {"domain_id": "foo1"}, "user": {"domain_id": "foo"}}}
	not remove.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"group": {"domain_id": "foo"}, "user": null}}
	not remove.allow with input as {"credentials": {"roles": ["manager"]}, "existing": {"group": {"domain_id": "foo"}, "user": {"domain_id": "foo"}}}
}
