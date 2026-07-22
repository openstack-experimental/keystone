package test_group_update

import data.identity.group.update

test_allowed if {
	update.allow with input as {"credentials": {"roles": ["admin"]}}
	update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"group": {"domain_id": "foo"}}}
}

test_forbidden if {
	not update.allow with input as {"credentials": {"roles": []}}
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"group": {"domain_id": "foo1"}}}
	not update.allow with input as {"credentials": {"roles": ["manager"]}, "existing": {"group": {"domain_id": "foo"}}}
	not update.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"group": {"domain_id": "foo"}}}
}
