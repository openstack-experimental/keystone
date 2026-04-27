package test_group_delete

import data.identity.group.delete

test_allowed if {
	delete.allow with input as {"credentials": {"roles": ["admin"]}}
	delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain_id": "foo"}}
}

test_forbidden if {
	not delete.allow with input as {"credentials": {"roles": []}}
	not delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain_id": "foo1"}}
	not delete.allow with input as {"credentials": {"roles": ["manager"]}, "target": {"domain_id": "foo"}}
	not delete.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"domain_id": "foo"}}
}
