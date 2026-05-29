package test_group_list

import data.identity.group.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	list.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"group": {"domain_id": "foo"}}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"group": {"domain_id": "foo1"}}}
	not list.allow with input as {"credentials": {"roles": ["manager"]}, "target": {"group": {"domain_id": "foo"}}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"group": {"domain_id": "foo2"}}}
}
