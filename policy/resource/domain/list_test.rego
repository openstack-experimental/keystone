package test_domain_list

import data.identity.resource.domain.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
}

test_not_allowed if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["manager"]}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}}
}
