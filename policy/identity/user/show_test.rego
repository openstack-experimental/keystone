package test_user_show

import data.identity.user.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}}
	show.allow with input as {"credentials": {"roles": ["manager", "reader"], "domain_id": "foo"}, "target": {"domain_id": "foo"}}
}

test_forbidden if {
	not show.allow with input as {"credentials": {"roles": []}}
	not show.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain_id": "foo1"}}
	not show.allow with input as {"credentials": {"roles": ["manager"]}, "target": {"domain_id": "foo"}}
	not show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"domain_id": "foo2"}}
}
