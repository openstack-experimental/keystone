package test_domain_user_role_check

import data.identity.domain.user.role.check

test_allowed if {
	check.allow with input as {"credentials": {"roles": ["admin"]}}
	check.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	check.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "user": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
	check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "user": {"domain_id": "foo"}, "role": {"domain_id": null}}}
}

test_forbidden if {
	not check.allow with input as {"credentials": {"roles": []}}
	not check.allow with input as {"credentials": {"roles": ["reader"], "system": "foo"}}
	not check.allow with input as {"credentials": {"roles": ["member"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "user": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
	not check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"domain": {"id": "foo1"}, "user": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
	not check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "user": {"domain_id": "foo1"}, "role": {"domain_id": "foo"}}}
	not check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "user": {"domain_id": "foo"}, "role": {"domain_id": "foo1"}}}
}
