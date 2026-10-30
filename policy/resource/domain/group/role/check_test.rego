package test_domain_group_role_check

import data.identity.domain.group.role.check

test_allowed if {
	check.allow with input as {"credentials": {"roles": ["admin"]}}
	check.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	check.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
	check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": null}}}
}

test_forbidden if {
	not check.allow with input as {"credentials": {"roles": []}}
	not check.allow with input as {"credentials": {"roles": ["reader"], "system": "foo"}}
	not check.allow with input as {"credentials": {"roles": ["member"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
	not check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"domain": {"id": "foo1"}, "group": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
	not check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "group": {"domain_id": "foo1"}, "role": {"domain_id": "foo"}}}
	not check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": "foo1"}}}
}
