package test_project_user_role_check

import data.identity.project.user.role.check

test_allowed if {
	check.allow with input as {"credentials": {"roles": ["admin"]}}
	check.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo"}, "project": {"domain_id": "foo"}, "role": {"domain_id": null}}}
	check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo"}, "project": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
}

test_forbidden if {
	not check.allow with input as {"credentials": {"roles": []}}
	not check.allow with input as {"credentials": {"roles": ["reader"], "system": "foo"}}
	not check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo1"}, "project": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
	not check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo1"}, "project": {"domain_id": "foo1"}, "role": {"domain_id": "foo1"}}}
	not check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo"}, "project": {"domain_id": "foo1"}, "role": {"domain_id": "foo1"}}}
	not check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo1"}, "project": {"domain_id": "foo1"}, "role": {"domain_id": "foo1"}}}
	not check.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
}
