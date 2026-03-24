package test_project_user_role_list

import data.identity.project.user.role.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"roles": ["reader"], "scope": "system"}}
	list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo"}, "project": {"domain_id": "foo"}, "role": {"domain_id": null}}}
	list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo"}, "project": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["member"]}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "bar"}, "project": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo"}, "project": {"domain_id": "bar"}, "role": {"domain_id": "foo"}}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "bar"}, "project": {"domain_id": "bar"}, "role": {"domain_id": "bar"}}}
}
