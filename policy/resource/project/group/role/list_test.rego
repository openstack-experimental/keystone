package test_project_group_role_list

import data.identity.project.group.role.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	list.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}, "group": {"domain_id": "foo"}}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "system": "foo"}}
	not list.allow with input as {"credentials": {"roles": ["member"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}, "group": {"domain_id": "foo"}}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo1"}, "group": {"domain_id": "foo"}}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}, "group": {"domain_id": "foo1"}}}
}
