package test_project_list

import data.identity.resource.project.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	list.allow with input as {"credentials": {"roles": ["admin"], "is_admin": true}}
	list.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}}}
}

test_not_allowed if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["manager"]}}
	not list.allow with input as {"credentials": {"roles": ["manager", "reader"], "domain_id": "foo"}, "target": {"project": {"domain_id": "bar"}}}
}
