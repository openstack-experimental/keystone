package test_project_create

import data.identity.project.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": ["admin"]}}
	create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}}}
}

test_forbidden if {
	not create.allow with input as {"credentials": {"roles": []}}
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo1"}}}
	not create.allow with input as {"credentials": {"roles": ["manager"]}, "target": {"project": {"domain_id": "foo"}}}
}
