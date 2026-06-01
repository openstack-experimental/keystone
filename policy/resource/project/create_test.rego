package test_project_create

import data.identity.resource.project.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	create.allow with input as {"credentials": {"roles": ["admin"], "is_admin": true}}
	create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}}}
}

test_not_allowed if {
	not create.allow with input as {"credentials": {"roles": []}}
	not create.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}}
}
