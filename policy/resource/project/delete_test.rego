package test_project_delete

import data.identity.resource.project.delete

test_allowed if {
	delete.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	delete.allow with input as {"credentials": {"roles": ["admin"], "is_admin": true}}
	delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"project": {"domain_id": "foo"}}}
}

test_not_allowed if {
	not delete.allow with input as {"credentials": {"roles": []}}
	not delete.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}}
}
