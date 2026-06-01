package test_project_show

import data.identity.resource.project.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	show.allow with input as {"credentials": {"roles": ["admin"]}}
	show.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"project": {"domain_id": "foo"}}}
}

test_not_allowed if {
	not show.allow with input as {"credentials": {"roles": []}}
	not show.allow with input as {"credentials": {"roles": ["manager"]}}
	not show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"project": {"domain_id": "bar"}}}
}
