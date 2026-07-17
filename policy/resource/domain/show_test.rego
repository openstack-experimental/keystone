package test_domain_show

import data.identity.resource.domain.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	show.allow with input as {"credentials": {"roles": ["admin"], "is_admin": true}}
	show.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
}

test_not_allowed if {
	show.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"domain": {"id": "foo"}}}
	not show.allow with input as {"credentials": {"roles": []}}
	not show.allow with input as {"credentials": {"roles": ["manager"]}}
	not show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}}
}

# A project-scoped caller (no admin/reader/manager role) can view the domain
# their own project belongs to, but not an unrelated one.
test_own_project_domain if {
	show.allow with input as {"credentials": {"roles": [], "project_domain_id": "foo"}, "existing": {"domain": {"id": "foo"}}}
	not show.allow with input as {"credentials": {"roles": [], "project_domain_id": "foo"}, "existing": {"domain": {"id": "bar"}}}
	not show.allow with input as {"credentials": {"roles": []}, "existing": {"domain": {"id": "foo"}}}
}
