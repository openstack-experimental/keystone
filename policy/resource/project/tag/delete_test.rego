package test_project_tag_delete

import data.identity.resource.project.tag.delete

test_admin_allowed if {
	delete.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	delete.allow with input as {"credentials": {"roles": ["admin"]}}
}

test_manager_in_domain_scope_allowed if {
	delete.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "domain1"},
		"existing": {"project": {"domain_id": "domain1"}},
	}
}

test_manager_outside_domain_scope_forbidden if {
	not delete.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "domain1"},
		"existing": {"project": {"domain_id": "domain2"}},
	}
}

test_non_manager_forbidden if {
	not delete.allow with input as {"credentials": {"roles": []}}
	not delete.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}}
}
