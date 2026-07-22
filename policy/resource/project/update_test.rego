package test_project_update

import data.identity.resource.project.update

test_admin_allowed if {
	update.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	update.allow with input as {"credentials": {"roles": ["admin"]}}
}

test_manager_in_domain_scope_allowed if {
	update.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "domain1"},
		"existing": {"project": {"domain_id": "domain1"}},
	}
}

test_manager_outside_domain_scope_forbidden if {
	not update.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "domain1"},
		"existing": {"project": {"domain_id": "domain2"}},
	}
}

test_non_admin_forbidden if {
	not update.allow with input as {"credentials": {"roles": []}}
	not update.allow with input as {"credentials": {"roles": ["member"], "domain_id": "foo"}}
}
