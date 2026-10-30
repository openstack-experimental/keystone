package test_project_tag_list

import data.identity.resource.project.tag.list

test_admin_allowed if {
	list.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	list.allow with input as {"credentials": {"roles": ["admin"]}}
}

test_reader_system_scope_allowed if {
	list.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
}

test_reader_in_domain_scope_allowed if {
	list.allow with input as {
		"credentials": {"roles": ["reader"], "domain_id": "domain1"},
		"existing": {"project": {"domain_id": "domain1"}},
	}
}

test_reader_outside_domain_scope_forbidden if {
	not list.allow with input as {
		"credentials": {"roles": ["reader"], "domain_id": "domain1"},
		"existing": {"project": {"domain_id": "domain2"}},
	}
}

test_non_reader_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["member"], "domain_id": "foo"}}
}

test_own_project_allowed if {
	list.allow with input as {
		"credentials": {"roles": ["member"], "project_id": "p1"},
		"existing": {"project": {"id": "p1", "domain_id": "domain1"}},
	}
}

test_other_project_forbidden if {
	not list.allow with input as {
		"credentials": {"roles": ["member"], "project_id": "p2"},
		"existing": {"project": {"id": "p1", "domain_id": "domain1"}},
	}
}

test_delegated_own_project_allowed if {
	list.allow with input as {
		"credentials": {
			"roles": ["member"], "project_id": "p1", "is_delegated": true,
			"delegated_project_id": "p1",
		},
		"existing": {"project": {"id": "p1", "domain_id": "domain1"}},
	}
}

test_delegated_scope_drift_forbidden if {
	not list.allow with input as {
		"credentials": {
			"roles": ["member"], "project_id": "p1", "is_delegated": true,
			"delegated_project_id": "p2",
		},
		"existing": {"project": {"id": "p1", "domain_id": "domain1"}},
	}
}
