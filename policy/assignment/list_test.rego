package test_assignment_list

import data.identity.assignment.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"roles": ["reader"], "system_scope": "all"}}
	list.allow with input as {
		"credentials": {"roles": ["admin"], "domain_id": "domain_a"},
		"target": {"domain_id": "domain_b"},
	}

	list.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "domain_a"},
		"target": {"domain_id": "domain_a"},
	}

	list.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "domain_a"},
		"target": {
			"domain_id": "domain_a",
			"project": {"domain_id": "domain_a"},
		},
	}
}

test_forbidden if {
	not list.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "domain_a"},
		"target": {"domain_id": "domain_b"},
	}

	not list.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "domain_a"},
		"target": {},
	}
}
