package test_role_imply_rule_create

import data.identity.role.imply_rule.create

test_allowed if {
	create.allow with input as {
		"credentials": {"roles": ["admin"]},
		"target": {"role_imply_rule": {"prior_role": {"id": "r1"}, "implied_role": {"id": "r2"}}},
	}
}

test_allowed_with_is_admin if {
	create.allow with input as {
		"credentials": {"roles": [], "is_admin": true},
		"target": {"role_imply_rule": {"prior_role": {"id": "r1"}, "implied_role": {"id": "r2"}}},
	}
}

test_forbidden if {
	not create.allow with input as {
		"credentials": {"roles": []},
		"target": {"role_imply_rule": {"prior_role": {"id": "r1"}, "implied_role": {"id": "r2"}}},
	}
	not create.allow with input as {
		"credentials": {"roles": ["reader"]},
		"target": {"role_imply_rule": {"prior_role": {"id": "r1"}, "implied_role": {"id": "r2"}}},
	}
	not create.allow with input as {
		"credentials": {"roles": ["reader"], "system": "all"},
		"target": {"role_imply_rule": {"prior_role": {"id": "r1"}, "implied_role": {"id": "r2"}}},
	}
}
