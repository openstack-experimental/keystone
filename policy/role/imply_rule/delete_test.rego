package test_role_imply_rule_delete

import data.identity.role.imply_rule.delete

test_allowed if {
	delete.allow with input as {
		"credentials": {"roles": ["admin"]},
		"existing": {"role_imply_rule": {"prior_role": {"id": "r1"}, "implied_role": {"id": "r2"}}}
	}
}

test_allowed_with_is_admin if {
	delete.allow with input as {
		"credentials": {"roles": [], "is_admin": true},
		"existing": {"role_imply_rule": {"prior_role": {"id": "r1"}, "implied_role": {"id": "r2"}}}
	}
}

test_forbidden if {
	not delete.allow with input as {
		"credentials": {"roles": []},
		"existing": {"role_imply_rule": {"prior_role": {"id": "r1"}, "implied_role": {"id": "r2"}}}
	}
	not delete.allow with input as {
		"credentials": {"roles": ["reader"]},
		"existing": {"role_imply_rule": {"prior_role": {"id": "r1"}, "implied_role": {"id": "r2"}}}
	}
	not delete.allow with input as {
		"credentials": {"roles": ["reader"], "system": "all"},
		"existing": {"role_imply_rule": {"prior_role": {"id": "r1"}, "implied_role": {"id": "r2"}}}
	}
}