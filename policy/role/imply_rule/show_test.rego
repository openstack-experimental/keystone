package test_role_imply_rule_show

import data.identity.role.imply_rule.show

test_allowed_if_admin if {
	show.allow with input as {
		"credentials": {"roles": ["admin"]},
		"existing": {"role_imply_rule": {"id": "r1", "implies_role_id": "r2"}}
	}
}

test_allowed_with_is_admin if {
	show.allow with input as {
		"credentials": {"roles": [], "is_admin": true},
		"existing": {"role_imply_rule": {"id": "r1", "implies_role_id": "r2"}}
	}
}

test_allowed_with_reader_system_all if {
	show.allow with input as {
		"credentials": {"roles": ["reader"], "system": "all"},
		"existing": {"role_imply_rule": {"id": "r1", "implies_role_id": "r2"}}
	}
}

test_forbidden if {
	not show.allow with input as {
		"credentials": {"roles": []},
		"existing": {"role_imply_rule": {"id": "r1", "implies_role_id": "r2"}}
	}
	not show.allow with input as {
		"credentials": {"roles": ["reader"]},
		"existing": {"role_imply_rule": {"id": "r1", "implies_role_id": "r2"}}
	}
	not show.allow with input as {
		"credentials": {"roles": ["reader"], "system": "foo"},
		"existing": {"role_imply_rule": {"id": "r1", "implies_role_id": "r2"}}
	}
}