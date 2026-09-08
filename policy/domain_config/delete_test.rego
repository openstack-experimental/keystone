package test_domain_config_delete

import data.identity.domain_config.delete

test_admin_allowed if {
	delete.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	delete.allow with input as {"credentials": {"roles": ["admin"], "is_admin": true}}
}

test_domain_manager_allowed if {
	delete.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d1"},
	}
	delete.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d1", "group": "identity"},
	}
}

# ADR 0034 §6: the `assignment` group is cloud-admin only — not satisfiable by
# a domain- or project-scoped token, whatever role it carries.
test_domain_manager_denied_the_assignment_group if {
	not delete.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d1", "group": "assignment"},
	}
	not delete.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d1", "group": "assignment", "option": "driver"},
	}
}

# A non-system `admin` is refused the `assignment` group but keeps every other
# group and the whole-config delete (which only reverts to the global driver).
test_non_system_admin_denied_the_assignment_group if {
	not delete.allow with input as {
		"credentials": {"roles": ["admin"], "domain_id": "d1"},
		"target": {"domain_id": "d1", "group": "assignment"},
	}
	not delete.allow with input as {
		"credentials": {"roles": ["admin"], "domain_id": "d1"},
		"target": {"domain_id": "d1", "group": "assignment", "option": "driver"},
	}
	delete.allow with input as {
		"credentials": {"roles": ["admin"]},
		"target": {"domain_id": "d1", "group": "identity"},
	}
	delete.allow with input as {
		"credentials": {"roles": ["admin"]},
		"target": {"domain_id": "d1"},
	}
}

test_admin_allowed_the_assignment_group if {
	# configured admin SVID
	delete.allow with input as {
		"credentials": {"roles": [], "is_admin": true},
		"target": {"domain_id": "d1", "group": "assignment"},
	}
	# system-scoped `admin`
	delete.allow with input as {
		"credentials": {"roles": ["admin"], "system": "all"},
		"target": {"domain_id": "d1", "group": "assignment"},
	}
}

test_forbidden if {
	not delete.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	not delete.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d2"},
	}
	not delete.allow with input as {"credentials": {"roles": []}}
}
