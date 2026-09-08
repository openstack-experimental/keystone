package test_domain_config_update

import data.identity.domain_config.update

test_admin_allowed if {
	update.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	update.allow with input as {"credentials": {"roles": ["admin"], "is_admin": true}}
}

test_domain_manager_allowed if {
	update.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d1"},
	}
	update.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d1", "group": "identity"},
	}
}

# ADR 0034 §6: the `assignment` group is cloud-admin only — not satisfiable by
# a domain- or project-scoped token, whatever role it carries.
test_domain_manager_denied_the_assignment_group if {
	not update.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d1", "group": "assignment"},
	}
	not update.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d1", "group": "assignment", "option": "driver"},
	}
	not update.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d1", "config": {"assignment": {"driver": "openfga"}}},
	}
}

# A non-system `admin` (domain- or project-scoped) is refused the `assignment`
# group but keeps every other group.
test_non_system_admin_denied_the_assignment_group if {
	not update.allow with input as {
		"credentials": {"roles": ["admin"], "domain_id": "d1"},
		"target": {"domain_id": "d1", "group": "assignment"},
	}
	not update.allow with input as {
		"credentials": {"roles": ["admin"]},
		"target": {"domain_id": "d1", "config": {"assignment": {"driver": "openfga"}}},
	}
	update.allow with input as {
		"credentials": {"roles": ["admin"]},
		"target": {"domain_id": "d1", "group": "identity"},
	}
}

test_admin_allowed_the_assignment_group if {
	# configured admin SVID
	update.allow with input as {
		"credentials": {"roles": [], "is_admin": true},
		"target": {"domain_id": "d1", "config": {"assignment": {"driver": "openfga"}}},
	}
	# system-scoped `admin`
	update.allow with input as {
		"credentials": {"roles": ["admin"], "system": "all"},
		"target": {"domain_id": "d1", "group": "assignment"},
	}
	update.allow with input as {
		"credentials": {"roles": ["admin"], "system": "all"},
		"target": {"domain_id": "d1", "config": {"assignment": {"driver": "openfga"}}},
	}
}

test_forbidden if {
	not update.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	not update.allow with input as {
		"credentials": {"roles": ["manager"], "domain_id": "d1"},
		"target": {"domain_id": "d2"},
	}
	not update.allow with input as {"credentials": {"roles": []}}
}
