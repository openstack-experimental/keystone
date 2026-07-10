package test_mapping_ruleset_show

import data.identity.mapping.ruleset.show

test_allowed_admin if {
	show.allow with input as {"credentials": {"roles": ["admin"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d2", "rules": []}}}
}

test_allowed_is_admin if {
	show.allow with input as {"credentials": {"is_admin": true}, "existing": {"mapping": {"domain_id": "d2", "rules": []}}}
}

test_allowed_reader_own if {
	show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d1", "rules": []}}}
}

test_allowed_reader_global if {
	show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": null, "rules": []}}}
}

test_forbidden_reader_foreign if {
	not show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d2", "rules": []}}}
}

test_forbidden_member if {
	not show.allow with input as {"credentials": {"roles": ["member"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d1", "rules": []}}}
}

test_violation_reader_foreign if {
	show.violation with input as {"credentials": {"roles": ["reader"], "domain_id": "d1"}, "existing": {"mapping": {"domain_id": "d2", "rules": []}}}
}
