package test_mapping_ruleset_list

import data.identity.mapping.ruleset.list

test_allowed_admin if {
	list.allow with input as {"credentials": {"roles": ["admin"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d2"}}}
	list.can_see_other_domain_resources with input as {"credentials": {"roles": ["admin"]}}
}

test_allowed_is_admin if {
	list.allow with input as {"credentials": {"is_admin": true}, "target": {"mapping": {"domain_id": "d2"}}}
	list.can_see_other_domain_resources with input as {"credentials": {"is_admin": true}}
}

test_allowed_reader_own if {
	list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d1"}}}
}

test_allowed_reader_global if {
	list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": null}}}
}

test_forbidden_reader_foreign if {
	not list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d2"}}}
}

test_forbidden_member if {
	not list.allow with input as {"credentials": {"roles": ["member"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d1"}}}
}

test_violation_reader_foreign if {
	list.violation with input as {"credentials": {"roles": ["reader"], "domain_id": "d1"}, "target": {"mapping": {"domain_id": "d2"}}}
}
