package test_auth_plugin_identity_link_create

import data.identity.auth_plugin.identity_link.create

test_allowed_system_admin if {
	create.allow with input as {"credentials": {"roles": ["admin"], "system": "all"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "other", "is_system": true}}}
	create.allow with input as {"credentials": {"roles": ["admin"], "system": "all"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d1", "is_system": false}}}
}

test_allowed_domain_admin if {
	create.allow with input as {"credentials": {"roles": ["admin"], "domain_id": "d1"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d1", "is_system": false}}}
}

test_allowed_domain_manager if {
	create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d1", "is_system": false}}}
}

test_forbidden_system_target if {
	not create.allow with input as {"credentials": {"roles": ["admin"], "domain_id": "d1"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d1", "is_system": true}}}
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d1", "is_system": true}}}
}

test_forbidden_foreign_domain if {
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d2", "is_system": false}}}
}

test_forbidden_reader if {
	not create.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "d1"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d1", "is_system": false}}}
}

test_forbidden_no_role if {
	not create.allow with input as {"credentials": {"roles": []}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d1", "is_system": false}}}
}

test_violation_system_target if {
	create.violation with input as {"credentials": {"roles": ["admin"], "domain_id": "d1"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d1", "is_system": true}}}
}

test_violation_foreign_domain if {
	create.violation with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d2", "is_system": false}}}
}

test_no_violation_system_admin if {
	v := create.violation with input as {"credentials": {"roles": ["admin"], "system": "all"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d2", "is_system": true}}}
	count(v) == 0
}
