package test_auth_plugin_identity_link_delete

import data.identity.auth_plugin.identity_link.delete

test_allowed_system_admin if {
	delete.allow with input as {"credentials": {"roles": ["admin"], "system": "all"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "other", "is_system": true}}}
	delete.allow with input as {"credentials": {"roles": ["admin"], "system": "all"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d1", "is_system": false}}}
}

test_allowed_domain_admin if {
	delete.allow with input as {"credentials": {"roles": ["admin"], "domain_id": "d1"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d1", "is_system": false}}}
}

test_allowed_domain_manager if {
	delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d1", "is_system": false}}}
}

test_forbidden_system_target if {
	not delete.allow with input as {"credentials": {"roles": ["admin"], "domain_id": "d1"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d1", "is_system": true}}}
	not delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d1", "is_system": true}}}
}

test_forbidden_foreign_domain if {
	not delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d2", "is_system": false}}}
}

test_forbidden_reader if {
	not delete.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "d1"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d1", "is_system": false}}}
}

test_violation_system_target if {
	delete.violation with input as {"credentials": {"roles": ["admin"], "domain_id": "d1"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d1", "is_system": true}}}
}

test_violation_foreign_domain if {
	delete.violation with input as {"credentials": {"roles": ["manager"], "domain_id": "d1"}, "target": {"identity_link": {"plugin_name": "p", "user_id": "u", "domain_id": "d2", "is_system": false}}}
}
