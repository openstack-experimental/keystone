package test_domain_config_get_default

import data.identity.domain_config.get_default

test_authenticated_roles_allowed if {
	get_default.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	get_default.allow with input as {"credentials": {"roles": ["admin"]}}
	get_default.allow with input as {"credentials": {"roles": ["reader"]}}
	get_default.allow with input as {"credentials": {"roles": ["manager"]}}
}

test_no_role_forbidden if {
	not get_default.allow with input as {"credentials": {"roles": []}}
	not get_default.allow with input as {"credentials": {"roles": ["member"]}}
}
