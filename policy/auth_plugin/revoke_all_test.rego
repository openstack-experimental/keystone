package test_auth_plugin_revoke_all

import data.identity.auth_plugin.revoke_all

test_allowed_admin if {
	revoke_all.allow with input as {"credentials": {"is_admin": true}}
	revoke_all.allow with input as {"credentials": {"roles": ["admin"], "system": "all"}}
}

test_forbidden if {
	not revoke_all.allow with input as {"credentials": {"roles": ["member"]}}
	not revoke_all.allow with input as {"credentials": {"roles": ["manager"]}}
	not revoke_all.allow with input as {"credentials": {"roles": ["admin"], "project_id": "proj_x"}}
}

test_violations if {
	revoke_all.violation with input as {"credentials": {"roles": ["member"]}}
}

test_no_violations_admin if {
	v := revoke_all.violation with input as {"credentials": {"is_admin": true}}
	count(v) == 0
}
