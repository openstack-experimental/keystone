package test_system_user_role_revoke

import data.identity.system.user.role.revoke

test_allowed if {
	revoke.allow with input as {"credentials": {"roles": ["admin"]}}
	revoke.allow with input as {"credentials": {"roles": ["manager"], "system": "all"}}
}

test_forbidden if {
	not revoke.allow with input as {"credentials": {"roles": []}}
	not revoke.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	not revoke.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}}
	not revoke.allow with input as {"credentials": {"roles": ["member"], "system": "all"}}
}
