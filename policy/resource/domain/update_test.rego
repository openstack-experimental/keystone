package test_domain_update

import data.identity.resource.domain.update

test_admin_allowed if {
	update.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	update.allow with input as {"credentials": {"roles": ["admin"]}}
}

test_non_admin_forbidden if {
	not update.allow with input as {"credentials": {"roles": []}}
	not update.allow with input as {"credentials": {"roles": ["member"], "domain_id": "foo"}}
}
