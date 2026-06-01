package test_domain_delete

import data.identity.resource.domain.delete

test_admin_allowed if {
	delete.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	delete.allow with input as {"credentials": {"roles": ["admin"]}}
}

test_non_admin_forbidden if {
	not delete.allow with input as {"credentials": {"roles": []}}
	not delete.allow with input as {"credentials": {"roles": ["member"], "domain_id": "foo"}}
}
