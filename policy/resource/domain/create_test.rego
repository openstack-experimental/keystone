package test_domain_create

import data.identity.resource.domain.create

test_admin_allowed if {
	create.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	create.allow with input as {"credentials": {"roles": ["admin"], "is_admin": true}}
}

test_non_admin_forbidden if {
	not create.allow with input as {"credentials": {"roles": []}}
	not create.allow with input as {"credentials": {"roles": ["reader"]}}
	not create.allow with input as {"credentials": {"roles": ["manager"]}}
}
