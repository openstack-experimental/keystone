package test_vendordata_create

import data.identity.vendordata.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": ["service"]}}
	create.allow with input as {"credentials": {"roles": [], "is_admin": true}}
}

test_forbidden if {
	not create.allow with input as {"credentials": {"roles": []}}
	not create.allow with input as {"credentials": {"roles": ["reader"]}}
	not create.allow with input as {"credentials": {"roles": ["manager"]}}
}
