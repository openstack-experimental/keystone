package test_scim_user_delete

import data.identity.scim.user.delete

test_allowed if {
	delete.allow with input as {"credentials": {"roles": ["admin"]}}
	delete.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	delete.allow with input as {"credentials": {"roles": ["scim_provisioner"], "domain_id": "foo"}, "existing": {"user": {"domain_id": "foo"}}}
}

test_forbidden if {
	not delete.allow with input as {"credentials": {"roles": []}}
	not delete.allow with input as {"credentials": {"roles": ["scim_provisioner"], "domain_id": "foo"}, "existing": {"user": {"domain_id": "foo1"}}}
	not delete.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"user": {"domain_id": "foo"}}}
}
