package test_scim_user_show

import data.identity.scim.user.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}}
	show.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	show.allow with input as {"credentials": {"roles": ["scim_provisioner"], "domain_id": "foo"}, "existing": {"user": {"domain_id": "foo"}}}
}

test_forbidden if {
	not show.allow with input as {"credentials": {"roles": []}}
	not show.allow with input as {"credentials": {"roles": ["scim_provisioner"], "domain_id": "foo"}, "existing": {"user": {"domain_id": "foo1"}}}
	not show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"user": {"domain_id": "foo"}}}
}
