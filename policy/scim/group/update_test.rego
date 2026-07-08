package test_scim_group_update

import data.identity.scim.group.update

test_allowed if {
	update.allow with input as {"credentials": {"roles": ["admin"]}}
	update.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	update.allow with input as {"credentials": {"roles": ["scim_provisioner"], "domain_id": "foo"}, "existing": {"group": {"domain_id": "foo"}}}
}

test_forbidden if {
	not update.allow with input as {"credentials": {"roles": []}}
	not update.allow with input as {"credentials": {"roles": ["scim_provisioner"], "domain_id": "foo"}, "existing": {"group": {"domain_id": "foo1"}}}
	not update.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"group": {"domain_id": "foo"}}}
}
