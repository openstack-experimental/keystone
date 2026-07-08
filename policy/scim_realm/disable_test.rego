package test_scim_realm_disable

import data.identity.scim_realm.disable

test_allowed if {
	disable.allow with input as {"credentials": {"roles": ["admin"]}}
	disable.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	disable.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"scim_realm": {"domain_id": "foo"}}}
}

test_forbidden if {
	not disable.allow with input as {"credentials": {"roles": []}}
	not disable.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"scim_realm": {"domain_id": "foo1"}}}
	not disable.allow with input as {"credentials": {"roles": ["manager"]}, "existing": {"scim_realm": {"domain_id": "foo"}}}
	not disable.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"scim_realm": {"domain_id": "foo2"}}}
}
