package test_scim_realm_purge

import data.identity.scim_realm.purge

test_allowed if {
	purge.allow with input as {"credentials": {"roles": ["admin"]}}
	purge.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	purge.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"scim_realm": {"domain_id": "foo"}}}
}

test_forbidden if {
	not purge.allow with input as {"credentials": {"roles": []}}
	not purge.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "existing": {"scim_realm": {"domain_id": "foo1"}}}
	not purge.allow with input as {"credentials": {"roles": ["manager"]}, "existing": {"scim_realm": {"domain_id": "foo"}}}
	not purge.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "existing": {"scim_realm": {"domain_id": "foo2"}}}
}
