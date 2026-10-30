package test_domain_group_role_revoke

import data.identity.domain.group.role.revoke

test_allowed if {
	revoke.allow with input as {"credentials": {"roles": ["admin"]}}
	revoke.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	revoke.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": null, "name": "member"}}}
	revoke.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": "foo", "name": "member"}}}
	revoke.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": null, "name": "reader"}}}
	revoke.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": null, "name": "manager"}}}
}

test_forbidden if {
	not revoke.allow with input as {"credentials": {"roles": []}}
	not revoke.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	not revoke.allow with input as {"credentials": {"roles": ["member"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": "foo", "name": "member"}}}
	not revoke.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo1"}, "group": {"domain_id": "foo"}, "role": {"domain_id": "foo", "name": "member"}}}
	not revoke.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "group": {"domain_id": "foo1"}, "role": {"domain_id": "foo", "name": "member"}}}
	not revoke.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": "foo1", "name": "member"}}}
	not revoke.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "role": {"domain_id": "foo", "name": "member"}}}
	not revoke.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": "foo", "name": "admin"}}}
	not revoke.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": null, "name": "service"}}}
}
