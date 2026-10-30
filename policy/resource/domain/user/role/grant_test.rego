package test_domain_user_role_grant

import data.identity.domain.user.role.grant

test_allowed if {
	grant.allow with input as {"credentials": {"roles": ["admin"]}}
	grant.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "user": {"domain_id": "foo"}, "role": {"domain_id": null, "name": "member"}}}
	grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "user": {"domain_id": "foo"}, "role": {"domain_id": "foo", "name": "member"}}}
	grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "user": {"domain_id": "foo"}, "role": {"domain_id": null, "name": "reader"}}}
	grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "user": {"domain_id": "foo"}, "role": {"domain_id": null, "name": "manager"}}}
}

test_forbidden if {
	not grant.allow with input as {"credentials": {"roles": []}}
	not grant.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	not grant.allow with input as {"credentials": {"roles": ["member"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "user": {"domain_id": "foo"}, "role": {"domain_id": "foo", "name": "member"}}}
	not grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo1"}, "user": {"domain_id": "foo"}, "role": {"domain_id": "foo", "name": "member"}}}
	not grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "user": {"domain_id": "foo1"}, "role": {"domain_id": "foo", "name": "member"}}}
	not grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "user": {"domain_id": "foo"}, "role": {"domain_id": "foo1", "name": "member"}}}
	not grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "role": {"domain_id": "foo", "name": "member"}}}
	not grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "user": {"domain_id": "foo"}, "role": {"domain_id": "foo", "name": "admin"}}}
	not grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"domain": {"id": "foo"}, "user": {"domain_id": "foo"}, "role": {"domain_id": null, "name": "service"}}}
}
