package test_project_group_role_grant

import data.identity.project.group.role.grant

test_allowed if {
	grant.allow with input as {"credentials": {"roles": ["admin"]}}
	grant.allow with input as {"credentials": {"roles": [], "is_admin": true}}
	grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": null, "name": "member"}}}
	grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": "foo", "name": "member"}}}
	grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": null, "name": "reader"}}}
	grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": null, "name": "manager"}}}
}

test_forbidden if {
	not grant.allow with input as {"credentials": {"roles": []}}
	not grant.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}}
	not grant.allow with input as {"credentials": {"roles": ["member"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": "foo", "name": "member"}}}
	not grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo1"}, "group": {"domain_id": "foo"}, "role": {"domain_id": "foo", "name": "member"}}}
	not grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}, "group": {"domain_id": "foo1"}, "role": {"domain_id": "foo", "name": "member"}}}
	not grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": "foo1", "name": "member"}}}
	not grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}, "role": {"domain_id": "foo", "name": "member"}}}
	not grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": "foo", "name": "admin"}}}
	not grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}, "group": {"domain_id": "foo"}, "role": {"domain_id": null, "name": "service"}}}
}
