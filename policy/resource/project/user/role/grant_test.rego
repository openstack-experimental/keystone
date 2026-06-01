package test_project_user_role_grant

import data.identity.project.user.role.grant

test_allowed if {
	grant.allow with input as {"credentials": {"roles": ["admin"]}}
	grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo"}, "project": {"domain_id": "foo"}, "role": {"domain_id": null}}}
	grant.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo"}, "project": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
}

test_forbidden if {
	not grant.allow with input as {"credentials": {"roles": []}}
	not grant.allow with input as {"credentials": {"roles": ["reader"], "system": "foo"}}
	not grant.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo1"}, "project": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
	not grant.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo1"}, "project": {"domain_id": "foo1"}, "role": {"domain_id": "foo1"}}}
	not grant.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo"}, "project": {"domain_id": "foo1"}, "role": {"domain_id": "foo1"}}}
	not grant.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo1"}, "project": {"domain_id": "foo1"}, "role": {"domain_id": "foo1"}}}
	not grant.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
	not grant.allow with input as {"credentials": {"roles": ["member"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}, "role": {"domain_id": "foo"}, "user": {"domain_id": "foo"}}}
}
