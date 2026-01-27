package test_project_user_role_revoke

import data.identity.project.user.role.revoke

test_allowed if {
	revoke.allow with input as {"credentials": {"roles": ["admin"]}}
	revoke.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo"}, "project": {"domain_id": "foo"}, "role": {"domain_id": null}}}
	revoke.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo"}, "project": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
}

test_forbidden if {
	not revoke.allow with input as {"credentials": {"roles": []}}
	not revoke.allow with input as {"credentials": {"roles": ["reader"], "system": "foo"}}
	not revoke.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo1"}, "project": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
	not revoke.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo1"}, "project": {"domain_id": "foo1"}, "role": {"domain_id": "foo1"}}}
	not revoke.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo"}, "project": {"domain_id": "foo1"}, "role": {"domain_id": "foo1"}}}
	not revoke.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"user": {"domain_id": "foo1"}, "project": {"domain_id": "foo1"}, "role": {"domain_id": "foo1"}}}
	not revoke.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}, "role": {"domain_id": "foo"}}}
	not revoke.allow with input as {"credentials": {"roles": ["member"], "domain_id": "foo"}, "target": {"project": {"domain_id": "foo"}, "role": {"domain_id": "foo"}, "user": {"domain_id": "foo"}}}
}
