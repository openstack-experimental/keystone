package test_passkey_register_start

import data.identity.user.passkey.register.start

test_allowed if {
	start.allow with input as {"credentials": {"roles": ["admin"]}}
	start.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"user": {"domain_id": "domain"}}}
	start.allow with input as {"credentials": {"user_id": "foo"}, "target": {"id": "foo"}}
}

test_forbidden if {
	not start.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"user": {"domain_id": "domain"}}}
	not start.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"user": {"domain_id": "other_domain"}}}
	not start.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"user": {"domain_id": null}}}
	not start.allow with input as {"credentials": {"user_id": "foo"}, "target": {"id": "bar"}}
}
