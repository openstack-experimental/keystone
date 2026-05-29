package test_passkey_register_finish

import data.identity.user.passkey.register.finish

test_allowed if {
	finish.allow with input as {"credentials": {"roles": ["admin"]}}
	finish.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"user": {"domain_id": "domain"}}}
	finish.allow with input as {"credentials": {"user_id": "foo"}, "target": {"id": "foo"}}
}

test_forbidden if {
	not finish.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"user": {"domain_id": "domain"}}}
	not finish.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"user": {"domain_id": "other_domain"}}}
	not finish.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"user": {"domain_id": null}}}
	not finish.allow with input as {"credentials": {"user_id": "foo"}, "target": {"id": "bar"}}
}
