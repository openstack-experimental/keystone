package test_token_restriction_create

import data.identity.token.token_restriction.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": ["admin"]}}
	create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"restriction": {"domain_id": "domain"}}}
	create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain", "user_id": "uid"}, "target": {"restriction": {"domain_id": "domain", "user_id": "uid"}}}
	create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain", "user_id": "uid"}, "target": {"restriction": {"domain_id": "domain", "user_id": "uid2"}}}
	create.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain", "user_id": "uid"}, "target": {"restriction": {"domain_id": "domain", "user_id": "uid"}}}
}

test_forbidden if {
	not create.allow with input as {"credentials": {"roles": []}}
	not create.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"restriction": {"domain_id": "other_domain"}}}
	not create.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"restriction": {"domain_id": "other_domain"}}}
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"restriction": {"domain_id": "other_domain"}}}
	not create.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain", "user_id": "uid1"}, "target": {"restriction": {"domain_id": "domain", "user_id": "uid2"}}}
}
