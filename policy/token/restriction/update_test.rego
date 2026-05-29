package test_token_restriction_update

import data.identity.token.token_restriction.update

test_allowed if {
	update.allow with input as {"credentials": {"roles": ["admin"]}}
	update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "existing": {"restriction": {"domain_id": "domain"}}}
	update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain", "user_id": "uid"}, "existing": {"restriction": {"domain_id": "domain", "user_id": "uid"}}}
	update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain", "user_id": "uid"}, "existing": {"restriction": {"domain_id": "domain", "user_id": "uid2"}}}
	update.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain", "user_id": "uid"}, "existing": {"restriction": {"domain_id": "domain", "user_id": "uid"}}}
}

test_forbidden if {
	not update.allow with input as {"credentials": {"roles": []}}
	not update.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "existing": {"restriction": {"domain_id": "other_domain"}}}
	not update.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "existing": {"restriction": {"domain_id": "other_domain"}}}
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "existing": {"restriction": {"domain_id": "other_domain"}}}
	not update.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain", "user_id": "uid1"}, "existing": {"restriction": {"domain_id": "domain", "user_id": "uid2"}}}
}
