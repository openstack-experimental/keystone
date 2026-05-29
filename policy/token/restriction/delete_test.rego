package test_token_restriction_delete

import data.identity.token.token_restriction.delete

test_allowed if {
	delete.allow with input as {"credentials": {"roles": ["admin"]}}
	delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"restriction": {"domain_id": "domain"}}}
	delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain", "user_id": "uid"}, "target": {"restriction": {"domain_id": "domain", "user_id": "uid"}}}
	delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain", "user_id": "uid"}, "target": {"restriction": {"domain_id": "domain", "user_id": "uid2"}}}
	delete.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain", "user_id": "uid"}, "target": {"restriction": {"domain_id": "domain", "user_id": "uid"}}}
}

test_forbidden if {
	not delete.allow with input as {"credentials": {"roles": []}}
	not delete.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"restriction": {"domain_id": "other_domain"}}}
	not delete.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"restriction": {"domain_id": "other_domain"}}}
	not delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"restriction": {"domain_id": "other_domain"}}}
	not delete.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain", "user_id": "uid1"}, "target": {"restriction": {"domain_id": "domain", "user_id": "uid2"}}}
}
