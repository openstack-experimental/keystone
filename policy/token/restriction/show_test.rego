package test_token_restriction_show

import data.identity.token.token_restriction.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}}
	show.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "existing": {"restriction": {"domain_id": "domain"}}}
}

test_forbidden if {
	not show.allow with input as {"credentials": {"roles": []}}
	not show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "existing": {"restriction": {"domain_id": "domain"}}}
	not show.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "existing": {"restriction": {"domain_id": "other_domain"}}}
	not show.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "existing": {"restriction": {"domain_id": "other_domain"}}}
}
