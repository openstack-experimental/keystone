package test_token_restriction_show

import data.identity.token.token_restriction.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}}
	#token_restriction_show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"restriction": {"domain_id": "domain"}}}
	#token_restriction_show.allow with input as {"credentials": {"roles": ["reader"]}, "target": {"domain_id": null}}
}

test_forbidden if {
	not show.allow with input as {"credentials": {"roles": []}}
	not show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"restriction": {"domain_id": "other_domain"}}}
	not show.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"restriction": {"domain_id": "other_domain"}}}
}
