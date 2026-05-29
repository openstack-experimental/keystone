package test_token_restriction_list

import data.identity.token.token_restriction.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"roles": ["manager"]}}
	list.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"restriction": {"domain_id": "domain"}}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"restriction": {"domain_id": "other_domain"}}}
	not list.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"restriction": {"domain_id": "other_domain"}}}
}
