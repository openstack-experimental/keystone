package test_role_show

import data.identity.role.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}}
	show.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain_a"}, "target": {"role": {"domain_id": "domain_a"}}}
}

test_forbidden if {
	not show.allow with input as {"credentials": {"roles": []}}
	not show.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"role": {"domain_id": "other_domain"}}}
	not show.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"role": {"domain_id": "other_domain"}}}
}
