package test_role_update

import data.identity.role.update

test_allowed if {
	update.allow with input as {"credentials": {"roles": ["admin"]}}
	update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain_a"}, "existing": {"role": {"domain_id": "domain_a"}}}
}

test_forbidden if {
	not update.allow with input as {"credentials": {"roles": []}}
	not update.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "existing": {"role": {"domain_id": "other_domain"}}}
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "existing": {"role": {"domain_id": "other_domain"}}}
}
