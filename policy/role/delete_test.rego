package test_role_delete

import data.identity.role.delete

test_allowed if {
	delete.allow with input as {"credentials": {"roles": ["admin"]}}
	delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain_a"}, "target": {"role": {"domain_id": "domain_a"}}}
}

test_forbidden if {
	not delete.allow with input as {"credentials": {"roles": []}}
	not delete.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"role": {"domain_id": "other_domain"}}}
	not delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"role": {"domain_id": "other_domain"}}}
}
