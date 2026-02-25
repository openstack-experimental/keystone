package test_k8s_auth_role_delete

import data.identity.k8s_auth.role.delete

test_allowed if {
	delete.allow with input as {"credentials": {"roles": ["admin"]}}
	delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
	delete.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"domain_id": null}}
}

test_forbidden if {
	not delete.allow with input as {"credentials": {"roles": []}}
	not delete.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
	not delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
	not delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": null}}
}
