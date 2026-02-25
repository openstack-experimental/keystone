package test_k8s_auth_role_create

import data.identity.k8s_auth.role.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": ["admin"]}}
	create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"instance": {"domain_id": "domain"}, "role": {}}}
	create.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"instance": {"domain_id": "other_domain"}}}
}

test_forbidden if {
	not create.allow with input as {"credentials": {"roles": []}}
	not create.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"instance": {"domain_id": "domain"}, "role": {}}}
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"instance": {"domain_id": "other_domain"}, "role": {}}}
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"instance": {"domain_id": null}, "role": {}}}
}
