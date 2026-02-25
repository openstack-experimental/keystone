package test_k8s_auth_instance_create

import data.identity.k8s_auth.instance.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": ["admin"]}}
	create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
	create.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"domain_id": null}}
}

test_forbidden if {
	not create.allow with input as {"credentials": {"roles": []}}
	not create.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"domain_id": null}}
}
