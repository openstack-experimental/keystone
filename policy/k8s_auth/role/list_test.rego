package test_k8s_auth_role_list

import data.identity.k8s_auth.role.list

test_allowed if {
	list.allow with input as {"credentials": {"roles": ["admin"]}}
	list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "domain"}}
	list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": null}}
}

test_forbidden if {
	not list.allow with input as {"credentials": {"roles": []}}
	not list.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
	not list.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"domain_id": "other_domain"}}
}
