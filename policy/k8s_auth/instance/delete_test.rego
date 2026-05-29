package test_k8s_auth_instance_delete

import data.identity.k8s_auth.instance.delete

test_allowed if {
	delete.allow with input as {"credentials": {"roles": ["admin"]}}
	delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"instance": {"domain_id": "domain"}}}
	delete.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"instance": {"domain_id": null}}}
}

test_forbidden if {
	not delete.allow with input as {"credentials": {"roles": []}}
	not delete.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"instance": {"domain_id": "domain"}}}
	not delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"instance": {"domain_id": "other_domain"}}}
	not delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"instance": {"domain_id": null}}}
}
