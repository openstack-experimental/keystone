package test_create

import data.identity.federation.mapping.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": ["admin"]}}
	create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"mapping": {"domain_id": "domain"}}}
	create.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"mapping": {"domain_id": null}}}
}

test_forbidden if {
	not create.allow with input as {"credentials": {"roles": []}}
	not create.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"mapping": {"domain_id": "domain"}}}
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"mapping": {"domain_id": "other_domain"}}}
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"mapping": {"domain_id": null}}}
}
