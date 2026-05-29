package test_mapping_delete

import data.identity.federation.mapping.delete

test_allowed if {
	delete.allow with input as {"credentials": {"roles": ["admin"]}}
	delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"mapping": {"domain_id": "domain"}}}
	delete.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"mapping": {"domain_id": null}}}
}

test_forbidden if {
	not delete.allow with input as {"credentials": {"roles": []}}
	not delete.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"mapping": {"domain_id": "domain"}}}
	not delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"mapping": {"domain_id": "other_domain"}}}
	not delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"mapping": {"domain_id": null}}}
}
