package test_mapping_update

import data.identity.federation.mapping.update

test_allowed if {
	update.allow with input as {"credentials": {"roles": ["admin"]}}
	update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"mapping": {"domain_id": "domain"}}}
	update.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"mapping": {"domain_id": null}}}
}

test_forbidden if {
	not update.allow with input as {"credentials": {"roles": []}}
	not update.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"mapping": {"domain_id": "domain"}}}
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"mapping": {"domain_id": "other_domain"}}}
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"mapping": {"domain_id": null}}}
}
