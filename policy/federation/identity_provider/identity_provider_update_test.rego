package test_identity_provider_update

import data.identity.federation.identity_provider.update

test_allowed if {
	update.allow with input as {"credentials": {"roles": ["admin"]}}
	update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"identity_provider": {"domain_id": "domain"}}}
	update.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"identity_provider": {"domain_id": null}}}
}

test_forbidden if {
	not update.allow with input as {"credentials": {"roles": []}}
	not update.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"identity_provider": {"domain_id": "domain"}}}
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"identity_provider": {"domain_id": "other_domain"}}}
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"identity_provider": {"domain_id": null}}}
}
