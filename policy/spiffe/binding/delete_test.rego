package test_spiffe_binding_delete

import data.identity.spiffe.binding.delete

test_allowed if {
	# Admin role can delete bindings.
	delete.allow with input as {"credentials": {"roles": ["admin"]}}

	# Admin (is_admin flag) can delete bindings.
	delete.allow with input as {"credentials": {"roles": [], "is_admin": true}}

	# System user (system == "all") with member role can delete bindings.
	delete.allow with input as {"credentials": {"roles": ["member"], "system": "all"}}

	# Owner with manager role can delete bindings.
	delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "existing": {"binding": {"domain_id": "domain"}}}

	# Admin can delete bindings for any domain.
	delete.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"binding": {"domain_id": null}}}
}

test_forbidden if {
	# No roles - forbidden.
	not delete.allow with input as {"credentials": {"roles": []}}

	# Reader role is not sufficient.
	not delete.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "existing": {"binding": {"domain_id": "domain"}}}

	# Manager role in a different domain - forbidden.
	not delete.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "existing": {"binding": {"domain_id": "other_domain"}}}

	# Member role in a different domain - forbidden.
	not delete.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "existing": {"binding": {"domain_id": "other_domain"}}}

	# No roles and no domain scope - forbidden.
	not delete.allow with input as {"credentials": {"roles": []}, "existing": {"binding": {"domain_id": "domain"}}}
}
