package test_spiffe_binding_update

import data.identity.spiffe.binding.update

test_allowed if {
	# Admin role can update bindings.
	update.allow with input as {"credentials": {"roles": ["admin"]}}

	# Admin (is_admin flag) can update bindings.
	update.allow with input as {"credentials": {"roles": [], "is_admin": true}}

	# System user (system == "all") with member role can update bindings.
	update.allow with input as {"credentials": {"roles": ["member"], "system": "all"}}

	# Owner with manager role can update bindings.
	update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "existing": {"binding": {"domain_id": "domain"}}}

	# Admin can update bindings for any domain.
	update.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"binding": {"domain_id": null}}}

	# Admin with resolved auths can update bindings.
	update.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"binding": {"domain_id": "domain"}}, "target": {"binding": {"authorizations": [{"domain": {"domain_id": "did", "domain": {"id": "did", "name": "default", "enabled": true}}}]}}}

	# Owner with resolved auths can update bindings.
	update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "existing": {"binding": {"domain_id": "domain"}}, "target": {"binding": {"authorizations": [{"project": {"project_id": "pid", "project": {"id": "pid", "name": "proj", "domain_id": "domain", "enabled": true}}}]}}}
}

test_forbidden if {
	# No roles - forbidden.
	not update.allow with input as {"credentials": {"roles": []}}

	# Reader role is not sufficient.
	not update.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "existing": {"binding": {"domain_id": "domain"}}}

	# Manager role in a different domain - forbidden.
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "existing": {"binding": {"domain_id": "other_domain"}}}

	# Member role in a different domain - forbidden.
	not update.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "existing": {"binding": {"domain_id": "other_domain"}}}

	# No roles and no domain scope - forbidden.
	not update.allow with input as {"credentials": {"roles": []}, "existing": {"binding": {"domain_id": "domain"}}}

	# Admin denied when auth domain is not found.
	not update.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"binding": {"domain_id": "domain"}}, "target": {"binding": {"authorizations": [{"domain": {"domain_id": "did", "domain": null}}]}}}

	# Admin denied when auth project is not found.
	not update.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"binding": {"domain_id": "domain"}}, "target": {"binding": {"authorizations": [{"project": {"project_id": "pid", "project": null}}]}}}

	# Admin denied when role IDs provided but not all resolved.
	not update.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"binding": {"domain_id": "domain"}}, "target": {"binding": {"authorizations": [{"domain": {"domain_id": "did", "domain": {"id": "did", "name": "default", "enabled": true}, "role_ids": ["r1", "r2"], "roles": [{"id": "r1"}]}}]}}}

	# Owner denied when auth domain is not found.
	not update.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "existing": {"binding": {"domain_id": "domain"}}, "target": {"binding": {"authorizations": [{"domain": {"domain_id": "did", "domain": null}}]}}}

	# Auth validation violations: domain missing produces violation.
	count(update.violation) > 0 with input as {"credentials": {"roles": ["admin"]}, "existing": {"binding": {"domain_id": "domain"}}, "target": {"binding": {"authorizations": [{"domain": {"domain_id": "did", "domain": null}}]}}}

	# Auth validation violations: project missing produces violation.
	count(update.violation) > 0 with input as {"credentials": {"roles": ["admin"]}, "existing": {"binding": {"domain_id": "domain"}}, "target": {"binding": {"authorizations": [{"project": {"project_id": "pid", "project": null}}]}}}

	# Auth validation violations: roles partially resolved produces violation.
	count(update.violation) > 0 with input as {"credentials": {"roles": ["admin"]}, "existing": {"binding": {"domain_id": "domain"}}, "target": {"binding": {"authorizations": [{"domain": {"domain_id": "did", "domain": {"id": "did", "name": "default", "enabled": true}, "role_ids": ["r1", "r2"], "roles": [{"id": "r1"}]}}]}}}
}
