package test_spiffe_binding_create

import data.identity.spiffe.binding.create

test_allowed if {
	# Admin role can create bindings.
	create.allow with input as {"credentials": {"roles": ["admin"]}}

	# Admin (is_admin flag) can create bindings.
	create.allow with input as {"credentials": {"roles": [], "is_admin": true}}

	# System user (system == "all") with member role can create bindings.
	create.allow with input as {"credentials": {"roles": ["member"], "system": "all"}}

	# Owner with manager role can create bindings.
	create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"binding": {"domain_id": "domain"}}}

	# Admin can create bindings for any domain.
	create.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"binding": {"domain_id": null}}}

	# Admin can create system-wide binding (is_system = true).
	create.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"binding": {"is_system": true}}}

	# Admin (is_admin flag) can create system-wide binding.
	create.allow with input as {"credentials": {"roles": [], "is_admin": true}, "target": {"binding": {"is_system": true}}}

	# Admin can create binding with resolved domain auths.
	create.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"binding": {"is_system": false, "authorizations": [{"domain": {"domain_id": "did", "domain": {"id": "did", "name": "default", "enabled": true}, "role_ids": ["admin"], "roles": [{"id": "admin"}]}}]}}}

	# Admin can create binding with resolved project auths.
	create.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"binding": {"is_system": false, "authorizations": [{"project": {"project_id": "pid", "project": {"id": "pid", "name": "proj", "domain_id": "did", "enabled": true}, "role_ids": ["admin"], "roles": [{"id": "admin"}]}}]}}}

	# Owner with resolved auths (no missing domains).
	create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"binding": {"domain_id": "domain", "is_system": false, "authorizations": [{"domain": {"domain_id": "did", "domain": {"id": "did", "name": "default", "enabled": true}}}]}}}
}

test_forbidden if {
	# No roles - forbidden.
	not create.allow with input as {"credentials": {"roles": []}}

	# Reader role alone is not sufficient.
	not create.allow with input as {"credentials": {"roles": ["reader"], "domain_id": "domain"}, "target": {"binding": {"domain_id": "domain"}}}

	# Manager role in a different domain - forbidden.
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"binding": {"domain_id": "other_domain"}}}

	# Member role in a different domain - forbidden.
	not create.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"binding": {"domain_id": "other_domain"}}}

	# No roles and no domain scope - forbidden.
	not create.allow with input as {"credentials": {"roles": []}, "target": {"binding": {"domain_id": "domain"}}}

	# Manager role cannot create system-wide binding.
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"binding": {"domain_id": "domain", "is_system": true}}}

	# Member role cannot create system-wide binding.
	not create.allow with input as {"credentials": {"roles": ["member"], "domain_id": "domain"}, "target": {"binding": {"domain_id": "domain", "is_system": true}}}

	# System user (system == "all") with member cannot create system-wide binding.
	not create.allow with input as {"credentials": {"roles": ["member"], "system": "all"}, "target": {"binding": {"is_system": true}}}

	# Admin denied when auth domain is not found (domain = null).
	not create.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"binding": {"is_system": false, "authorizations": [{"domain": {"domain_id": "did", "domain": null}}]}}}

	# Admin denied when auth project is not found (project = null).
	not create.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"binding": {"is_system": false, "authorizations": [{"project": {"project_id": "pid", "project": null}}]}}}

	# Admin denied when role IDs provided but not all resolved.
	not create.allow with input as {"credentials": {"roles": ["admin"]}, "target": {"binding": {"is_system": false, "authorizations": [{"domain": {"domain_id": "did", "domain": {"id": "did", "name": "default", "enabled": true}, "role_ids": ["r1", "r2"], "roles": [{"id": "r1"}]}}]}}}

	# Owner denied when auth domain is not found.
	not create.allow with input as {"credentials": {"roles": ["manager"], "domain_id": "domain"}, "target": {"binding": {"domain_id": "domain", "is_system": false, "authorizations": [{"domain": {"domain_id": "did", "domain": null}}]}}}

	# System user denied when auth project is not found.
	not create.allow with input as {"credentials": {"roles": ["member"], "system": "all"}, "target": {"binding": {"is_system": false, "authorizations": [{"project": {"project_id": "pid", "project": null}}]}}}

	# Auth validation violations: domain/project missing produces violation.
	count(create.violation) > 0 with input as {"credentials": {"roles": ["admin"]}, "target": {"binding": {"is_system": false, "authorizations": [{"domain": {"domain_id": "did", "domain": null}}]}}}

	# Auth validation violations: project missing produces violation.
	count(create.violation) > 0 with input as {"credentials": {"roles": ["admin"]}, "target": {"binding": {"is_system": false, "authorizations": [{"project": {"project_id": "pid", "project": null}}]}}}

	# Auth validation violations: roles partially resolved produces violation.
	count(create.violation) > 0 with input as {"credentials": {"roles": ["admin"]}, "target": {"binding": {"is_system": false, "authorizations": [{"domain": {"domain_id": "did", "domain": {"id": "did", "name": "default", "enabled": true}, "role_ids": ["r1", "r2"], "roles": [{"id": "r1"}]}}]}}}
}
