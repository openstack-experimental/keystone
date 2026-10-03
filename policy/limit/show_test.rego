package test_limit_show

import data.identity.limit.show

project_limit := {"limit": {"id": "l1", "project_id": "p1", "domain_id": null, "project_domain_id": "d1"}}

domain_limit := {"limit": {"id": "l2", "project_id": null, "domain_id": "d1", "project_domain_id": null}}

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}, "existing": project_limit}
	show.allow with input as {"credentials": {"is_admin": true}, "existing": project_limit}
	show.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}, "existing": project_limit}
	show.allow with input as {"credentials": {"roles": ["member"], "project_id": "p1", "is_delegated": false}, "existing": project_limit}
	show.allow with input as {"credentials": {"roles": ["member"], "domain_id": "d1"}, "existing": project_limit}
	show.allow with input as {"credentials": {"roles": ["member"], "domain_id": "d1"}, "existing": domain_limit}
}

test_forbidden if {
	not show.allow with input as {"credentials": {"roles": []}, "existing": project_limit}
	not show.allow with input as {"credentials": {"roles": ["reader"]}, "existing": project_limit}
	not show.allow with input as {"credentials": {"roles": ["reader"], "system": "domain"}, "existing": project_limit}

	# other project
	not show.allow with input as {"credentials": {"roles": ["member"], "project_id": "p2"}, "existing": project_limit}

	# project scope does not see the domain limit
	not show.allow with input as {"credentials": {"roles": ["member"], "project_id": "p1"}, "existing": domain_limit}

	# other domain
	not show.allow with input as {"credentials": {"roles": ["member"], "domain_id": "d2"}, "existing": project_limit}
	not show.allow with input as {"credentials": {"roles": ["member"], "domain_id": "d2"}, "existing": domain_limit}
}

# A delegated caller (trust/app-cred) is bound to the delegation project.
test_delegated_allowed if {
	show.allow with input as {"credentials": {"roles": ["member"], "project_id": "p1", "is_delegated": true, "delegated_project_id": "p1"}, "existing": project_limit}
}

test_delegated_forbidden if {
	# The delegation is bound to another project than the limit.
	not show.allow with input as {"credentials": {"roles": ["member"], "project_id": "p2", "is_delegated": true, "delegated_project_id": "p2"}, "existing": project_limit}

	# Scope-drift tripwire: the token scope matches the limit while the
	# delegation's own immutable project does not.
	not show.allow with input as {"credentials": {"roles": ["member"], "project_id": "p1", "is_delegated": true, "delegated_project_id": "p3"}, "existing": project_limit}

	# Scope-drift tripwire: the token scope diverges from the delegation's
	# project, which is the limit's project.
	not show.allow with input as {"credentials": {"roles": ["member"], "project_id": "p2", "is_delegated": true, "delegated_project_id": "p1"}, "existing": project_limit}

	# Delegation without a project binding.
	not show.allow with input as {"credentials": {"roles": ["member"], "project_id": "p1", "is_delegated": true, "delegated_project_id": null}, "existing": project_limit}
}
