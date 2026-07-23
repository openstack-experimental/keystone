package test_trust_create

import data.identity.trust.create

test_allowed if {
	create.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "target": {"trust": {"trustor_user_id": "u1"}}}

	# No role requirement: matches python keystone's identity:create_trust,
	# which only checks trustor identity. Whether the trustor actually
	# holds the delegated roles is checked provider-side.
	create.allow with input as {"credentials": {"roles": [], "user_id": "u1"}, "target": {"trust": {"trustor_user_id": "u1"}}}
}

test_forbidden if {
	# Not the trustor.
	not create.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "target": {"trust": {"trustor_user_id": "other"}}}

	not create.allow with input as {"credentials": {"roles": []}, "target": {"trust": {"trustor_user_id": "u1"}}}

	# No admin bypass: matches python keystone's identity:create_trust,
	# which has no admin_required clause.
	not create.allow with input as {"credentials": {"roles": ["admin"], "user_id": "u2"}, "target": {"trust": {"trustor_user_id": "other"}}}

	not create.allow with input as {"credentials": {"roles": ["admin"], "is_admin": true, "user_id": "u2"}, "target": {"trust": {"trustor_user_id": "other"}}}
}

# OSSA-2026-015: a delegated (trust/app-cred) caller creating a *new* trust
# must only bind it to its own delegation project.
test_delegated_allowed if {
	create.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p1", "delegated_project_id": "p1"}, "target": {"trust": {"trustor_user_id": "u1", "project_id": "p1"}}}
}

test_delegated_forbidden if {
	# Different project than the delegation is bound to.
	not create.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p2", "delegated_project_id": "p2"}, "target": {"trust": {"trustor_user_id": "u1", "project_id": "p1"}}}

	# Unscoped trust is out-of-scope for any delegated caller.
	not create.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p1", "delegated_project_id": "p1"}, "target": {"trust": {"trustor_user_id": "u1"}}}

	# Scope-drift tripwire: token scope diverges from the delegation's own project.
	not create.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p2", "delegated_project_id": "p1"}, "target": {"trust": {"trustor_user_id": "u1", "project_id": "p1"}}}
}
