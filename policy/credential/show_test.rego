package test_credential_show

import data.identity.credential.show

test_allowed if {
	show.allow with input as {"credentials": {"roles": ["admin"]}, "existing": {"credential": {"user_id": "other"}}}
	show.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "existing": {"credential": {"user_id": "u1"}}}
	show.allow with input as {"credentials": {"roles": ["reader"], "system": "all"}, "existing": {"credential": {"user_id": "other"}}}
}

test_forbidden if {
	not show.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1"}, "existing": {"credential": {"user_id": "other"}}}
	not show.allow with input as {"credentials": {"roles": []}, "existing": {"credential": {"user_id": "u1"}}}
}

# OSSA-2026-015: a delegated (trust/app-cred) caller must only reach
# credentials bound to its own delegation project; unscoped credentials
# (e.g. TOTP/MFA) must be unreachable via delegation entirely.
test_delegated_allowed if {
	show.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p1", "delegated_project_id": "p1"}, "existing": {"credential": {"user_id": "u1", "project_id": "p1"}}}
}

test_delegated_forbidden if {
	# Same user, but delegation is bound to a different project.
	not show.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p2", "delegated_project_id": "p2"}, "existing": {"credential": {"user_id": "u1", "project_id": "p1"}}}

	# Unscoped credential (e.g. TOTP) is out-of-scope for any delegated caller.
	not show.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p1", "delegated_project_id": "p1"}, "existing": {"credential": {"user_id": "u1", "project_id": null}}}

	# Scope-drift tripwire: the token scope (project_id) diverges from the
	# delegation's own immutable project. Even though the credential matches
	# the delegation project, the mismatch must fail closed.
	not show.allow with input as {"credentials": {"roles": ["member"], "user_id": "u1", "is_delegated": true, "project_id": "p2", "delegated_project_id": "p1"}, "existing": {"credential": {"user_id": "u1", "project_id": "p1"}}}
}
