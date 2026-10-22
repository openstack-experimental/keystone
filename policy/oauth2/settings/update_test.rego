package test_oauth2_settings_update

import data.identity.oauth2.settings.update

settings(domain_id, current, new, global) := {
	"target": {"oauth2_settings": {"dpop": new, "global_dpop": global}},
	"existing": {"oauth2_settings": {"domain_id": domain_id, "dpop": current}},
}

manager(domain_id) := {"roles": ["manager"], "domain_id": domain_id}

test_admin_allowed if {
	update.allow with input as object.union({"credentials": {"roles": ["admin"]}}, settings("foo", "required", "disabled", "optional"))
	update.allow with input as object.union({"credentials": {"roles": [], "is_admin": true}}, settings("foo", "required", "disabled", "disabled"))
}

test_manager_raise_allowed if {
	update.allow with input as object.union({"credentials": manager("foo")}, settings("foo", "disabled", "optional", "disabled"))
	update.allow with input as object.union({"credentials": manager("foo")}, settings("foo", "optional", "required", "optional"))
	update.allow with input as object.union({"credentials": manager("foo")}, settings("foo", "disabled", "required", "required"))
}

test_manager_unchanged_allowed if {
	update.allow with input as object.union({"credentials": manager("foo")}, settings("foo", "optional", "optional", "optional"))
	# A no-op below the global floor changes nothing.
	update.allow with input as object.union({"credentials": manager("foo")}, settings("foo", "disabled", "disabled", "required"))
}

test_manager_lowering_denied if {
	not update.allow with input as object.union({"credentials": manager("foo")}, settings("foo", "required", "optional", "disabled"))
	not update.allow with input as object.union({"credentials": manager("foo")}, settings("foo", "optional", "disabled", "disabled"))
}

test_manager_below_global_denied if {
	not update.allow with input as object.union({"credentials": manager("foo")}, settings("foo", "disabled", "optional", "required"))
}

test_manager_other_domain_denied if {
	not update.allow with input as object.union({"credentials": manager("foo")}, settings("bar", "disabled", "required", "disabled"))
}

test_no_manager_role_denied if {
	not update.allow with input as object.union({"credentials": {"roles": ["reader"], "domain_id": "foo"}}, settings("foo", "disabled", "required", "disabled"))
	not update.allow with input as object.union({"credentials": {"roles": []}}, settings("foo", "disabled", "required", "disabled"))
}

test_violations if {
	update.violation[{"field": "dpop", "msg": "lowering the DPoP mode of a domain requires `admin` role."}] with input as object.union({"credentials": manager("foo")}, settings("foo", "required", "optional", "disabled"))
	update.violation[{"field": "dpop", "msg": "setting the DPoP mode of a domain below the global mode requires `admin` role."}] with input as object.union({"credentials": manager("foo")}, settings("foo", "disabled", "optional", "required"))
}
