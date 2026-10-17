# METADATA
# title: Delete service grant
# description: Policy for revoking one service grant (ADR 0036 §4.2)
package identity.service_grant.delete

import data.identity.service_grant as sg

# The `input.existing.service_grant` is the stored grant, or `{"id": ...}`
# only when it does not exist. The `input.target` is null.
#
# The grantee service may delete its own grants (e.g. Heat at stack
# delete); it may not list them.
default allow := false

allow if {
	sg.may_manage(input.existing.service_grant)
}
