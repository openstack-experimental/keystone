# METADATA
# title: Show service grant
# description: Policy for reading one service grant (ADR 0036 §4.2)
package identity.service_grant.show

import data.identity.service_grant as sg

# The `input.existing.service_grant` is the stored grant, or `{"id": ...}`
# only when it does not exist (the handler answers 404 after an allow).
# The `input.target` is null.
#
# Also invoked by `identity/service_grant/list` for every listed grant.
default allow := false

allow if {
	sg.may_manage(input.existing.service_grant)
}
