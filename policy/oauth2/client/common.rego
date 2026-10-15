# METADATA
# description: Shared predicates for OAuth2 client (relying party) policies (ADR 0026 §5)
package identity.oauth2.client

import data.identity

# Resolve domain_id from target or existing depending on operation.
# Create/List: domain_id is a top-level input.target field (from the URL
# path, ADR 0026 §5), not nested under input.target.oauth2_client.
# Show/Update/RotateSecret/Delete: domain_id is in
# input.existing.oauth2_client.
client_domain_id := input.target.domain_id if {
	input.target.domain_id
}

client_domain_id := input.existing.oauth2_client.domain_id if {
	input.existing.oauth2_client.domain_id
}

own_client if {
	client_domain_id != null
	client_domain_id == input.credentials.domain_id
}

foreign_client if {
	client_domain_id != null
	client_domain_id != input.credentials.domain_id
}

# The object (a create payload, an update patch or a stored client) touches
# the delegatable service registration (ADR 0036 §3): SPIFFE ID patterns or
# a delegation policy. Registering a delegatable service is admin-only.
delegation_fields(obj) if {
	obj.delegation != null
}

delegation_fields(obj) if {
	count(obj.spiffe_ids) > 0
}

delegation_fields(obj) if {
	obj.remove_delegation == true
}
