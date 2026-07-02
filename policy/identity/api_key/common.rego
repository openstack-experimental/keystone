# METADATA
# description: Shared predicates for API Key (SCIM ingress) policies (ADR 0021)
package identity.api_key

import data.identity

# Resolve domain_id from target or existing depending on operation.
# Create/List: domain_id is in input.target.api_key.
# Update/Revoke/SimulateAccess: domain_id is in input.existing.api_key.
# Unlike mapping rulesets, an API Key's domain_id is always mandatory (ADR
# 0021 §2: "Domain-Owned Machine Identities") -- there is no global/orphaned
# case to account for.
key_domain_id := input.target.api_key.domain_id if {
	input.target.api_key.domain_id
}

key_domain_id := input.existing.api_key.domain_id if {
	input.existing.api_key.domain_id
}

own_key if {
	key_domain_id != null
	key_domain_id == input.credentials.domain_id
}

foreign_key if {
	key_domain_id != null
	key_domain_id != input.credentials.domain_id
}
